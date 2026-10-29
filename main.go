// Command sendscore-app runs the SendScore web app and its SMTP receiver in
// one process, sharing one SQLite database.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore-app/internal/mail"
	"github.com/sendscore/sendscore-app/internal/receiver"
	"github.com/sendscore/sendscore-app/internal/web"
	"github.com/sendscore/sendscore/engine"
)

func main() {
	loadDotEnv(".env.local")
	loadDotEnv(".env")
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	dbPath := getenv("SENDSCORE_DB", "sendscore.db")
	store, err := db.Open(dbPath)
	if err != nil {
		log.Error("database init failed", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	httpAddr := getenv("SENDSCORE_ADDR", "127.0.0.1:3014")
	smtpAddr := getenv("SENDSCORE_SMTP_ADDR", "127.0.0.1:2525")
	mailDomain := getenv("SENDSCORE_MAIL_DOMAIN", "localhost")
	baseURL := strings.TrimRight(getenv("SENDSCORE_BASE_URL", "http://"+httpAddr), "/")
	// Secure cookies are the production switch. Sign-in links are built
	// from SENDSCORE_BASE_URL, never the Host header, so production must set
	// it.
	secureCookies := os.Getenv("SENDSCORE_SECURE_COOKIES") == "true"
	if secureCookies && os.Getenv("SENDSCORE_BASE_URL") == "" {
		log.Error("SENDSCORE_BASE_URL is required when SENDSCORE_SECURE_COOKIES=true")
		os.Exit(1)
	}

	var mailer mail.Sender = mail.Log{Logger: log}
	ses, ok, err := mail.FromEnv(context.Background())
	switch {
	case err != nil:
		log.Error("ses config", "err", err)
		os.Exit(1)
	case ok:
		mailer = ses
		log.Info("sign-in email via SES", "from", ses.From())
	case secureCookies:
		// A production log must never hold working sign-in links.
		log.Error("SES_ACCESS_KEY_ID and SES_SECRET_ACCESS_KEY are required when SENDSCORE_SECURE_COOKIES=true")
		os.Exit(1)
	default:
		log.Warn("SES is not configured, so sign-in links are logged here instead of emailed")
	}

	lists := blocklists()
	// Links are fetched with the engine's safe client, which refuses
	// non-public addresses and never follows unsubscribe or confirm links.
	checkLinks := os.Getenv("SENDSCORE_CHECK_LINKS") != "0"
	app, err := web.New(web.Config{
		Blocklists:     lists,
		CheckLinks:     checkLinks,
		BehindProxy:    !isLocal(baseURL),
		TrustProxy:     os.Getenv("SENDSCORE_TRUST_PROXY") == "1",
		SecureCookies:  secureCookies,
		Mailer:         mailer,
		FreeDailyTests: getint(log, "SENDSCORE_FREE_DAILY_TESTS", 25),
		AnonDailyTests: getint(log, "SENDSCORE_ANON_DAILY_TESTS", 5),
		BaseURL:        baseURL,
		MailDomain:     mailDomain,
		AddressTTL:     24 * time.Hour,
		ReportTTL:      7 * 24 * time.Hour,
	}, store, log)
	if err != nil {
		log.Error("templates", "err", err)
		os.Exit(1)
	}
	var tlsConfig *tls.Config
	if cert, key := os.Getenv("SENDSCORE_TLS_CERT"), os.Getenv("SENDSCORE_TLS_KEY"); cert != "" || key != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			log.Error("tls certificate", "err", err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	} else {
		log.Warn("STARTTLS is off: set SENDSCORE_TLS_CERT and SENDSCORE_TLS_KEY, or every message fails auth.tls")
	}
	rcv := receiver.New(receiver.Config{
		Addr:       smtpAddr,
		MailDomain: mailDomain,
		ReportTTL:  7 * 24 * time.Hour,
		TLS:        tlsConfig,
		Blocklists: lists,
		CheckLinks: checkLinks,
	}, store, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              httpAddr,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		log.Info("web listening", "addr", httpAddr, "base_url", baseURL, "db", dbPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("web server failed", "err", err)
			os.Exit(1)
		}
	}()
	go func() {
		log.Info("smtp listening", "addr", smtpAddr, "mail_domain", mailDomain)
		if err := rcv.ListenAndServe(); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			log.Error("smtp server failed", "err", err)
			os.Exit(1)
		}
	}()
	go sweep(ctx, store, log)

	<-ctx.Done()
	// Open long polls answer not_received at once, so agents call again
	// instead of seeing a reset. Uploads and SMTP sessions in DATA get up to
	// a minute to finish their checks (45 seconds) and save; a session
	// still open after that, such as an idle one, is dropped, and the sender
	// retries. A process manager's stop timeout must allow for that minute.
	log.Info("shutting down")
	app.StopWaits()
	shutdown, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = srv.Shutdown(shutdown) }()
	go func() { defer wg.Done(); _ = rcv.Shutdown(shutdown) }()
	wg.Wait()
	_ = rcv.Close()
}

// sweep deletes expired reports every hour.
func sweep(ctx context.Context, store *db.Store, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := store.Sweep(ctx); err != nil {
			log.Error("sweep", "err", err)
		} else if n > 0 {
			log.Info("swept expired reports", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// blocklists reads which domain blocklists to use. The free public zones
// are for non-commercial use, so the hosted service uses a Spamhaus DQS key;
// a personal self-hosted instance may turn the public zones on instead.
func blocklists() []engine.Blocklist {
	var out []engine.Blocklist
	public := os.Getenv("SENDSCORE_PUBLIC_BLOCKLISTS") == "1"
	switch key := os.Getenv("SENDSCORE_SPAMHAUS_DQS_KEY"); {
	case key != "":
		out = append(out, engine.SpamhausDQS(key))
	case public:
		out = append(out, engine.SpamhausPublic())
	}
	switch zone := os.Getenv("SENDSCORE_SURBL_ZONE"); {
	case zone != "":
		out = append(out, engine.SURBLZone(zone))
	case public:
		out = append(out, engine.SURBLPublic())
	}
	return out
}

// isLocal reports whether the public URL is this machine, as in development.
func isLocal(base string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return true
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getint reads a whole number setting, exiting on a value that is not one.
func getint(log *slog.Logger, key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		log.Error("setting must be a whole number", "key", key, "value", v)
		os.Exit(1)
	}
	return n
}

// loadDotEnv fills variables that are not already set from a KEY=value file.
func loadDotEnv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
}
