// Command sendscore-app runs the SendScore web app and its SMTP receiver in
// one process, sharing one SQLite database.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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

	"github.com/sendscore/sendscore-app/internal/billing"
	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore-app/internal/mail"
	"github.com/sendscore/sendscore-app/internal/monitor"
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
	// Secure cookies are the production switch, on by default for an https
	// base URL. Sign-in links are built from SENDSCORE_BASE_URL, never the
	// Host header, so production must set it.
	secureCookies, err := secureCookiesFor(baseURL, os.Getenv("SENDSCORE_SECURE_COOKIES"))
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	if secureCookies && os.Getenv("SENDSCORE_BASE_URL") == "" {
		log.Error("SENDSCORE_BASE_URL is required when SENDSCORE_SECURE_COOKIES=true")
		os.Exit(1)
	}

	var mailer mail.Sender = mail.Log{Logger: log}
	var alerter mail.Alerter = mail.Log{Logger: log}
	ses, ok, err := mail.FromEnv(context.Background())
	switch {
	case err != nil:
		log.Error("ses config", "err", err)
		os.Exit(1)
	case ok:
		mailer, alerter = ses, ses
		log.Info("sign-in email and alerts via SES", "from", ses.From(), "alerts_from", mail.AlertFrom())
	case secureCookies:
		// A production log must never hold working sign-in links.
		log.Error("SES_ACCESS_KEY_ID and SES_SECRET_ACCESS_KEY are required when SENDSCORE_SECURE_COOKIES=true")
		os.Exit(1)
	default:
		log.Warn("SES is not configured, so sign-in links and alerts are logged here instead of emailed")
	}

	// These accounts are Pro, now and at sign-in, whatever billing says.
	proEmails := emailList(os.Getenv("SENDSCORE_PRO_EMAILS"))
	if n, err := store.PromoteEmails(context.Background(), proEmails); err != nil {
		log.Error("pro accounts", "err", err)
		os.Exit(1)
	} else if n > 0 {
		log.Info("accounts moved to the pro plan", "count", n)
	}
	// Without billing nothing is for sale, so nobody is held to the free limits.
	billingClient := creem(log)
	if billingClient == nil {
		if n, err := store.PromoteAll(context.Background()); err != nil {
			log.Error("pro accounts", "err", err)
			os.Exit(1)
		} else if n > 0 {
			log.Info("accounts moved to the pro plan", "count", n)
		}
	}
	historyDays := getpos(log, "SENDSCORE_HISTORY_DAYS", 365)
	mon := &monitor.Monitor{
		Store: store, Mailer: alerter, BaseURL: baseURL, Log: log,
		PerDay: getpos(log, "SENDSCORE_ALERTS_PER_DAY", monitor.DefaultAlertsPerDay),
	}

	trustProxy := os.Getenv("SENDSCORE_TRUST_PROXY") == "1"
	if needsProxyWarning(baseURL, trustProxy) {
		// Behind a proxy every visitor would share the proxy's address, so
		// one person could use up the sign-in and anonymous limits for all.
		log.Warn("WARNING: SENDSCORE_BASE_URL is public but SENDSCORE_TRUST_PROXY is not set. Behind a reverse proxy every visitor then counts as the proxy's IP, " +
			"and one person can use up the sign-in and anonymous limits for everyone. Set SENDSCORE_TRUST_PROXY=1 behind a proxy, and only then.")
	}

	lists := blocklists()
	// Links are fetched with the engine's safe client, which refuses
	// non-public addresses and never follows unsubscribe or confirm links.
	checkLinks := os.Getenv("SENDSCORE_CHECK_LINKS") != "0"
	app, err := web.New(web.Config{
		Blocklists:           lists,
		CheckLinks:           checkLinks,
		BehindProxy:          !isLocal(baseURL),
		TrustProxy:           trustProxy,
		SecureCookies:        secureCookies,
		Mailer:               mailer,
		FreeDailyTests:       getint(log, "SENDSCORE_FREE_DAILY_TESTS", 25),
		ProDailyTests:        getpos(log, "SENDSCORE_PRO_DAILY_TESTS", web.DefaultProDailyTests),
		AnonDailyTests:       getint(log, "SENDSCORE_ANON_DAILY_TESTS", 5),
		SigninEmailsPerHour:  getpos(log, "SENDSCORE_SIGNIN_EMAILS_PER_HOUR", 200),
		RegistrationsPerHour: getpos(log, "SENDSCORE_OAUTH_REGISTRATIONS_PER_HOUR", 600),
		ProPublications:      getpos(log, "SENDSCORE_PRO_PUBLICATIONS", web.DefaultProPublications),
		FreePublications:     getint(log, "SENDSCORE_FREE_PUBLICATIONS", 0),
		ProEmails:            proEmails,
		Billing:              billingClient,
		HistoryDays:          historyDays,
		BaseURL:              baseURL,
		PrivacyURL:           os.Getenv("SENDSCORE_PRIVACY_URL"),
		TermsURL:             os.Getenv("SENDSCORE_TERMS_URL"),
		MailDomain:           mailDomain,
		AddressTTL:           24 * time.Hour,
		ReportTTL:            7 * 24 * time.Hour,
	}, store, log)
	if err != nil {
		log.Error("templates", "err", err)
		os.Exit(1)
	}
	var tlsConfig *tls.Config
	if cert, key := os.Getenv("SENDSCORE_TLS_CERT"), os.Getenv("SENDSCORE_TLS_KEY"); cert != "" || key != "" {
		// Reloaded when the files change, so a renewal needs no restart.
		certs, err := receiver.NewCertLoader(cert, key, func(err error) { log.Error("tls certificate reload", "err", err) })
		if err != nil {
			log.Error("tls certificate", "err", err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{GetCertificate: certs.GetCertificate, MinVersion: tls.VersionTLS12}
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

		MessagesPerAddress: getpos(log, "SENDSCORE_MESSAGES_PER_ADDRESS", receiver.DefaultMessagesPerAddress),
		DailyMessages:      getpos(log, "SENDSCORE_FREE_DAILY_MESSAGES", receiver.DefaultDailyMessages),
		ProDailyMessages:   getpos(log, "SENDSCORE_PRO_DAILY_MESSAGES", receiver.DefaultProDailyMessages),
		MaxSessions:        getpos(log, "SENDSCORE_SMTP_SESSIONS", receiver.DefaultMaxSessions),
		MaxSessionsPerIP:   getpos(log, "SENDSCORE_SMTP_SESSIONS_PER_IP", receiver.DefaultMaxSessionsPerIP),

		PublicationDailyMessages: getpos(log, "SENDSCORE_PUBLICATION_DAILY_MESSAGES", receiver.DefaultPublicationDailyMessages),
		HistoryTTL:               time.Duration(historyDays) * 24 * time.Hour,
		Monitor:                  mon,
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
	// The heartbeat: missed issues, and alerts waiting to be sent.
	go mon.Run(ctx)

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

// creem reads the Creem settings and returns the billing client, or nil
// when billing is off (a self-hosted instance sells nothing). It exits on a
// half-configured billing, and on one without SENDSCORE_SECRET, which signs
// the account in every checkout.
func creem(log *slog.Logger) *billing.Client {
	cfg := billing.Config{
		APIKey:         strings.TrimSpace(os.Getenv("CREEM_API_KEY")),
		WebhookSecret:  strings.TrimSpace(os.Getenv("CREEM_WEBHOOK_SECRET")),
		ProductMonthly: strings.TrimSpace(os.Getenv("CREEM_PRODUCT_PRO_MONTHLY")),
		ProductYearly:  strings.TrimSpace(os.Getenv("CREEM_PRODUCT_PRO_YEARLY")),
		Secret:         os.Getenv("SENDSCORE_SECRET"),
	}
	if !cfg.Configured() {
		if missing := cfg.Missing(); len(missing) < 3 {
			log.Error("billing is half configured; set the rest or none of them", "missing", strings.Join(missing, ", "))
			os.Exit(1)
		}
		return nil
	}
	if len(cfg.Secret) < billing.MinSecretLen {
		log.Error(fmt.Sprintf("SENDSCORE_SECRET must be at least %d characters when billing is on; it signs the account in each checkout", billing.MinSecretLen))
		os.Exit(1)
	}
	c := billing.New(cfg)
	log.Info("billing via Creem", "mode", c.Mode(), "yearly", c.YearlyOffered())
	return c
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
// are for non-commercial use, so a commercial instance uses a Spamhaus DQS key;
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

// secureCookiesFor reads SENDSCORE_SECURE_COOKIES: true or false, and when
// unset, on for an https base URL.
func secureCookiesFor(baseURL, setting string) (bool, error) {
	switch setting {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "":
		return strings.HasPrefix(baseURL, "https://"), nil
	}
	return false, fmt.Errorf("SENDSCORE_SECURE_COOKIES must be true or false, not %q", setting)
}

// needsProxyWarning reports whether a public site runs without trusting the
// proxy's X-Forwarded-For, which behind a proxy makes every visitor one IP.
func needsProxyWarning(baseURL string, trustProxy bool) bool {
	return !isLocal(baseURL) && !trustProxy
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

// emailList reads a comma separated list of addresses, normalized.
func emailList(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		if e = db.NormalizeEmail(e); e != "" {
			out = append(out, e)
		}
	}
	return out
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

// getpos is getint for a setting that must be at least 1, since 0 would
// mean the default.
func getpos(log *slog.Logger, key string, fallback int) int {
	n := getint(log, key, fallback)
	if n == 0 {
		log.Error("setting must be at least 1", "key", key)
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
