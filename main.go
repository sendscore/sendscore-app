// Command sendscore-app runs the SendScore web app and its SMTP receiver in
// one process, sharing one SQLite database.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/sendscore/sendscore-app/internal/budget"
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
	if len(os.Args) > 1 {
		os.Exit(command(os.Args[1:], os.Stdout, os.Stderr))
	}

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
	if err := checkConfig(baseURL, mailDomain, secureCookies); err != nil {
		log.Error(err.Error())
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
		log.Info("sign-in email and alerts via SES", "from", ses.From(), "alerts_from", ses.AlertFrom())
	case secureCookies || !isLocal(baseURL):
		// A production log must never hold working sign-in links.
		log.Error("SES_ACCESS_KEY_ID and SES_SECRET_ACCESS_KEY are required unless SENDSCORE_BASE_URL is local")
		os.Exit(1)
	default:
		log.Warn("SES is not configured, so sign-in links and alerts are logged here instead of emailed")
	}

	closedSignups, err := signupsClosed(os.Getenv("SENDSCORE_SIGNUPS"))
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	historyDays := getpos(log, "SENDSCORE_HISTORY_DAYS", 365)
	store.RawKeep = time.Duration(getpos(log, "SENDSCORE_RAW_DAYS", 30)) * 24 * time.Hour
	// Alerts link to issues, so they are kept a little longer than those.
	store.AlertKeep = time.Duration(historyDays+alertExtraDays) * 24 * time.Hour
	mon := &monitor.Monitor{
		Store: store, Mailer: alerter, BaseURL: baseURL, Log: log,
		PerDay:       getpos(log, "SENDSCORE_ALERTS_PER_DAY", monitor.DefaultAlertsPerDay),
		PerAccount:   getpos(log, "SENDSCORE_ALERTS_PER_ACCOUNT", monitor.DefaultAlertsPerAccount),
		PerRecipient: getpos(log, "SENDSCORE_ALERTS_PER_RECIPIENT", monitor.DefaultAlertsPerRecipient),
		PerHour:      getpos(log, "SENDSCORE_ALERTS_PER_HOUR", monitor.DefaultAlertsPerHour),
	}

	trustProxy := getbool(log, "SENDSCORE_TRUST_PROXY", false)
	trustedProxies, err := parseProxies(os.Getenv("SENDSCORE_TRUSTED_PROXIES"))
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	if needsProxyWarning(baseURL, trustProxy) {
		// Behind a proxy every visitor would share the proxy's address, so
		// one person could use up the sign-in and anonymous limits for all.
		log.Warn("WARNING: SENDSCORE_BASE_URL is public but SENDSCORE_TRUST_PROXY is not set. Behind a reverse proxy every visitor then counts as the proxy's IP, " +
			"and one person can use up the sign-in and anonymous limits for everyone. Set SENDSCORE_TRUST_PROXY=true behind a proxy, and only then.")
	}

	lists := blocklists(log)
	// Links are fetched with the engine's safe client, which refuses
	// non-public addresses and never follows unsubscribe or confirm links.
	checkLinks := getbool(log, "SENDSCORE_CHECK_LINKS", true)
	dailyBytes := getpos(log, "SENDSCORE_DAILY_MB", db.DefaultDailyBytes>>20) << 20
	accountBytes := int64(getpos(log, "SENDSCORE_ACCOUNT_STORAGE_MB", db.DefaultAccountBytes>>20)) << 20
	maxStorage := int64(getpos(log, "SENDSCORE_MAX_STORAGE_MB", db.DefaultMaxStorageBytes>>20)) << 20
	bufferBytes := int64(getpos(log, "SENDSCORE_SMTP_BUFFER_MB", receiver.DefaultMaxBufferedBytes>>20)) << 20
	if bufferBytes < receiver.MaxMessageBytes*budget.PerByte {
		log.Error(fmt.Sprintf("SENDSCORE_SMTP_BUFFER_MB must be at least %d, or the largest message could never be checked", receiver.MaxMessageBytes*budget.PerByte>>20))
		os.Exit(1)
	}
	memory := budget.New(bufferBytes)
	started := time.Now()
	app, err := web.New(web.Config{
		Blocklists:      lists,
		CheckLinks:      checkLinks,
		BehindProxy:     !isLocal(baseURL),
		TrustProxy:      trustProxy,
		TrustedProxies:  trustedProxies,
		ClosedSignups:   closedSignups,
		AnonDailyTotal:  getpos(log, "SENDSCORE_ANON_DAILY_TOTAL", web.DefaultAnonDailyTotal),
		DailyBytes:      dailyBytes,
		AccountBytes:    accountBytes,
		MaxStorageBytes: maxStorage,
		Memory:          memory,
		Health: func(ctx context.Context) error {
			return checkHealth(ctx, mon.LastTick(), started, time.Now(), smtpAddr)
		},
		SecureCookies:        secureCookies,
		Mailer:               mailer,
		DailyTests:           getpos(log, "SENDSCORE_DAILY_TESTS", web.DefaultDailyTests),
		AnonDailyTests:       getint(log, "SENDSCORE_ANON_DAILY_TESTS", anonDefault(closedSignups, isLocal(baseURL))),
		SigninEmailsPerHour:  getpos(log, "SENDSCORE_SIGNIN_EMAILS_PER_HOUR", 200),
		RegistrationsPerHour: getpos(log, "SENDSCORE_OAUTH_REGISTRATIONS_PER_HOUR", 600),
		Publications:         getpos(log, "SENDSCORE_PUBLICATIONS", web.DefaultPublications),
		AllowedEmails:        emailList(os.Getenv("SENDSCORE_ALLOWED_EMAILS")),
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
		DailyMessages:      getpos(log, "SENDSCORE_DAILY_MESSAGES", receiver.DefaultDailyMessages),
		MaxSessions:        getpos(log, "SENDSCORE_SMTP_SESSIONS", receiver.DefaultMaxSessions),
		MaxSessionsPerIP:   getpos(log, "SENDSCORE_SMTP_SESSIONS_PER_IP", receiver.DefaultMaxSessionsPerIP),

		DailyBytes:        dailyBytes,
		AccountBytes:      accountBytes,
		AnonDailyMessages: getpos(log, "SENDSCORE_ANON_DAILY_MESSAGES", receiver.DefaultAnonDailyMessages),
		MaxStorageBytes:   maxStorage,
		Memory:            memory,
		MaxAnalyzing:      getpos(log, "SENDSCORE_SMTP_ANALYZING", receiver.DefaultMaxAnalyzing),

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
	var background sync.WaitGroup
	background.Go(func() { sweep(ctx, store, log) })
	// The heartbeat: missed issues, and alerts waiting to be sent.
	background.Go(func() { mon.Run(ctx) })
	// Sign-in links, sent apart from the request.
	background.Go(func() { app.RunSignins(ctx) })

	<-ctx.Done()
	// A second signal now stops the process at once.
	stop()
	// Open long polls answer not_received at once, so agents call again
	// instead of seeing a reset. Uploads and SMTP sessions in DATA get
	// shutdownGrace to finish. The slowest message waits for a turn (30
	// seconds), is checked (45), saved (10), and sends an alert (10), so it
	// can pass that; a session still open then is dropped when the process
	// exits, and the sender retries, which loses nothing. A process manager's
	// stop timeout must allow for shutdownGrace plus backgroundGrace. The
	// heartbeat and the sweep finish before the database closes, so no send
	// loses its status.
	log.Info("shutting down")
	app.StopWaits()
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() { _ = srv.Shutdown(shutdown) })
	wg.Go(func() { _ = rcv.Shutdown(shutdown) })
	wg.Wait()
	done := make(chan struct{})
	go func() { background.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(backgroundGrace):
		log.Warn("the heartbeat or the sweep did not stop in time")
	}
}

// alertExtraDays is how much longer than an issue its alerts are kept.
const alertExtraDays = 35

// How long shutdown waits for sessions, then for the heartbeat and the sweep.
// Together they stay under the 90 seconds compose.yaml gives the process.
const (
	shutdownGrace   = 70 * time.Second
	backgroundGrace = 15 * time.Second
)

// maxTickAge is how long the heartbeat may go quiet before /healthz fails.
const maxTickAge = 5 * time.Minute

// checkHealth is what /healthz adds to the database check: the heartbeat ran
// recently, and the SMTP listener takes connections.
func checkHealth(ctx context.Context, last, started, now time.Time, smtpAddr string) error {
	if last.IsZero() {
		last = started
	}
	if age := now.Sub(last); age > maxTickAge {
		return fmt.Errorf("the heartbeat last ran %s ago", age.Round(time.Second))
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.DialContext(ctx, "tcp", localAddr(smtpAddr))
	if err != nil {
		return fmt.Errorf("smtp listener: %w", err)
	}
	return c.Close()
}

// localAddr is how this machine reaches a listen address.
func localAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// command runs a subcommand and returns the exit code: healthcheck, for
// Docker's HEALTHCHECK, since the image has no shell or curl, and backup, for
// a consistent copy of the live database.
func command(args []string, stdout, stderr io.Writer) int {
	switch {
	case args[0] == "healthcheck" && len(args) == 1:
		c := http.Client{Timeout: 5 * time.Second}
		res, err := c.Get("http://" + localAddr(getenv("SENDSCORE_ADDR", "127.0.0.1:3014")) + "/healthz")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			fmt.Fprintln(stderr, "unhealthy:", res.Status)
			return 1
		}
		fmt.Fprintln(stdout, "ok")
		return 0
	case args[0] == "backup" && len(args) == 2:
		store, err := db.Open(getenv("SENDSCORE_DB", "sendscore.db"))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer store.Close()
		if err := store.Backup(context.Background(), args[1]); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, "wrote", args[1])
		return 0
	}
	fmt.Fprintln(stderr, "usage: sendscore-app [healthcheck | backup <new file>]")
	return 64
}

// checkConfig refuses settings that would start cleanly and then fail for
// every visitor.
func checkConfig(baseURL, mailDomain string, secureCookies bool) error {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("SENDSCORE_BASE_URL must be a full URL such as https://sendscore.example.com, not %q", baseURL)
	}
	if secureCookies && u.Scheme != "https" {
		return errors.New("SENDSCORE_SECURE_COOKIES needs an https SENDSCORE_BASE_URL, since a browser drops these cookies over http")
	}
	if !isLocal(baseURL) && mailDomain == "localhost" {
		return errors.New("SENDSCORE_MAIL_DOMAIN is required in production: without it, test addresses end in @localhost and mail for your domain is refused")
	}
	return nil
}

// signupsClosed reads SENDSCORE_SIGNUPS, open or closed, which is closed when
// unset. The limits suit an operator and their team, not the whole internet.
func signupsClosed(setting string) (bool, error) {
	switch setting {
	case "open":
		return false, nil
	case "closed", "":
		return true, nil
	}
	return false, fmt.Errorf("SENDSCORE_SIGNUPS must be open or closed, not %q", setting)
}

// anonDefault is SENDSCORE_ANON_DAILY_TESTS when unset: off for a public
// instance with closed sign-ups, whose visitors have no reason to be here.
func anonDefault(closedSignups, local bool) int {
	if closedSignups && !local {
		return 0
	}
	return 5
}

// parseProxies reads SENDSCORE_TRUSTED_PROXIES, comma separated addresses or
// CIDR ranges, or nil for the default.
func parseProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if addr, err := netip.ParseAddr(p); err == nil {
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("SENDSCORE_TRUSTED_PROXIES: %q is not an address or a CIDR range", p)
		}
		out = append(out, prefix)
	}
	return out, nil
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
func blocklists(log *slog.Logger) []engine.Blocklist {
	var out []engine.Blocklist
	public := getbool(log, "SENDSCORE_PUBLIC_BLOCKLISTS", false)
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

// parseBool reads a yes or no setting: 1 or true, 0 or false. Anything else is
// an error, so a misspelled setting never silently means off.
func parseBool(key, value string) (bool, error) {
	switch value {
	case "1", "true":
		return true, nil
	case "0", "false":
		return false, nil
	}
	return false, fmt.Errorf("%s must be true or false, not %q", key, value)
}

// getbool reads a yes or no setting, exiting on anything else.
func getbool(log *slog.Logger, key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := parseBool(key, v)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	return b
}

// secureCookiesFor reads SENDSCORE_SECURE_COOKIES, which when unset is on for
// an https base URL.
func secureCookiesFor(baseURL, setting string) (bool, error) {
	if setting == "" {
		return strings.HasPrefix(baseURL, "https://"), nil
	}
	return parseBool("SENDSCORE_SECURE_COOKIES", setting)
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
