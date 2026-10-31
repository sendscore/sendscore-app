// Package web serves the app: test addresses, reports, uploads, and the JSON
// API the MCP tools call.
package web

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore-app/internal/mail"
	"github.com/sendscore/sendscore/engine"
	"github.com/sendscore/sendscore/verdict"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed assets
var assetFS embed.FS

// Config configures the app.
type Config struct {
	BaseURL string
	// PrivacyURL and TermsURL are the operator's policy pages, linked from
	// the footer and the sign-in page when set.
	PrivacyURL string
	TermsURL   string
	MailDomain string
	AddressTTL time.Duration
	ReportTTL  time.Duration
	// MaxWait bounds the long poll behind wait_for_message. It defaults to
	// 50 seconds, below the 60 second idle timeouts of common proxies.
	MaxWait time.Duration
	// CheckLinks fetches the links and images in uploaded messages.
	CheckLinks bool
	// Resolver overrides DNS for uploads (tests).
	Resolver engine.Resolver
	// Blocklists are the domain blocklists uploads are checked against.
	Blocklists []engine.Blocklist
	// BehindProxy is set when a reverse proxy on the same machine forwards
	// public requests, so loopback connections carry a public Host header.
	BehindProxy bool
	// TrustProxy takes the client IP for limits from X-Forwarded-For.
	TrustProxy bool
	// SecureCookies marks cookies Secure, for a site served over HTTPS.
	SecureCookies bool
	// Mailer sends sign-in links. It defaults to logging them.
	Mailer mail.Sender
	// DailyTests and AnonDailyTests are the test addresses (and uploads) per
	// UTC day for an account and for an anonymous IP.
	DailyTests     int
	AnonDailyTests int
	// SigninEmailsPerHour caps the sign-in emails the whole service sends
	// in an hour. It defaults to 200.
	SigninEmailsPerHour int
	// RegistrationsPerHour caps OAuth client registrations for the whole
	// service in an hour, on top of the per-network limit. It defaults to
	// 600.
	RegistrationsPerHour int
	// Publications is how many newsletters an account may monitor. It
	// defaults to DefaultPublications.
	Publications int
	// AllowedEmails may make an account while sign-ups are closed.
	AllowedEmails []string
	// ClosedSignups lets only AllowedEmails make a new account. Accounts that
	// exist still sign in, and the sign-in page says the same to everyone.
	ClosedSignups bool
	// AnonDailyTotal caps test addresses and uploads by all anonymous
	// visitors together in a UTC day. It defaults to DefaultAnonDailyTotal.
	AnonDailyTotal int
	// DailyBytes is what one account, or anonymous uploads together, may
	// store by upload in a UTC day, and MaxStorageBytes the database size at
	// which uploads are refused. Both have defaults.
	DailyBytes      int
	MaxStorageBytes int64
	// TrustedProxies are the addresses X-Forwarded-For is believed from, with
	// TrustProxy on. It defaults to loopback and private networks.
	TrustedProxies []netip.Prefix
	// Health adds checks to /healthz, such as the heartbeat's age.
	Health func(context.Context) error
	// HistoryDays is how long a newsletter's history is kept,
	// for the pages to say.
	HistoryDays int
}

// Bounds on long polls (API and MCP waits) open at once, per account and in
// all, and on uploads being checked at once.
const (
	maxWaitsPerUser = 5
	maxWaits        = 200
	maxUploads      = 4
	// uploadsPerIP is how many of those one network may hold.
	uploadsPerIP = 1
)

// Defaults for the volume limits in Config.
const (
	DefaultAnonDailyTotal  = 100
	DefaultDailyBytes      = 1 << 30
	DefaultMaxStorageBytes = 10 << 30
)

// MaxUploadBytes is the largest upload checked, the same as the largest
// message the receiver accepts.
const MaxUploadBytes = 25 << 20

const tooLargeMessage = "This file is larger than 25 MB, which is the largest message SendScore checks."

// App is the web application.
type App struct {
	cfg   Config
	store *db.Store
	log   *slog.Logger
	tmpl  map[string]*template.Template

	// quit is closed by StopWaits, so long polls answer before shutdown.
	quit     chan struct{}
	quitOnce sync.Once

	// waits counts open long polls per user ("" is the total).
	waitMu sync.Mutex
	waits  map[string]int
	// uploads holds a slot per upload being read or checked, and uploadIPs
	// counts them per network, under waitMu.
	uploads   chan struct{}
	uploadIPs map[string]int
}

// StopWaits makes every open and future long poll answer at once, as if its
// timeout had passed. Call it before shutting the HTTP server down, which
// waits for handlers but never cancels them.
func (a *App) StopWaits() { a.quitOnce.Do(func() { close(a.quit) }) }

// New builds the app.
func New(cfg Config, store *db.Store, log *slog.Logger) (*App, error) {
	if cfg.MaxWait == 0 {
		cfg.MaxWait = 50 * time.Second
	}
	if cfg.Mailer == nil {
		cfg.Mailer = mail.Log{Logger: log}
	}
	if cfg.SigninEmailsPerHour == 0 {
		cfg.SigninEmailsPerHour = 200
	}
	if cfg.RegistrationsPerHour == 0 {
		cfg.RegistrationsPerHour = 600
	}
	if cfg.DailyTests == 0 {
		cfg.DailyTests = DefaultDailyTests
	}
	if cfg.Publications == 0 {
		cfg.Publications = DefaultPublications
	}
	if cfg.HistoryDays == 0 {
		cfg.HistoryDays = 365
	}
	if cfg.AnonDailyTotal == 0 {
		cfg.AnonDailyTotal = DefaultAnonDailyTotal
	}
	if cfg.DailyBytes == 0 {
		cfg.DailyBytes = DefaultDailyBytes
	}
	if cfg.MaxStorageBytes == 0 {
		cfg.MaxStorageBytes = DefaultMaxStorageBytes
	}
	if cfg.TrustedProxies == nil {
		cfg.TrustedProxies = DefaultTrustedProxies()
	}
	a := &App{cfg: cfg, store: store, log: log, tmpl: map[string]*template.Template{}, quit: make(chan struct{}),
		waits: map[string]int{}, uploads: make(chan struct{}, maxUploads), uploadIPs: map[string]int{}}
	funcs := template.FuncMap{
		"lower":  strings.ToLower,
		"status": func(s verdict.Status) string { return string(s) },
		"kb":     func(n int) string { return strconv.Itoa((n+1023)/1024) + " KB" },
		"when":   func(t time.Time) string { return t.UTC().Format("2 Jan 2006, 15:04 UTC") },
		"day":    func(t time.Time) string { return t.UTC().Format("2 Jan 2006") },
		"who": func(w string) string {
			if w == verdict.FixedByProvider {
				return "your email platform"
			}
			return "you"
		},
		"json": func(v any) string {
			b, _ := json.MarshalIndent(v, "", "  ")
			return string(b)
		},
		// local formats t in an IANA time zone, falling back to UTC.
		"local": func(t time.Time, zone string) string {
			if loc, err := time.LoadLocation(zone); err == nil {
				t = t.In(loc)
			}
			return t.Format("Mon 2 Jan 2006, 15:04 MST")
		},
		"worsened":   worsened,
		"privacyURL": func() string { return cfg.PrivacyURL },
		"termsURL":   func() string { return cfg.TermsURL },
	}
	for _, page := range []string{"home", "address", "report", "upload", "error", "signin", "account", "consent",
		"newsletters", "newsletter", "newsletter_form", "newsletter_delete", "message", "account_delete", "alerts"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/"+page+".html")
		if err != nil {
			return nil, err
		}
		a.tmpl[page] = t
	}
	return a, nil
}

// Routes returns the handler.
func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()
	assets, _ := fs.Sub(assetFS, "assets")
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServerFS(assets)))

	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/assets/images/favicon.ico", http.StatusMovedPermanently)
	})
	// Every POST form goes through a.form, which checks the CSRF token.
	const formLimit = 64 << 10
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("POST /test", a.form(formLimit, a.createAddressPage))
	mux.HandleFunc("GET /t/{token}", a.addressPage)
	mux.HandleFunc("GET /upload", a.uploadForm)
	// The body may be a little larger than the file, for the form fields.
	// uploadGate refuses an upload over the daily limit, or when too many
	// are in progress, before a.form reads the body.
	mux.HandleFunc("POST /upload", a.uploadGate(a.form(MaxUploadBytes+1<<20, a.upload)))
	mux.HandleFunc("GET /r/{id}", a.reportPage)
	mux.HandleFunc("GET /r/{id}/raw", a.rawMessage)
	mux.HandleFunc("GET /r/{id}/json", a.reportJSON)

	mux.HandleFunc("GET /signin", a.signinForm)
	mux.HandleFunc("POST /signin", a.form(formLimit, a.signin))
	mux.HandleFunc("GET /signin/verify", a.verifyForm)
	mux.HandleFunc("POST /signin/verify", a.form(formLimit, a.verify))
	mux.HandleFunc("POST /signout", a.form(formLimit, a.signout))
	mux.HandleFunc("GET /account", a.account)
	mux.HandleFunc("POST /account/tokens", a.form(formLimit, a.createToken))
	mux.HandleFunc("POST /account/tokens/{id}/revoke", a.form(formLimit, a.revokeToken))
	mux.HandleFunc("POST /account/apps/{id}/disconnect", a.form(formLimit, a.disconnect))
	// Deleting the account (see delete.go). Web only, never the API.
	mux.HandleFunc("GET /account/delete", a.deleteAccountForm)
	mux.HandleFunc("POST /account/delete", a.form(formLimit, a.deleteAccount))

	// Monitored newsletters (see newsletters.go).
	mux.HandleFunc("GET /newsletters", a.newsletters)
	mux.HandleFunc("GET /newsletters/new", a.newNewsletter)
	mux.HandleFunc("POST /newsletters", a.form(formLimit, a.createNewsletter))
	mux.HandleFunc("GET /newsletters/{id}", a.newsletter)
	mux.HandleFunc("POST /newsletters/{id}", a.form(formLimit, a.updateNewsletter))
	mux.HandleFunc("GET /newsletters/{id}/edit", a.editNewsletter)
	mux.HandleFunc("GET /newsletters/{id}/delete", a.deleteNewsletterForm)
	mux.HandleFunc("POST /newsletters/{id}/delete", a.form(formLimit, a.deleteNewsletter))
	mux.HandleFunc("GET /newsletters/{id}/messages/{mid}", a.messageView)
	mux.HandleFunc("POST /newsletters/{id}/messages/{mid}/kind", a.form(formLimit, a.messageKind))
	// Pages an alert's recipient opens, who has no account here.
	mux.HandleFunc("GET /alerts/confirm", a.alertConfirmForm)
	mux.HandleFunc("POST /alerts/confirm", a.form(formLimit, a.alertConfirm))
	mux.HandleFunc("GET /alerts/stop/{token}", a.alertStopForm)
	mux.HandleFunc("POST /alerts/stop/{token}", a.form(formLimit, a.alertStop))

	// OAuth for the MCP connector (see oauth.go).
	mux.Handle("/.well-known/oauth-protected-resource", cors(http.HandlerFunc(a.protectedResource)))
	mux.Handle("/.well-known/oauth-protected-resource/api/mcp", cors(http.HandlerFunc(a.protectedResource)))
	mux.Handle("/.well-known/oauth-authorization-server", cors(http.HandlerFunc(a.authorizationServer)))
	mux.Handle("/.well-known/mcp/server-card.json", cors(http.HandlerFunc(a.serverCard)))
	mux.Handle("/oauth/register", cors(onlyPost(a.register)))
	mux.Handle("/oauth/token", cors(onlyPost(a.token)))
	mux.HandleFunc("GET /oauth/authorize", a.authorize)
	mux.HandleFunc("POST /oauth/authorize", a.form(formLimit, a.approve))

	// The API and the MCP connector take an API token, not the session.
	mux.HandleFunc("POST /api/v1/test-addresses", a.api(a.apiCreateAddress))
	mux.HandleFunc("GET /api/v1/test-addresses/{token}/wait", a.api(a.apiWait))
	mux.HandleFunc("GET /api/v1/reports/{id}", a.api(a.apiReport))
	mux.HandleFunc("GET /api/v1/publications", a.api(a.apiPublications))
	mux.HandleFunc("GET /api/v1/publications/{id}", a.api(a.apiPublicationByID))
	mux.Handle("/api/mcp", cors(a.mcpAuth(a.mcpHandler())))
	return a.secure(a.session(mux))
}

// csp allows no inline script or style, like Preflight.
const csp = "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// secure sets the headers every response carries. A site served over HTTPS
// (SecureCookies) also gets Strict-Transport-Security, so a browser never
// tries plain HTTP again.
func (a *App) secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", csp)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "same-origin")
		if a.cfg.SecureCookies {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}

// onlyPost answers 405 to anything but POST (OPTIONS is handled by cors).
func onlyPost(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST, OPTIONS")
			apiError(w, http.StatusMethodNotAllowed, "use POST")
			return
		}
		h(w, r)
	})
}

func (a *App) render(w http.ResponseWriter, r *http.Request, status int, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["MailDomain"] = a.cfg.MailDomain
	data["User"] = userFrom(r.Context())
	data["ReportDays"] = int(a.cfg.ReportTTL / (24 * time.Hour))
	data["CSRF"], _ = r.Context().Value(csrfKey).(string)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := a.tmpl[page].Execute(w, data); err != nil {
		a.log.Error("render", "page", page, "err", err)
	}
}

func (a *App) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	a.render(w, r, status, "error", map[string]any{"Title": http.StatusText(status), "Message": msg})
}

func (a *App) address(token string) string {
	return "t-" + token + "@" + a.cfg.MailDomain
}

func (a *App) home(w http.ResponseWriter, r *http.Request) {
	deleted := r.URL.Query().Get("deleted") == "1" && userFrom(r.Context()) == nil
	a.render(w, r, http.StatusOK, "home", map[string]any{"Title": "Check a newsletter", "Deleted": deleted})
}

// healthz answers 200 when the database answers and cfg.Health passes, and
// 503 otherwise, saying no more than that to the public.
func (a *App) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	err := a.store.DB.QueryRowContext(ctx, `SELECT 1 FROM users LIMIT 1`).Scan(new(int))
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if err == nil && a.cfg.Health != nil {
		err = a.cfg.Health(ctx)
	}
	if err != nil {
		a.log.Error("health check", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "failing"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// testRefused answers a takeTest error: the allowance page, or a plain
// failure, since a broken database is not a used-up allowance.
func (a *App) testRefused(w http.ResponseWriter, r *http.Request, limit int, err error) {
	if errors.Is(err, db.ErrLimit) {
		a.limitPage(w, r, limit)
		return
	}
	a.log.Error("count test", "err", err)
	a.fail(w, r, http.StatusInternalServerError, "Could not count this test. Try again in a minute.")
}

func (a *App) createAddressPage(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if limit, err := a.takeTest(r.Context(), u, a.clientIP(r)); err != nil {
		a.testRefused(w, r, limit, err)
		return
	}
	// An address belongs to the account, or for an anonymous visitor, to
	// this browser (by its CSRF cookie), so its reports show the address
	// only to whoever made it.
	uid, creator := "", ""
	if u != nil {
		uid = u.ID
	} else if c, _ := r.Context().Value(csrfKey).(string); c != "" {
		creator = db.HashToken(c)
	}
	addr, err := a.store.CreateAddressBy(r.Context(), a.cfg.AddressTTL, uid, creator)
	if err != nil {
		a.log.Error("create address", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not create a test address.")
		return
	}
	http.Redirect(w, r, "/t/"+addr.Token, http.StatusSeeOther)
}

func (a *App) addressPage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	// An expired address still opens its reports while they are kept.
	addr, err := a.store.AnyAddressByToken(r.Context(), token)
	if err != nil {
		a.fail(w, r, http.StatusNotFound, "This test address does not exist, or it has expired and its reports were deleted.")
		return
	}
	// After a report, the page waits for the next message instead.
	m, err := a.store.LatestForToken(r.Context(), token, r.URL.Query().Get("after"))
	if err == nil {
		http.Redirect(w, r, "/r/"+m.ID, http.StatusSeeOther)
		return
	}
	if errors.Is(err, db.ErrUnknownAfter) {
		a.fail(w, r, http.StatusNotFound, "That report did not come from this test address.")
		return
	}
	if addr.Expired(a.store.Now()) {
		a.render(w, r, http.StatusGone, "error", map[string]any{"Title": "Address expired",
			"Message": "This test address stopped accepting mail on " + addr.ExpiresAt.Format("2 Jan 2006 at 15:04 UTC") + ", and no new message arrived before then. Start a new test to get another address."})
		return
	}
	a.render(w, r, http.StatusOK, "address", map[string]any{
		"Title": "Waiting for your email", "Address": a.address(addr.Token), "Expires": addr.ExpiresAt,
		"Refresh": true,
	})
}

func (a *App) uploadForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, http.StatusOK, "upload", map[string]any{"Title": "Check a saved email"})
}

// uploadGate runs before an upload's body is read. It refuses a post from
// another site, an upload while the network has another in progress or
// maxUploads others are being read or checked, and a visitor whose daily
// allowance is used up, so a flood of large bodies costs neither memory nor
// disk. The allowance is counted here, so a body that never arrives is not
// free.
func (a *App) uploadGate(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.sameOrigin(r) || !a.hasCSRFCookie(r) {
			a.fail(w, r, http.StatusForbidden, formExpired)
			return
		}
		ip := a.clientIP(r)
		if !a.takeUploadSlot(ip) {
			a.fail(w, r, http.StatusServiceUnavailable, "SendScore is checking several uploads right now. Try again in a minute.")
			return
		}
		defer a.releaseUploadSlot(ip)
		if n, err := a.store.SizeBytes(r.Context()); err != nil {
			a.log.Error("database size", "err", err)
		} else if n >= a.cfg.MaxStorageBytes {
			a.log.Error("refusing uploads: the database reached SENDSCORE_MAX_STORAGE_MB", "bytes", n)
			a.fail(w, r, http.StatusServiceUnavailable, "This SendScore is out of storage for messages. Try again later.")
			return
		}
		if limit, err := a.takeTest(r.Context(), userFrom(r.Context()), ip); err != nil {
			a.testRefused(w, r, limit, err)
			return
		}
		h(w, r)
	}
}

func (a *App) takeUploadSlot(ip string) bool {
	a.waitMu.Lock()
	defer a.waitMu.Unlock()
	if a.uploadIPs[ip] >= uploadsPerIP {
		return false
	}
	select {
	case a.uploads <- struct{}{}:
		a.uploadIPs[ip]++
		return true
	default:
		return false
	}
}

func (a *App) releaseUploadSlot(ip string) {
	a.waitMu.Lock()
	defer a.waitMu.Unlock()
	<-a.uploads
	if a.uploadIPs[ip]--; a.uploadIPs[ip] <= 0 {
		delete(a.uploadIPs, ip)
	}
}

func (a *App) upload(w http.ResponseWriter, r *http.Request) {
	// a.form has parsed the body, within the size limit; a large file was
	// spilled to a temporary file.
	file, _, err := r.FormFile("message")
	if err != nil {
		if tooLarge := (*http.MaxBytesError)(nil); errors.As(err, &tooLarge) {
			a.fail(w, r, http.StatusRequestEntityTooLarge, tooLargeMessage)
			return
		}
		a.fail(w, r, http.StatusBadRequest, "Choose an .eml file to check.")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxUploadBytes+1))
	if err != nil {
		a.fail(w, r, http.StatusBadRequest, "Could not read the file.")
		return
	}
	if len(raw) > MaxUploadBytes {
		a.fail(w, r, http.StatusRequestEntityTooLarge, tooLargeMessage)
		return
	}
	u := userFrom(r.Context())
	owner := "bytes:anon"
	if u != nil {
		owner = "bytes:user:" + u.ID
	}
	if _, err := a.store.TakeAll(r.Context(), []db.Cap{{Name: owner, Bucket: db.Day(a.store.Now()), Limit: a.cfg.DailyBytes, N: len(raw), Keep: 48 * time.Hour}}); err != nil {
		if errors.Is(err, db.ErrLimit) {
			a.fail(w, r, http.StatusTooManyRequests, "Today's storage for uploads is used up. The allowance starts again at midnight UTC.")
			return
		}
		a.log.Error("count upload", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not count this upload. Try again in a minute.")
		return
	}
	env := engine.Envelope{MailFrom: strings.TrimSpace(r.FormValue("mail_from"))}
	if ip := strings.TrimSpace(r.FormValue("ip")); ip != "" {
		env.RemoteIP = net.ParseIP(ip)
		if env.RemoteIP == nil {
			a.fail(w, r, http.StatusBadRequest, "The sending IP is not an IP address.")
			return
		}
	}
	now := a.store.Now().UTC()
	// The server's write deadline started when the headers were read, and
	// reading a large body may have used most of it, so the response gets a
	// fresh one that covers the checks and the save.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(uploadCheckTimeout + 30*time.Second))
	actx, cancel := context.WithTimeout(r.Context(), uploadCheckTimeout)
	defer cancel()
	v, err := engine.Analyze(actx, raw, engine.Options{
		Envelope: env, Resolver: a.cfg.Resolver, CheckLinks: a.cfg.CheckLinks,
		Blocklists: a.cfg.Blocklists, ReceivedAt: now,
	})
	if err != nil {
		a.fail(w, r, http.StatusBadRequest, "That file is not an email message. "+err.Error())
		return
	}
	m := &db.Message{Source: "upload", ReceivedAt: now, ExpiresAt: now.Add(a.cfg.ReportTTL),
		RemoteIP: r.FormValue("ip"), MailFrom: env.MailFrom, Raw: raw, Verdict: v}
	if u != nil {
		// A signed-in upload is the account's, so the API and MCP can read it.
		m.UserID = u.ID
	}
	if err := a.store.SaveMessage(r.Context(), m); err != nil {
		a.log.Error("save upload", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not save the report.")
		return
	}
	http.Redirect(w, r, "/r/"+m.ID, http.StatusSeeOther)
}

// uploadCheckTimeout bounds the checks on an upload.
const uploadCheckTimeout = 45 * time.Second

type section struct {
	Name   string
	Checks []verdict.Check
}

var sections = []struct {
	cat  verdict.Category
	name string
}{
	{verdict.Auth, "Authentication"},
	{verdict.Unsub, "Unsubscribe"},
	{verdict.Structure, "Structure"},
	{verdict.Content, "Content"},
	{verdict.Delivery, "Delivery"},
	{verdict.Changes, "Changes"},
}

func (a *App) reportPage(w http.ResponseWriter, r *http.Request) {
	m, err := a.store.MessageByID(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, r, http.StatusNotFound, "This report does not exist, or it has expired.")
		return
	}
	var secs []section
	for _, s := range sections {
		var cs []verdict.Check
		for _, c := range m.Verdict.Checks {
			if c.Category == s.cat {
				cs = append(cs, c)
			}
		}
		if len(cs) > 0 {
			secs = append(secs, section{Name: s.name, Checks: cs})
		}
	}
	data := map[string]any{"Title": m.Verdict.Message.Subject, "M": m, "V": m.Verdict, "Sections": secs, "ShowRaw": a.ownsMessage(r, m)}
	// Only whoever made the address sees it and the link to send again,
	// since a report link is shared and the address takes mail from anyone.
	if m.Token != "" {
		if addr, err := a.store.AnyAddressByToken(r.Context(), m.Token); err == nil && a.ownsAddress(r, addr) {
			data["Resend"] = !addr.Expired(a.store.Now())
			data["Address"] = a.address(addr.Token)
		}
	}
	// The owner of a newsletter gets a way back to its timeline.
	if u := userFrom(r.Context()); m.PublicationID != "" && u != nil {
		if p, err := a.store.PublicationForUser(r.Context(), m.PublicationID, u.ID); err == nil {
			data["Publication"] = p
		}
	}
	a.render(w, r, http.StatusOK, "report", data)
}

// ownsAddress reports whether the request comes from the account that owns
// addr, or for an anonymous address, the browser that made it.
func (a *App) ownsAddress(r *http.Request, addr db.Address) bool {
	if addr.UserID != "" {
		u := userFrom(r.Context())
		return u != nil && u.ID == addr.UserID
	}
	c, _ := r.Context().Value(csrfKey).(string)
	return addr.Creator != "" && c != "" && db.HashToken(c) == addr.Creator
}

// ownsMessage reports whether the visitor may read a message's original. Its
// headers name the address it was sent to, whose token opens every later
// report and lets anyone send to it, so a shared report link must not lead
// there. An anonymous upload has no address and no owner, so it stays open.
func (a *App) ownsMessage(r *http.Request, m *db.Message) bool {
	ctx := r.Context()
	if m.Token != "" {
		addr, err := a.store.AnyAddressByToken(ctx, m.Token)
		return err == nil && a.ownsAddress(r, addr)
	}
	if m.UserID != "" {
		u := userFrom(ctx)
		return u != nil && u.ID == m.UserID
	}
	return m.PublicationID == ""
}

func (a *App) rawMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m, err := a.store.MessageByID(r.Context(), id)
	if err != nil || !a.ownsMessage(r, m) {
		http.NotFound(w, r)
		return
	}
	raw, err := a.store.RawByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="`+id+`.eml"`)
	w.Write(raw)
}

// API

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Served as JSON with nosniff, so < and > need no escaping.
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (a *App) apiCreateAddress(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if limit, err := a.takeTest(r.Context(), u, ""); err != nil {
		if !errors.Is(err, db.ErrLimit) {
			a.log.Error("count test", "err", err)
			apiError(w, http.StatusInternalServerError, "could not count the test")
			return
		}
		apiError(w, http.StatusTooManyRequests, limitError(limit))
		return
	}
	addr, err := a.store.CreateAddressFor(r.Context(), a.cfg.AddressTTL, u.ID)
	if err != nil {
		a.log.Error("create address", "err", err)
		apiError(w, http.StatusInternalServerError, "could not create a test address")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"address":    a.address(addr.Token),
		"token":      addr.Token,
		"expires_at": addr.ExpiresAt,
		"wait_url":   a.cfg.BaseURL + "/api/v1/test-addresses/" + addr.Token + "/wait",
		"page_url":   a.cfg.BaseURL + "/t/" + addr.Token,
	})
}

// apiWait long-polls until a message arrives at the address or the timeout
// passes. It answers 200 either way; status says which. With ?after=<report
// id>, only a message received after that report counts.
func (a *App) apiWait(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	u := userFrom(r.Context())
	// Another account's address is answered as if it did not exist. An
	// expired address still answers while its reports are kept.
	addr, err := a.store.AnyAddressByToken(r.Context(), token)
	if err != nil || addr.UserID != u.ID {
		apiError(w, http.StatusNotFound, "no such test address, or it has expired and its reports were deleted")
		return
	}
	timeout := 30 * time.Second
	if s := r.URL.Query().Get("timeout"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			apiError(w, http.StatusBadRequest, "timeout must be a number of seconds")
			return
		}
		timeout = time.Duration(n) * time.Second
	}
	m, err := a.wait(r.Context(), u.ID, addr, r.URL.Query().Get("after"), timeout)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "received", "report_id": m.ID,
			"report_url": a.cfg.BaseURL + "/r/" + m.ID,
			"verdict":    m.Verdict,
		})
	case errors.Is(err, errNotReceived):
		writeJSON(w, http.StatusOK, map[string]any{"status": "not_received"})
	case errors.Is(err, errExpired):
		apiError(w, http.StatusGone, expiredMessage(addr))
	case errors.Is(err, errTooManyWaits):
		apiError(w, http.StatusTooManyRequests, errTooManyWaits.Error())
	case errors.Is(err, db.ErrUnknownAfter):
		apiError(w, http.StatusBadRequest, "after must be a report_id from this test address")
	default:
		a.log.Error("wait", "err", err)
		apiError(w, http.StatusInternalServerError, "lookup failed")
	}
}

var (
	errNotReceived  = errors.New("not received")
	errExpired      = errors.New("the test address has expired")
	errTooManyWaits = fmt.Errorf("too many waits are open for this account (at most %d at once); finish one before starting another", maxWaitsPerUser)
	errBusy         = errors.New("SendScore has too many waits open right now; try again in a minute")
)

func expiredMessage(addr db.Address) string {
	return "the test address expired at " + addr.ExpiresAt.Format(time.RFC3339) + " and no matching message arrived before then; create a new test address"
}

// wait polls for a message at the address, newer than the after report when
// one is given, for up to timeout (capped at MaxWait). It returns
// errNotReceived when the timeout passes, the request ends, or StopWaits is
// called, and errExpired at once when the address no longer accepts mail
// and has no such message. Each user may hold maxWaitsPerUser waits at once,
// and the app maxWaits.
func (a *App) wait(ctx context.Context, userID string, addr db.Address, after string, timeout time.Duration) (*db.Message, error) {
	release, err := a.holdWait(userID)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, min(timeout, a.cfg.MaxWait))
	defer cancel()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		m, err := a.store.LatestForToken(ctx, addr.Token, after)
		if err == nil || errors.Is(err, db.ErrUnknownAfter) {
			return m, err
		}
		if !errors.Is(err, db.ErrNotFound) && ctx.Err() == nil {
			return nil, err
		}
		// A message accepted just before expiry is still being checked for
		// up to a minute, so give up only after that.
		if a.store.Now().After(addr.ExpiresAt.Add(time.Minute)) {
			return nil, errExpired
		}
		select {
		case <-ctx.Done():
			return nil, errNotReceived
		case <-a.quit:
			return nil, errNotReceived
		case <-tick.C:
		}
	}
}

// holdWait takes a wait slot for userID, or returns errTooManyWaits or
// errBusy.
func (a *App) holdWait(userID string) (release func(), err error) {
	a.waitMu.Lock()
	defer a.waitMu.Unlock()
	switch {
	case a.waits[""] >= maxWaits:
		return nil, errBusy
	case a.waits[userID] >= maxWaitsPerUser:
		return nil, errTooManyWaits
	}
	a.waits[""]++
	a.waits[userID]++
	return func() {
		a.waitMu.Lock()
		defer a.waitMu.Unlock()
		for _, k := range []string{"", userID} {
			if a.waits[k]--; a.waits[k] <= 0 {
				delete(a.waits, k)
			}
		}
	}, nil
}

// apiReport returns a report from one of the token owner's test addresses.
func (a *App) apiReport(w http.ResponseWriter, r *http.Request) {
	m, err := a.store.MessageForUser(r.Context(), r.PathValue("id"), userFrom(r.Context()).ID)
	if err != nil {
		apiError(w, http.StatusNotFound, "no such report, or it has expired")
		return
	}
	writeJSON(w, http.StatusOK, m.Verdict)
}

// reportJSON is the verdict behind the report page, viewable by its link
// like the page itself.
func (a *App) reportJSON(w http.ResponseWriter, r *http.Request) {
	m, err := a.store.MessageByID(r.Context(), r.PathValue("id"))
	if err != nil {
		apiError(w, http.StatusNotFound, "no such report, or it has expired")
		return
	}
	writeJSON(w, http.StatusOK, m.Verdict)
}
