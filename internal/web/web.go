// Package web serves the app: test addresses, reports, uploads, and the JSON
// API the MCP tools call.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
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
	BaseURL    string
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
	// FreeDailyTests and AnonDailyTests are the test addresses (and
	// uploads) per UTC day for a free account and for an anonymous IP.
	FreeDailyTests int
	AnonDailyTests int
}

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
	a := &App{cfg: cfg, store: store, log: log, tmpl: map[string]*template.Template{}, quit: make(chan struct{})}
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
	}
	for _, page := range []string{"home", "address", "report", "upload", "error", "signin", "account", "consent"} {
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
	mux.HandleFunc("POST /test", a.form(formLimit, a.createAddressPage))
	mux.HandleFunc("GET /t/{token}", a.addressPage)
	mux.HandleFunc("GET /upload", a.uploadForm)
	// The body may be a little larger than the file, for the form fields.
	mux.HandleFunc("POST /upload", a.form(MaxUploadBytes+1<<20, a.upload))
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
	mux.Handle("/api/mcp", cors(a.mcpAuth(a.mcpHandler())))
	return secure(a.session(mux))
}

// csp allows no inline script or style, like Preflight.
const csp = "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// secure sets the headers every response carries.
func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", csp)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "same-origin")
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
	a.render(w, r, http.StatusOK, "home", map[string]any{"Title": "Check a newsletter"})
}

func (a *App) createAddressPage(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if limit, err := a.takeTest(r.Context(), u, a.clientIP(r)); err != nil {
		if !errors.Is(err, db.ErrLimit) {
			a.log.Error("count test", "err", err)
		}
		a.limitPage(w, r, limit)
		return
	}
	uid := ""
	if u != nil {
		uid = u.ID
	}
	addr, err := a.store.CreateAddressFor(r.Context(), a.cfg.AddressTTL, uid)
	if err != nil {
		a.log.Error("create address", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not create a test address.")
		return
	}
	http.Redirect(w, r, "/t/"+addr.Token, http.StatusSeeOther)
}

func (a *App) addressPage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	addr, err := a.store.AddressByToken(r.Context(), token)
	if err != nil {
		a.fail(w, r, http.StatusNotFound, "This test address does not exist, or it has expired.")
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
	a.render(w, r, http.StatusOK, "address", map[string]any{
		"Title": "Waiting for your email", "Address": a.address(addr.Token), "Expires": addr.ExpiresAt,
		"Refresh": true,
	})
}

func (a *App) uploadForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, http.StatusOK, "upload", map[string]any{"Title": "Check a saved email"})
}

func (a *App) upload(w http.ResponseWriter, r *http.Request) {
	// a.form has parsed the body, within the size limit.
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
	if limit, err := a.takeTest(r.Context(), userFrom(r.Context()), a.clientIP(r)); err != nil {
		if !errors.Is(err, db.ErrLimit) {
			a.log.Error("count test", "err", err)
		}
		a.limitPage(w, r, limit)
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
	// Bounded well inside the server's write timeout.
	actx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	v, err := engine.Analyze(actx, raw, engine.Options{
		Envelope: env, Resolver: a.cfg.Resolver, CheckLinks: a.cfg.CheckLinks,
		Blocklists: a.cfg.Blocklists, ReceivedAt: now,
	})
	if err != nil {
		a.fail(w, r, http.StatusBadRequest, "That file is not an email message: "+err.Error())
		return
	}
	m := &db.Message{Source: "upload", ReceivedAt: now, ExpiresAt: now.Add(a.cfg.ReportTTL),
		RemoteIP: r.FormValue("ip"), MailFrom: env.MailFrom, Raw: raw, Verdict: v}
	if err := a.store.SaveMessage(r.Context(), m); err != nil {
		a.log.Error("save upload", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not save the report.")
		return
	}
	http.Redirect(w, r, "/r/"+m.ID, http.StatusSeeOther)
}

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
	a.render(w, r, http.StatusOK, "report", map[string]any{
		"Title": m.Verdict.Message.Subject, "M": m, "V": m.Verdict, "Sections": secs,
	})
}

func (a *App) rawMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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
	// Another account's address is answered as if it did not exist.
	if addr, err := a.store.AddressByToken(r.Context(), token); err != nil || addr.UserID != userFrom(r.Context()).ID {
		apiError(w, http.StatusNotFound, "no such test address, or it has expired")
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
	m, err := a.wait(r.Context(), token, r.URL.Query().Get("after"), timeout)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "received", "report_id": m.ID,
			"report_url": a.cfg.BaseURL + "/r/" + m.ID,
			"verdict":    m.Verdict,
		})
	case errors.Is(err, errNotReceived):
		writeJSON(w, http.StatusOK, map[string]any{"status": "not_received"})
	case errors.Is(err, db.ErrUnknownAfter):
		apiError(w, http.StatusBadRequest, "after must be a report_id from this test address")
	default:
		a.log.Error("wait", "err", err)
		apiError(w, http.StatusInternalServerError, "lookup failed")
	}
}

var errNotReceived = errors.New("not received")

// wait polls for a message at the address, newer than the after report when
// one is given, for up to timeout (capped at MaxWait). It returns
// errNotReceived when the timeout passes, the request ends, or StopWaits is
// called.
func (a *App) wait(ctx context.Context, token, after string, timeout time.Duration) (*db.Message, error) {
	ctx, cancel := context.WithTimeout(ctx, min(timeout, a.cfg.MaxWait))
	defer cancel()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		m, err := a.store.LatestForToken(ctx, token, after)
		if err == nil || errors.Is(err, db.ErrUnknownAfter) {
			return m, err
		}
		if !errors.Is(err, db.ErrNotFound) && ctx.Err() == nil {
			return nil, err
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
