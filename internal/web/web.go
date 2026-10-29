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
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
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
	// MaxWait bounds the long poll behind wait_for_message.
	MaxWait time.Duration
	// Resolver overrides DNS for uploads (tests).
	Resolver engine.Resolver
	// BehindProxy is set when a reverse proxy on the same machine forwards
	// public requests, so loopback connections carry a public Host header.
	BehindProxy bool
}

// App is the web application.
type App struct {
	cfg   Config
	store *db.Store
	log   *slog.Logger
	tmpl  map[string]*template.Template
}

// New builds the app.
func New(cfg Config, store *db.Store, log *slog.Logger) (*App, error) {
	if cfg.MaxWait == 0 {
		cfg.MaxWait = 60 * time.Second
	}
	a := &App{cfg: cfg, store: store, log: log, tmpl: map[string]*template.Template{}}
	funcs := template.FuncMap{
		"lower":  strings.ToLower,
		"status": func(s verdict.Status) string { return string(s) },
		"kb":     func(n int) string { return strconv.Itoa((n+1023)/1024) + " KB" },
		"when":   func(t time.Time) string { return t.UTC().Format("2 Jan 2006, 15:04 UTC") },
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
	for _, page := range []string{"home", "address", "report", "upload", "error"} {
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

	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("POST /test", a.createAddressPage)
	mux.HandleFunc("GET /t/{token}", a.addressPage)
	mux.HandleFunc("GET /upload", a.uploadForm)
	mux.HandleFunc("POST /upload", a.upload)
	mux.HandleFunc("GET /r/{id}", a.reportPage)
	mux.HandleFunc("GET /r/{id}/raw", a.rawMessage)

	mux.HandleFunc("POST /api/v1/test-addresses", a.apiCreateAddress)
	mux.HandleFunc("GET /api/v1/test-addresses/{token}/wait", a.apiWait)
	mux.HandleFunc("GET /api/v1/reports/{id}", a.apiReport)
	mux.Handle("/api/mcp", a.mcpHandler())
	return secure(mux)
}

// secure sets the headers every response carries. The CSP allows no inline
// script or style, like Preflight.
func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

func (a *App) render(w http.ResponseWriter, status int, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["MailDomain"] = a.cfg.MailDomain
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := a.tmpl[page].Execute(w, data); err != nil {
		a.log.Error("render", "page", page, "err", err)
	}
}

func (a *App) fail(w http.ResponseWriter, status int, msg string) {
	a.render(w, status, "error", map[string]any{"Title": http.StatusText(status), "Message": msg})
}

func (a *App) address(token string) string {
	return "t-" + token + "@" + a.cfg.MailDomain
}

func (a *App) home(w http.ResponseWriter, r *http.Request) {
	a.render(w, http.StatusOK, "home", map[string]any{"Title": "Check a newsletter"})
}

func (a *App) createAddressPage(w http.ResponseWriter, r *http.Request) {
	addr, err := a.store.CreateAddress(r.Context(), a.cfg.AddressTTL)
	if err != nil {
		a.log.Error("create address", "err", err)
		a.fail(w, http.StatusInternalServerError, "Could not create a test address.")
		return
	}
	http.Redirect(w, r, "/t/"+addr.Token, http.StatusSeeOther)
}

func (a *App) addressPage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	addr, err := a.store.AddressByToken(r.Context(), token)
	if err != nil {
		a.fail(w, http.StatusNotFound, "This test address does not exist, or it has expired.")
		return
	}
	m, err := a.store.LatestForToken(r.Context(), token)
	if err == nil {
		http.Redirect(w, r, "/r/"+m.ID, http.StatusSeeOther)
		return
	}
	a.render(w, http.StatusOK, "address", map[string]any{
		"Title": "Waiting for your email", "Address": a.address(addr.Token), "Expires": addr.ExpiresAt,
		"Refresh": true,
	})
}

func (a *App) uploadForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, http.StatusOK, "upload", map[string]any{"Title": "Check a saved email"})
}

func (a *App) upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 26<<20)
	file, _, err := r.FormFile("message")
	if err != nil {
		a.fail(w, http.StatusBadRequest, "Choose an .eml file to check.")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 25<<20))
	if err != nil {
		a.fail(w, http.StatusBadRequest, "Could not read the file.")
		return
	}
	env := engine.Envelope{MailFrom: strings.TrimSpace(r.FormValue("mail_from"))}
	if ip := strings.TrimSpace(r.FormValue("ip")); ip != "" {
		env.RemoteIP = net.ParseIP(ip)
		if env.RemoteIP == nil {
			a.fail(w, http.StatusBadRequest, "The sending IP is not an IP address.")
			return
		}
	}
	now := a.store.Now().UTC()
	v, err := engine.Analyze(r.Context(), raw, engine.Options{Envelope: env, Resolver: a.cfg.Resolver, ReceivedAt: now})
	if err != nil {
		a.fail(w, http.StatusBadRequest, "That file is not an email message: "+err.Error())
		return
	}
	m := &db.Message{Source: "upload", ReceivedAt: now, ExpiresAt: now.Add(a.cfg.ReportTTL),
		RemoteIP: r.FormValue("ip"), MailFrom: env.MailFrom, Raw: raw, Verdict: v}
	if err := a.store.SaveMessage(r.Context(), m); err != nil {
		a.log.Error("save upload", "err", err)
		a.fail(w, http.StatusInternalServerError, "Could not save the report.")
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
		a.fail(w, http.StatusNotFound, "This report does not exist, or it has expired.")
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
	a.render(w, http.StatusOK, "report", map[string]any{
		"Title": m.Verdict.Message.Subject, "M": m, "V": m.Verdict, "Sections": secs,
	})
}

func (a *App) rawMessage(w http.ResponseWriter, r *http.Request) {
	m, err := a.store.MessageByID(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="`+m.ID+`.eml"`)
	w.Write(m.Raw)
}

// API

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (a *App) apiCreateAddress(w http.ResponseWriter, r *http.Request) {
	addr, err := a.store.CreateAddress(r.Context(), a.cfg.AddressTTL)
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
// passes. It answers 200 either way; status says which.
func (a *App) apiWait(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if _, err := a.store.AddressByToken(r.Context(), token); err != nil {
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
	timeout = min(timeout, a.cfg.MaxWait)

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		m, err := a.store.LatestForToken(ctx, token)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"status": "received", "report_id": m.ID,
				"report_url": a.cfg.BaseURL + "/r/" + m.ID,
				"verdict":    m.Verdict,
			})
			return
		}
		if !errors.Is(err, db.ErrNotFound) && ctx.Err() == nil {
			a.log.Error("wait", "err", err)
			apiError(w, http.StatusInternalServerError, "lookup failed")
			return
		}
		select {
		case <-ctx.Done():
			writeJSON(w, http.StatusOK, map[string]any{"status": "not_received"})
			return
		case <-tick.C:
		}
	}
}

func (a *App) apiReport(w http.ResponseWriter, r *http.Request) {
	m, err := a.store.MessageByID(r.Context(), r.PathValue("id"))
	if err != nil {
		apiError(w, http.StatusNotFound, "no such report, or it has expired")
		return
	}
	writeJSON(w, http.StatusOK, m.Verdict)
}
