package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sendscore/sendscore-app/internal/db"
)

const (
	sessionCookie = "ss_session"
	csrfCookie    = "ss_csrf"
)

// Sign-in emails allowed per address and per IP in an hour.
const signinPerHour = 5

// maxAPITokens is how many API tokens one account may hold.
const maxAPITokens = 25

type ctxKey int

const (
	userKey ctxKey = iota
	csrfKey
)

// userFrom returns the signed-in user (web) or the token's owner (API), or
// nil.
func userFrom(ctx context.Context) *db.User {
	u, _ := ctx.Value(userKey).(*db.User)
	return u
}

func withUser(ctx context.Context, u *db.User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

// session loads the signed-in user from the session cookie and makes sure
// the browser has a CSRF cookie, for every page (not the API, the assets,
// or the OAuth endpoints a client calls directly).
func (a *App) session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/assets/") || strings.HasPrefix(p, "/.well-known/") ||
			p == "/oauth/token" || p == "/oauth/register" {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		if c, err := r.Cookie(sessionCookie); err == nil {
			u, err := a.store.UserBySession(ctx, c.Value)
			switch {
			case err == nil:
				ctx = withUser(ctx, &u)
			case !errors.Is(err, db.ErrNotFound):
				a.log.Error("session lookup", "err", err)
			}
		}
		token := ""
		if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 32 {
			token = c.Value
		} else {
			token = db.NewToken(32)
			a.setCookie(w, csrfCookie, token, db.SessionTTL)
		}
		ctx = context.WithValue(ctx, csrfKey, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *App) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	c := &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: a.cfg.SecureCookies, SameSite: http.SameSiteLaxMode,
	}
	if ttl < 0 {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

// form wraps every handler of a state-changing form. It parses the body
// (at most limit bytes), then requires a request from this site (by Origin,
// or Referer when there is no Origin) and the CSRF token from the cookie in
// the form's csrf field.
func (a *App) form(limit int64, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		if err := r.ParseMultipartForm(32 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
			if tooLarge := (*http.MaxBytesError)(nil); errors.As(err, &tooLarge) {
				a.fail(w, r, http.StatusRequestEntityTooLarge, tooLargeMessage)
				return
			}
			a.fail(w, r, http.StatusBadRequest, "The form could not be read.")
			return
		}
		want, _ := r.Context().Value(csrfKey).(string)
		sent := r.PostFormValue("csrf")
		if !a.sameOrigin(r) || want == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(want)) != 1 {
			a.fail(w, r, http.StatusForbidden, "This form expired or came from another site. Go back, reload the page, and try again.")
			return
		}
		h(w, r)
	}
}

// sameOrigin reports whether a form post came from this site. A request
// with neither header (an old browser, or a privacy setting) relies on the
// CSRF token alone.
func (a *App) sameOrigin(r *http.Request) bool {
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return true
	}
	u, err := url.Parse(src)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Host == r.Host {
		return true
	}
	b, err := url.Parse(a.cfg.BaseURL)
	return err == nil && u.Scheme == b.Scheme && u.Host == b.Host
}

// clientIP is the address limits are counted against. Behind a proxy
// (SENDSCORE_TRUST_PROXY=1) it is the last X-Forwarded-For entry, the one
// the proxy added; earlier entries come from the client and can be forged.
// An IPv6 address counts as its /64, since one machine usually has many.
func (a *App) clientIP(r *http.Request) string {
	raw := r.RemoteAddr
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	if a.cfg.TrustProxy {
		if vals := r.Header.Values("X-Forwarded-For"); len(vals) > 0 {
			parts := strings.Split(vals[len(vals)-1], ",")
			raw = strings.TrimSpace(parts[len(parts)-1])
		}
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return raw
	}
	if ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return ip.String()
}

// takeTest counts one test address or upload against the user's daily
// allowance, or the IP's when nobody is signed in. It returns the limit and
// db.ErrLimit when the allowance is used up.
func (a *App) takeTest(ctx context.Context, u *db.User, ip string) (int, error) {
	name, limit := "tests:ip:"+ip, a.cfg.AnonDailyTests
	if u != nil {
		name, limit = "tests:user:"+u.ID, a.dailyLimit(u)
	}
	_, err := a.store.Take(ctx, name, db.Day(a.store.Now()), limit, 48*time.Hour)
	return limit, err
}

// dailyLimit is the user's test addresses per UTC day. Every account is on
// the free plan until billing adds others.
func (a *App) dailyLimit(u *db.User) int {
	switch u.Plan {
	default:
		return a.cfg.FreeDailyTests
	}
}

// limitPage explains a used-up daily allowance.
func (a *App) limitPage(w http.ResponseWriter, r *http.Request, limit int) {
	msg := fmt.Sprintf("You have used all %d of today's test addresses. The allowance starts again at midnight UTC.", limit)
	if userFrom(r.Context()) == nil {
		msg = fmt.Sprintf("This network has used all %d of today's free tests. Sign in for %d a day, or come back after midnight UTC.", limit, a.cfg.FreeDailyTests)
	}
	a.render(w, r, http.StatusTooManyRequests, "error", map[string]any{"Title": "Daily limit reached", "Message": msg})
}

func limitError(limit int) string {
	return fmt.Sprintf("the daily limit of %d test addresses is used up; it resets at midnight UTC", limit)
}

// Sign-in by emailed link

// safeNext keeps only a path on this site, so the page to open after
// signing in cannot send anyone elsewhere.
func safeNext(p string) string {
	if len(p) > 2048 || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return ""
	}
	for _, r := range p {
		if r < 0x21 || r == 0x7f {
			return ""
		}
	}
	return p
}

func (a *App) signinForm(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if userFrom(r.Context()) != nil {
		if next == "" {
			next = "/account"
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	a.render(w, r, http.StatusOK, "signin", map[string]any{"Title": "Sign in", "Next": next})
}

func validEmail(s string) bool {
	if len(s) > 254 || strings.ContainsAny(s, " <>\r\n") {
		return false
	}
	addr, err := mail.ParseAddress(s)
	return err == nil && addr.Address == s && strings.Contains(s[strings.LastIndex(s, "@"):], ".")
}

// signin emails a sign-in link. The page says the same thing whether or
// not the address has an account, so it cannot be used to find accounts.
func (a *App) signin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := db.NormalizeEmail(r.PostFormValue("email"))
	next := safeNext(r.PostFormValue("next"))
	if !validEmail(email) {
		a.render(w, r, http.StatusBadRequest, "signin", map[string]any{"Title": "Sign in", "Email": email, "Next": next, "Error": "Enter a full email address, such as you@example.com."})
		return
	}
	hour := db.Hour(a.store.Now())
	for _, name := range []string{"signin:ip:" + a.clientIP(r), "signin:email:" + email} {
		if _, err := a.store.Take(ctx, name, hour, signinPerHour, 2*time.Hour); err != nil {
			if !errors.Is(err, db.ErrLimit) {
				a.log.Error("signin limit", "err", err)
			}
			a.render(w, r, http.StatusTooManyRequests, "error", map[string]any{"Title": "Too many sign-in emails",
				"Message": "Too many sign-in links were requested in the last hour. Use the newest link you received, or try again in an hour."})
			return
		}
	}
	token, err := a.store.CreateLoginTokenNext(ctx, email, next)
	if err != nil {
		a.log.Error("create login token", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not start signing in. Try again in a minute.")
		return
	}
	link := a.cfg.BaseURL + "/signin/verify?t=" + token
	body := "Use this link to sign in to SendScore. It works once and expires in 15 minutes.\n\n" + link +
		"\n\nIf you did not ask to sign in, ignore this email. Nobody can sign in without the link.\n"
	if err := a.cfg.Mailer.Send(ctx, email, "Sign in to SendScore", body); err != nil {
		a.log.Error("send sign-in email", "err", err)
		a.fail(w, r, http.StatusBadGateway, "The sign-in email could not be sent. Try again in a few minutes.")
		return
	}
	a.render(w, r, http.StatusOK, "signin", map[string]any{"Title": "Check your email", "Sent": true, "Email": email})
}

// verifyForm shows a button that signs in. Following the link only shows
// the page, so a mail scanner that opens links cannot use it up.
func (a *App) verifyForm(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("t")
	if t == "" {
		a.fail(w, r, http.StatusBadRequest, "This sign-in link is incomplete. Copy the whole link from the email, or request a new one.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a.render(w, r, http.StatusOK, "signin", map[string]any{"Title": "Sign in", "Verify": t})
}

func (a *App) verify(w http.ResponseWriter, r *http.Request) {
	u, session, err := a.store.ConsumeLoginToken(r.Context(), r.PostFormValue("t"))
	if errors.Is(err, db.ErrNotFound) {
		a.render(w, r, http.StatusBadRequest, "signin", map[string]any{"Title": "Sign in",
			"Error": "That sign-in link has expired or was already used. Enter your email to get a new one."})
		return
	}
	if err != nil {
		a.log.Error("consume login token", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not sign you in. Try the link again in a minute.")
		return
	}
	a.setCookie(w, sessionCookie, session, db.SessionTTL)
	next := safeNext(u.Next)
	if next == "" {
		next = "/account"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (a *App) signout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := a.store.DeleteSession(r.Context(), c.Value); err != nil {
			a.log.Error("delete session", "err", err)
		}
	}
	a.setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Account and API tokens

func (a *App) account(w http.ResponseWriter, r *http.Request) {
	a.renderAccount(w, r, http.StatusOK, nil)
}

func (a *App) renderAccount(w http.ResponseWriter, r *http.Request, status int, extra map[string]any) {
	u := userFrom(r.Context())
	if u == nil {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	ctx := r.Context()
	tokens, err := a.store.APITokens(ctx, u.ID)
	if err != nil {
		a.log.Error("list tokens", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not load your account.")
		return
	}
	used, err := a.store.Count(ctx, "tests:user:"+u.ID, db.Day(a.store.Now()))
	if err != nil {
		a.log.Error("usage", "err", err)
	}
	apps, err := a.store.ConnectedApps(ctx, u.ID)
	if err != nil {
		a.log.Error("connected apps", "err", err)
	}
	data := map[string]any{"Title": "Account", "Tokens": tokens, "Apps": apps, "Used": used, "Limit": a.dailyLimit(u), "BaseURL": a.cfg.BaseURL}
	for k, v := range extra {
		data[k] = v
	}
	a.render(w, r, status, "account", data)
}

// createToken makes an API token and shows it on this response only. It is
// not stored, so a reload cannot show it again.
func (a *App) createToken(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if u == nil {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	switch {
	case name == "":
		a.renderAccount(w, r, http.StatusBadRequest, map[string]any{"Error": "Give the token a name, such as the agent or machine that will use it."})
		return
	case utf8.RuneCountInString(name) > 60:
		a.renderAccount(w, r, http.StatusBadRequest, map[string]any{"Error": "Keep the name to 60 characters or fewer.", "Name": name})
		return
	}
	existing, err := a.store.APITokens(r.Context(), u.ID)
	if err == nil && len(existing) >= maxAPITokens {
		a.renderAccount(w, r, http.StatusBadRequest, map[string]any{"Error": fmt.Sprintf("An account can hold %d tokens. Revoke one you no longer use first.", maxAPITokens)})
		return
	}
	t, token, err := a.store.CreateAPIToken(r.Context(), u.ID, name)
	if err != nil {
		a.log.Error("create token", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not create the token.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a.renderAccount(w, r, http.StatusCreated, map[string]any{"NewToken": token, "NewTokenName": t.Name})
}

func (a *App) revokeToken(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if u == nil {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	if err := a.store.RevokeAPIToken(r.Context(), u.ID, r.PathValue("id")); err != nil && !errors.Is(err, db.ErrNotFound) {
		a.log.Error("revoke token", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not revoke the token.")
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// API authentication

const unauthorized = `missing or invalid API token. Send "Authorization: Bearer <token>" with a token from `

// bearer returns the owner of the request's API token, or of an OAuth
// access token when oauth is set (the MCP connector). ok is false for a
// missing or unknown token.
func (a *App) bearer(r *http.Request, oauth bool) (u db.User, ok bool, err error) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return u, false, nil
	}
	token = strings.TrimSpace(token)
	if oauth && strings.HasPrefix(token, db.OAuthAccessPrefix) {
		u, err = a.store.UserByOAuthToken(r.Context(), token)
	} else {
		u, err = a.store.UserByAPIToken(r.Context(), token)
	}
	if errors.Is(err, db.ErrNotFound) {
		return u, false, nil
	}
	return u, err == nil, err
}

// api requires an API token on a JSON route.
func (a *App) api(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok, err := a.bearer(r, false)
		if err != nil {
			a.log.Error("api token lookup", "err", err)
			apiError(w, http.StatusInternalServerError, "token lookup failed")
			return
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sendscore"`)
			apiError(w, http.StatusUnauthorized, unauthorized+a.cfg.BaseURL+"/account.")
			return
		}
		h(w, r.WithContext(withUser(r.Context(), &u)))
	}
}

// mcpAuth requires an API token or an OAuth access token on the MCP
// connector. The 401 names the protected resource metadata (RFC 9728), which
// is how a client finds where to sign in.
func (a *App) mcpAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok, err := a.bearer(r, true)
		if err != nil {
			a.log.Error("mcp token lookup", "err", err)
			http.Error(w, "token lookup failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			challenge := `Bearer resource_metadata="` + a.resourceMetadataURL() + `"`
			if r.Header.Get("Authorization") != "" {
				challenge += `, error="invalid_token", error_description="The access token is missing, expired, or revoked."`
			}
			w.Header().Set("WWW-Authenticate", challenge)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r.WithContext(withUser(r.Context(), &u)))
	})
}
