package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sendscore/sendscore-app/internal/db"
)

// OAuth 2.1 for the MCP connector, as the MCP authorization spec asks: a
// client finds this server through the 401 on /api/mcp and the two metadata
// documents, registers itself, sends the user here to sign in and allow
// access, and swaps the code (with its PKCE verifier) for tokens. Clients
// are public, with no secret.

// Registration limits.
const (
	maxClientName      = 120
	maxRedirectURIs    = 8
	maxRedirectURI     = 400
	registrationsPerIP = 20 // an hour
)

func (a *App) mcpResource() string { return a.cfg.BaseURL + "/api/mcp" }

func (a *App) resourceMetadataURL() string {
	return a.cfg.BaseURL + "/.well-known/oauth-protected-resource/api/mcp"
}

// cors lets clients that run in a browser (such as the MCP Inspector) read
// the metadata, register, swap codes, and call the connector. None of these
// use cookies, so any origin is safe.
func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Access-Control-Allow-Origin", "*")
		hd.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		hd.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID")
		hd.Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
		hd.Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func publicJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, v)
}

// protectedResource is RFC 9728 metadata for /api/mcp.
func (a *App) protectedResource(w http.ResponseWriter, r *http.Request) {
	publicJSON(w, map[string]any{
		"resource":                 a.mcpResource(),
		"authorization_servers":    []string{a.cfg.BaseURL},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "SendScore",
	})
}

// authorizationServer is RFC 8414 metadata.
func (a *App) authorizationServer(w http.ResponseWriter, r *http.Request) {
	b := a.cfg.BaseURL
	publicJSON(w, map[string]any{
		"issuer":                                         b,
		"authorization_endpoint":                         b + "/oauth/authorize",
		"token_endpoint":                                 b + "/oauth/token",
		"registration_endpoint":                          b + "/oauth/register",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"authorization_response_iss_parameter_supported": true,
		"service_documentation":                          "https://sendscore.ai",
	})
}

// serverCard describes the connector to clients before they connect.
func (a *App) serverCard(w http.ResponseWriter, r *http.Request) {
	publicJSON(w, map[string]any{
		"serverInfo": map[string]any{"name": "sendscore", "title": "SendScore", "homepage": "https://sendscore.ai"},
		"transport":  map[string]any{"type": "streamable-http", "url": a.mcpResource()},
		"authentication": map[string]any{
			"required": true, "schemes": []string{"oauth2", "bearer"},
		},
	})
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// Schemes that are not an app's own, so never a redirect URI.
var notAnApp = map[string]bool{"javascript": true, "data": true, "blob": true, "file": true, "about": true, "vbscript": true,
	"mailto": true, "tel": true, "sms": true, "ftp": true, "ws": true, "wss": true, "http": true, "https": true}

var schemeRE = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)

// validRedirect reports whether a code may be sent to uri: https, http on
// loopback (RFC 8252 section 7.3), or a native app's private-use scheme such
// as cursor:// or vscode:// (section 7.1). Fragments, wildcards, and
// characters that could break the consent page's CSP are refused.
func validRedirect(uri string) bool {
	if uri == "" || len(uri) > maxRedirectURI || strings.ContainsAny(uri, "#*,;'\"\\ ") {
		return false
	}
	for _, r := range uri {
		if r < 0x21 || r >= 0x7f {
			return false
		}
	}
	u, err := url.Parse(uri)
	if err != nil || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		h := u.Hostname()
		return h == "127.0.0.1" || h == "localhost" || h == "::1"
	}
	return schemeRE.MatchString(u.Scheme) && !notAnApp[u.Scheme] && len(uri) > len(u.Scheme)+1
}

// formActionSource is the CSP source that lets the consent form's redirect
// reach uri, which validRedirect has passed.
func formActionSource(uri string) string {
	u, _ := url.Parse(uri)
	if u.Scheme == "https" || u.Scheme == "http" {
		return u.Scheme + "://" + u.Host
	}
	return u.Scheme + ":"
}

// cleanClientName keeps a registered name readable on the consent page:
// no control or invisible characters, one space between words, at most 120
// characters. A name claiming to be SendScore itself is dropped, since
// anyone can register; the page then says "An app" and shows where it
// sends you.
func cleanClientName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > maxClientName {
		s = string([]rune(s)[:maxClientName])
	}
	folded := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r
		}
		return -1
	}, strings.ToLower(s))
	if strings.Contains(folded, "sendscore") {
		return ""
	}
	return s
}

// register is dynamic client registration (RFC 7591). Every client is public:
// one that asks for a secret is registered without one, and the answer says
// so. Unusable redirect URIs are dropped, and only a list with none left is
// refused.
func (a *App) register(w http.ResponseWriter, r *http.Request) {
	if _, err := a.store.Take(r.Context(), "oauth-register:ip:"+a.clientIP(r), db.Hour(a.store.Now()), registrationsPerIP, 2*time.Hour); err != nil {
		if !errors.Is(err, db.ErrLimit) {
			a.log.Error("register limit", "err", err)
		}
		oauthError(w, http.StatusTooManyRequests, "too_many_requests", "Too many registrations from this network. Try again in an hour.")
		return
	}
	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "The body must be a JSON object of client metadata, at most 16 KB.")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > maxRedirectURIs {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "Send between 1 and 8 redirect_uris.")
		return
	}
	var keep []string
	for _, u := range req.RedirectURIs {
		if validRedirect(u) && !contains(keep, u) {
			keep = append(keep, u)
		}
	}
	if len(keep) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri",
			"Each redirect_uri must be https, http on 127.0.0.1 or localhost, or a native app's own scheme, with no fragment or wildcard.")
		return
	}
	c, err := a.store.CreateOAuthClient(r.Context(), cleanClientName(req.ClientName), keep)
	if err != nil {
		a.log.Error("register client", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "Could not register the client.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        c.CreatedAt.Unix(),
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// authzRequest is a checked authorization request.
type authzRequest struct {
	Client      db.OAuthClient
	RedirectURI string
	State       string
	Challenge   string
	Resource    string
	Scope       string
}

var challengeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// readAuthorize checks an authorization request. fatal is set when the
// client or redirect URI cannot be trusted, so the error is shown here and
// never sent to the redirect URI; otherwise errCode is an OAuth error to
// send back to it.
func (a *App) readAuthorize(ctx context.Context, v url.Values) (req authzRequest, fatal, errCode, errDesc string) {
	c, err := a.store.OAuthClientByID(ctx, v.Get("client_id"))
	if err != nil {
		return req, "This app is not registered with SendScore, so it cannot connect. Remove the connector and add it again.", "", ""
	}
	req.Client = c
	req.RedirectURI = v.Get("redirect_uri")
	if req.RedirectURI == "" && len(c.RedirectURIs) == 1 {
		req.RedirectURI = c.RedirectURIs[0]
	}
	if !contains(c.RedirectURIs, req.RedirectURI) {
		return req, "The app asked to send you back to an address it did not register, so SendScore stopped here.", "", ""
	}
	req.State, req.Resource, req.Scope = v.Get("state"), v.Get("resource"), v.Get("scope")
	req.Challenge = v.Get("code_challenge")
	switch {
	case v.Get("response_type") != "code":
		return req, "", "unsupported_response_type", "response_type must be code"
	case v.Get("code_challenge_method") != "S256" || !challengeRE.MatchString(req.Challenge):
		return req, "", "invalid_request", "PKCE with code_challenge_method S256 is required"
	case req.Resource != "" && req.Resource != a.mcpResource():
		return req, "", "invalid_target", "resource must be " + a.mcpResource()
	}
	return req, "", "", ""
}

// redirectTo sends the browser back to the client with params added to its
// redirect URI, and the issuer (RFC 9207).
func (a *App) redirectTo(w http.ResponseWriter, r *http.Request, uri string, params map[string]string) {
	u, _ := url.Parse(uri)
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	q.Set("iss", a.cfg.BaseURL)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (a *App) authorize(w http.ResponseWriter, r *http.Request) {
	if userFrom(r.Context()) == nil {
		http.Redirect(w, r, "/signin?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	req, fatal, code, desc := a.readAuthorize(r.Context(), r.URL.Query())
	if fatal != "" {
		a.fail(w, r, http.StatusBadRequest, fatal)
		return
	}
	if code != "" {
		a.redirectTo(w, r, req.RedirectURI, map[string]string{"error": code, "error_description": desc, "state": req.State})
		return
	}
	name := req.Client.Name
	if name == "" {
		name = "An app"
	}
	dest := formActionSource(req.RedirectURI)
	// The form posts here and is answered with a redirect to the client,
	// which CSP's form-action also governs, so it names that one place.
	w.Header().Set("Content-Security-Policy", strings.Replace(csp, "form-action 'self'", "form-action 'self' "+dest, 1))
	w.Header().Set("Cache-Control", "no-store")
	a.render(w, r, http.StatusOK, "consent", map[string]any{
		"Title": "Connect " + name, "Name": name, "Destination": strings.TrimSuffix(dest, ":"), "Req": req,
	})
}

// approve answers the consent form.
func (a *App) approve(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if u == nil {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	req, fatal, code, desc := a.readAuthorize(r.Context(), r.PostForm)
	if fatal != "" {
		a.fail(w, r, http.StatusBadRequest, fatal)
		return
	}
	if code != "" {
		a.redirectTo(w, r, req.RedirectURI, map[string]string{"error": code, "error_description": desc, "state": req.State})
		return
	}
	if r.PostForm.Get("decision") != "allow" {
		a.redirectTo(w, r, req.RedirectURI, map[string]string{"error": "access_denied", "error_description": "the user did not allow access", "state": req.State})
		return
	}
	c, err := a.store.CreateOAuthCode(r.Context(), db.OAuthCode{ClientID: req.Client.ID, UserID: u.ID, RedirectURI: req.RedirectURI, CodeChallenge: req.Challenge})
	if err != nil {
		a.log.Error("create oauth code", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not finish connecting the app. Try again.")
		return
	}
	a.redirectTo(w, r, req.RedirectURI, map[string]string{"code": c, "state": req.State})
}

var verifierRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// token is the token endpoint: authorization_code with PKCE, and
// refresh_token with rotation.
func (a *App) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "The body must be a form of at most 16 KB.")
		return
	}
	f := r.PostForm
	clientID := f.Get("client_id")
	if _, err := a.store.OAuthClientByID(r.Context(), clientID); err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client_id is not a registered client")
		return
	}
	if res := f.Get("resource"); res != "" && res != a.mcpResource() {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource must be "+a.mcpResource())
		return
	}
	var t db.OAuthTokens
	var err error
	switch f.Get("grant_type") {
	case "authorization_code":
		verifier, redirect := f.Get("code_verifier"), f.Get("redirect_uri")
		if !verifierRE.MatchString(verifier) {
			oauthError(w, http.StatusBadRequest, "invalid_request", "code_verifier is required (43 to 128 characters)")
			return
		}
		t, err = a.store.ExchangeOAuthCode(r.Context(), f.Get("code"), func(c db.OAuthCode) error {
			sum := sha256.Sum256([]byte(verifier))
			want := base64.RawURLEncoding.EncodeToString(sum[:])
			if c.ClientID != clientID || c.RedirectURI != redirect || subtle.ConstantTimeCompare([]byte(want), []byte(c.CodeChallenge)) != 1 {
				return db.ErrInvalidGrant
			}
			return nil
		})
	case "refresh_token":
		t, err = a.store.RefreshOAuth(r.Context(), f.Get("refresh_token"), clientID)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
		return
	}
	if errors.Is(err, db.ErrInvalidGrant) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the code or refresh token is invalid, expired, already used, or was issued to another client or redirect_uri")
		return
	}
	if err != nil {
		a.log.Error("oauth token", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "Could not issue a token.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  t.Access,
		"token_type":    "Bearer",
		"expires_in":    int(t.ExpiresIn.Seconds()),
		"refresh_token": t.Refresh,
	})
}

// disconnect revokes an app's tokens from the account page.
func (a *App) disconnect(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if u == nil {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	if err := a.store.DisconnectApp(r.Context(), u.ID, r.PathValue("id")); err != nil {
		a.log.Error("disconnect app", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not disconnect the app.")
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
