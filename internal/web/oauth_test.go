package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore/mcpserver"
)

const testRedirect = "https://claude.ai/api/mcp/auth_callback"

func jsonBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("not JSON (%d): %s", w.Code, w.Body)
	}
	return m
}

func registerClient(h http.Handler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return serve(h, r)
}

func newClient(t *testing.T, h http.Handler, name string) string {
	t.Helper()
	w := registerClient(h, `{"client_name":"`+name+`","redirect_uris":["`+testRedirect+`"],"token_endpoint_auth_method":"client_secret_post"}`)
	if w.Code != 201 {
		t.Fatalf("register = %d %s", w.Code, w.Body)
	}
	return jsonBody(t, w)["client_id"].(string)
}

func pkce(seed string) (verifier, challenge string) {
	verifier = strings.Repeat(seed, 64)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeQuery(client, challenge string) url.Values {
	return url.Values{"response_type": {"code"}, "client_id": {client}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"st8"}, "resource": {"http://test/api/mcp"}}
}

// approveCode answers the consent form with Allow and returns the code.
func approveCode(t *testing.T, h http.Handler, session string, q url.Values) string {
	t.Helper()
	vals := url.Values{}
	for k, v := range q {
		vals[k] = v
	}
	vals.Set("decision", "allow")
	w := post(h, "/oauth/authorize", vals, session)
	loc, err := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusSeeOther || err != nil || !strings.HasPrefix(loc.String(), testRedirect+"?") {
		t.Fatalf("allow = %d %q", w.Code, w.Header().Get("Location"))
	}
	if loc.Query().Get("state") != "st8" || loc.Query().Get("iss") != "http://test" || loc.Query().Get("code") == "" {
		t.Fatalf("redirect query = %v", loc.Query())
	}
	return loc.Query().Get("code")
}

func tokenRequest(h http.Handler, vals url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return serve(h, r)
}

func exchange(h http.Handler, client, code, verifier string) *httptest.ResponseRecorder {
	return tokenRequest(h, url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "code": {code},
		"code_verifier": {verifier}, "redirect_uri": {testRedirect}})
}

func refresh(h http.Handler, client, token string) *httptest.ResponseRecorder {
	return tokenRequest(h, url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {token}})
}

// mcpStatus is the status /api/mcp answers a token with (401 when refused).
func mcpStatus(h http.Handler, token string) (int, string) {
	r := httptest.NewRequest("POST", "/api/mcp", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := serve(h, r)
	return w.Code, w.Header().Get("WWW-Authenticate")
}

// grant runs the whole flow for a new user and client and returns them with
// the first token pair.
func grant(t *testing.T, h http.Handler, store *db.Store) (client, session, access, refreshTok string) {
	t.Helper()
	client = newClient(t, h, "Claude")
	_, session, _ = newUser(t, store, "oauth@example.com")
	verifier, challenge := pkce("a")
	code := approveCode(t, h, session, authorizeQuery(client, challenge))
	w := exchange(h, client, code, verifier)
	if w.Code != 200 {
		t.Fatalf("exchange = %d %s", w.Code, w.Body)
	}
	m := jsonBody(t, w)
	return client, session, m["access_token"].(string), m["refresh_token"].(string)
}

func TestOAuthMetadata(t *testing.T) {
	_, _, h := newApp(t)
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/api/mcp"} {
		w := do(h, "GET", p, nil, "")
		m := jsonBody(t, w)
		if m["resource"] != "http://test/api/mcp" || m["authorization_servers"].([]any)[0] != "http://test" || w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s = %v", p, m)
		}
	}
	m := jsonBody(t, do(h, "GET", "/.well-known/oauth-authorization-server", nil, ""))
	want := map[string]any{
		"issuer": "http://test", "authorization_endpoint": "http://test/oauth/authorize", "token_endpoint": "http://test/oauth/token",
		"registration_endpoint": "http://test/oauth/register",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %v, want %v", k, m[k], v)
		}
	}
	for k, v := range map[string]string{"code_challenge_methods_supported": `"S256"`, "token_endpoint_auth_methods_supported": `"none"`,
		"grant_types_supported": `"authorization_code","refresh_token"`, "response_types_supported": `"code"`} {
		if got := jsonList(m[k]); got != v {
			t.Errorf("%s = %s, want %s", k, got, v)
		}
	}
	if w := do(h, "OPTIONS", "/oauth/token", nil, ""); w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("preflight = %d", w.Code)
	}

	// The 401 on the connector points at the resource metadata.
	code, challenge := mcpStatus(h, "")
	if code != 401 || challenge != `Bearer resource_metadata="http://test/.well-known/oauth-protected-resource/api/mcp"` {
		t.Errorf("no token = %d %q", code, challenge)
	}
	code, challenge = mcpStatus(h, db.OAuthAccessPrefix+"bogus")
	if code != 401 || !strings.Contains(challenge, `error="invalid_token"`) || !strings.Contains(challenge, "resource_metadata=") {
		t.Errorf("bad token = %d %q", code, challenge)
	}
}

func jsonList(v any) string {
	b, _ := json.Marshal(v)
	return strings.Trim(string(b), "[]")
}

func TestOAuthRegistration(t *testing.T) {
	_, store, h := newApp(t)
	good := []string{testRedirect, "http://127.0.0.1:6274/oauth/callback", "http://localhost:33418/cb", "cursor://anysphere.cursor-mcp/oauth/callback"}
	for _, u := range good {
		if !validRedirect(u) {
			t.Errorf("refused %s", u)
		}
	}
	for _, u := range []string{"", "http://example.com/cb", "https://claude.ai/cb#frag", "https://*.claude.ai/cb", "javascript:alert(1)",
		"data:text/html,x", "https://user:pw@claude.ai/cb", "https://claude.ai/a b", "https://claude.ai/a;b", "cursor:", "https://" + strings.Repeat("a", 400)} {
		if validRedirect(u) {
			t.Errorf("accepted %q", u)
		}
	}

	w := registerClient(h, `{"client_name":"Claude","redirect_uris":["http://example.com/cb","`+testRedirect+`"],"token_endpoint_auth_method":"client_secret_post"}`)
	m := jsonBody(t, w)
	if w.Code != 201 || m["token_endpoint_auth_method"] != "none" || m["client_secret"] != nil || jsonList(m["redirect_uris"]) != `"`+testRedirect+`"` {
		t.Errorf("register = %d %v", w.Code, m)
	}
	c, err := store.OAuthClientByID(context.Background(), m["client_id"].(string))
	if err != nil || c.Name != "Claude" || len(c.RedirectURIs) != 1 {
		t.Errorf("stored client = %+v %v", c, err)
	}

	for name, body := range map[string]string{
		"no redirects":     `{"client_name":"x"}`,
		"only bad ones":    `{"redirect_uris":["http://example.com/cb"]}`,
		"too many":         `{"redirect_uris":["` + strings.TrimSuffix(strings.Repeat(testRedirect+`","`, 9), `","`) + `"]}`,
		"not JSON":         `redirect_uris=x`,
		"too large a body": `{"client_name":"` + strings.Repeat("a", 20<<10) + `","redirect_uris":["` + testRedirect + `"]}`,
	} {
		if w := registerClient(h, body); w.Code != 400 || jsonBody(t, w)["error"] == nil {
			t.Errorf("%s = %d %s", name, w.Code, w.Body)
		}
	}

	// A name claiming to be SendScore is not kept, and names are cleaned.
	if got := cleanClientName("Send​Score Official"); got != "" {
		t.Errorf("impersonating name = %q", got)
	}
	if got := cleanClientName("  Claude\x07  Code ‮ "); got != "Claude Code" {
		t.Errorf("cleaned name = %q", got)
	}
	if got := cleanClientName(strings.Repeat("n", 200)); len(got) != maxClientName {
		t.Errorf("long name kept %d characters", len(got))
	}

	// Registration is limited per IP.
	limited := 0
	for range registrationsPerIP + 2 {
		if w := registerClient(h, `{"redirect_uris":["`+testRedirect+`"]}`); w.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Error("registration is not rate limited")
	}
}

func TestOAuthAuthorize(t *testing.T) {
	a, store, h := newApp(t)
	client := newClient(t, h, "Claude")
	_, challenge := pkce("b")
	q := authorizeQuery(client, challenge)
	path := "/oauth/authorize?" + q.Encode()

	// Signed out, it goes through email sign-in and comes back.
	w := do(h, "GET", path, nil, "")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/signin?next="+url.QueryEscape(path) {
		t.Fatalf("signed out = %d %q", w.Code, w.Header().Get("Location"))
	}
	if page := do(h, "GET", w.Header().Get("Location"), nil, "").Body.String(); !strings.Contains(page, `name="next"`) {
		t.Error("the sign-in form drops next")
	}
	post(h, "/signin", url.Values{"email": {"consent@example.com"}, "next": {path}}, "")
	w = post(h, "/signin/verify", url.Values{"t": {mailer(a).lastLink(t)}}, "")
	if w.Header().Get("Location") != path {
		t.Fatalf("after sign-in = %q, want %q", w.Header().Get("Location"), path)
	}
	session := cookieNamed(w, sessionCookie).Value
	post(h, "/signin", url.Values{"email": {"evil@example.com"}, "next": {"//evil.example/x"}}, "")
	if w := post(h, "/signin/verify", url.Values{"t": {mailer(a).lastLink(t)}}, ""); w.Header().Get("Location") != "/account" {
		t.Errorf("off-site next = %q", w.Header().Get("Location"))
	}

	// The consent page names the client and lets the redirect through CSP.
	w = serve(h, request("GET", path, nil, "", session))
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Allow Claude to use SendScore?") || !strings.Contains(body, "consent@example.com") ||
		!strings.Contains(body, `value="deny"`) || !strings.Contains(body, `name="csrf"`) {
		t.Fatalf("consent = %d %s", w.Code, body)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.HasSuffix(csp, "form-action 'self' https://claude.ai") {
		t.Errorf("consent CSP = %q", csp)
	}

	// Problems with the client or the redirect URI stay here.
	for name, mod := range map[string]func(url.Values){
		"unknown client":    func(v url.Values) { v.Set("client_id", "cli_nope") },
		"redirect mismatch": func(v url.Values) { v.Set("redirect_uri", "https://claude.ai/other") },
	} {
		v := authorizeQuery(client, challenge)
		mod(v)
		w := serve(h, request("GET", "/oauth/authorize?"+v.Encode(), nil, "", session))
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Errorf("%s = %d %q", name, w.Code, w.Header().Get("Location"))
		}
	}
	// Others go back to the client with an error and the state.
	for name, c := range map[string]struct {
		mod  func(url.Values)
		want string
	}{
		"no PKCE":        {func(v url.Values) { v.Del("code_challenge") }, "invalid_request"},
		"plain PKCE":     {func(v url.Values) { v.Set("code_challenge_method", "plain") }, "invalid_request"},
		"other resource": {func(v url.Values) { v.Set("resource", "https://elsewhere.example/mcp") }, "invalid_target"},
		"token response": {func(v url.Values) { v.Set("response_type", "token") }, "unsupported_response_type"},
	} {
		v := authorizeQuery(client, challenge)
		c.mod(v)
		w := serve(h, request("GET", "/oauth/authorize?"+v.Encode(), nil, "", session))
		loc, _ := url.Parse(w.Header().Get("Location"))
		if w.Code != http.StatusSeeOther || loc.Query().Get("error") != c.want || loc.Query().Get("state") != "st8" {
			t.Errorf("%s = %d %q", name, w.Code, w.Header().Get("Location"))
		}
	}

	// Deny, and a consent post without the CSRF token.
	vals := authorizeQuery(client, challenge)
	vals.Set("decision", "deny")
	w = post(h, "/oauth/authorize", vals, session)
	if loc, _ := url.Parse(w.Header().Get("Location")); loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" {
		t.Errorf("deny = %q", w.Header().Get("Location"))
	}
	vals.Set("decision", "allow")
	vals.Del("csrf")
	if w := serve(h, request("POST", "/oauth/authorize", strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded", session)); w.Code != http.StatusForbidden {
		t.Errorf("allow without CSRF = %d", w.Code)
	}
	_ = store
}

func TestOAuthCodeExchange(t *testing.T) {
	_, store, h := newApp(t)
	client := newClient(t, h, "Claude")
	other := newClient(t, h, "Other")
	_, session, _ := newUser(t, store, "code@example.com")
	verifier, challenge := pkce("c")
	code := approveCode(t, h, session, authorizeQuery(client, challenge))

	wrong, _ := pkce("d")
	for name, w := range map[string]*httptest.ResponseRecorder{
		"wrong verifier": exchange(h, client, code, wrong),
		"other client":   exchange(h, other, code, verifier),
		"redirect mismatch": tokenRequest(h, url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "code": {code},
			"code_verifier": {verifier}, "redirect_uri": {"https://claude.ai/other"}}),
		"unknown code": exchange(h, client, "nope", verifier),
	} {
		if w.Code != 400 || jsonBody(t, w)["error"] != "invalid_grant" {
			t.Errorf("%s = %d %s", name, w.Code, w.Body)
		}
	}
	if w := exchange(h, "cli_nope", code, verifier); w.Code != 401 || jsonBody(t, w)["error"] != "invalid_client" {
		t.Errorf("unknown client = %d %s", w.Code, w.Body)
	}

	w := exchange(h, client, code, verifier)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("exchange = %d %s", w.Code, w.Body)
	}
	m := jsonBody(t, w)
	access := m["access_token"].(string)
	if m["token_type"] != "Bearer" || m["expires_in"] != float64(3600) || !strings.HasPrefix(access, db.OAuthAccessPrefix) {
		t.Errorf("tokens = %v", m)
	}
	if code, _ := mcpStatus(h, access); code == 401 {
		t.Fatal("the access token is refused")
	}
	// Only hashes are stored.
	var n int
	store.DB.QueryRow(`SELECT COUNT(*) FROM oauth_tokens WHERE token_hash = ? OR selector = ?`, access, access).Scan(&n)
	if n != 0 {
		t.Error("an access token is stored in the clear")
	}
	// An OAuth token is for the connector, not the JSON API.
	if w := apiDo(h, "POST", "/api/v1/test-addresses", access); w.Code != 401 {
		t.Errorf("OAuth token on the API = %d", w.Code)
	}

	// The code works once, and using it again revokes what it led to.
	if w := exchange(h, client, code, verifier); w.Code != 400 || jsonBody(t, w)["error"] != "invalid_grant" {
		t.Errorf("code reuse = %d %s", w.Code, w.Body)
	}
	if code, _ := mcpStatus(h, access); code != 401 {
		t.Error("a reused code did not revoke its tokens")
	}

	// A code expires after 10 minutes.
	v2, c2 := pkce("e")
	late := approveCode(t, h, session, authorizeQuery(client, c2))
	store.Now = func() time.Time { return time.Now().Add(db.OAuthCodeTTL + time.Minute) }
	if w := exchange(h, client, late, v2); w.Code != 400 {
		t.Errorf("expired code = %d", w.Code)
	}
}

func TestOAuthRefreshRotation(t *testing.T) {
	_, store, h := newApp(t)
	client, _, access, first := grant(t, h, store)
	other := newClient(t, h, "Other")

	if w := refresh(h, other, first); w.Code != 400 {
		t.Errorf("another client's refresh = %d", w.Code)
	}
	w := refresh(h, client, first)
	if w.Code != 200 {
		t.Fatalf("refresh = %d %s", w.Code, w.Body)
	}
	m := jsonBody(t, w)
	access2, second := m["access_token"].(string), m["refresh_token"].(string)
	if second == first || access2 == access {
		t.Fatal("refresh did not rotate")
	}
	if code, _ := mcpStatus(h, access2); code == 401 {
		t.Fatal("the refreshed access token is refused")
	}

	// The first refresh token is used up, and presenting it again revokes
	// the whole family, including the pair it was swapped for.
	if w := refresh(h, client, first); w.Code != 400 {
		t.Errorf("reuse = %d", w.Code)
	}
	if w := refresh(h, client, second); w.Code != 400 {
		t.Errorf("the newer refresh token survived reuse = %d", w.Code)
	}
	if code, _ := mcpStatus(h, access2); code != 401 {
		t.Error("the newer access token survived reuse")
	}
}

func TestOAuthExpiry(t *testing.T) {
	_, store, h := newApp(t)
	client, _, access, refreshTok := grant(t, h, store)
	store.Now = func() time.Time { return time.Now().Add(db.OAuthAccessTTL + time.Minute) }
	if code, challenge := mcpStatus(h, access); code != 401 || !strings.Contains(challenge, "invalid_token") {
		t.Errorf("expired access token = %d %q", code, challenge)
	}
	if w := refresh(h, client, refreshTok); w.Code != 200 {
		t.Errorf("refresh after the access token expired = %d", w.Code)
	}
	_, _, _, r2 := grant(t, h, store)
	store.Now = func() time.Time { return time.Now().Add(db.OAuthAccessTTL + db.OAuthRefreshTTL + time.Hour) }
	if w := refresh(h, client, r2); w.Code != 400 {
		t.Errorf("expired refresh token = %d", w.Code)
	}
}

func TestOAuthDisconnect(t *testing.T) {
	_, store, h := newApp(t)
	client, session, access, refreshTok := grant(t, h, store)
	page := serve(h, request("GET", "/account", nil, "", session)).Body.String()
	if !strings.Contains(page, "Claude") || !strings.Contains(page, "/account/apps/"+client+"/disconnect") {
		t.Fatal("the account page does not list the connected app")
	}
	if w := post(h, "/account/apps/"+client+"/disconnect", nil, session); w.Code != http.StatusSeeOther {
		t.Fatalf("disconnect = %d", w.Code)
	}
	if code, _ := mcpStatus(h, access); code != 401 {
		t.Error("access token works after disconnect")
	}
	if w := refresh(h, client, refreshTok); w.Code != 400 {
		t.Error("refresh token works after disconnect")
	}
	if page := serve(h, request("GET", "/account", nil, "", session)).Body.String(); strings.Contains(page, "/disconnect") {
		t.Error("the app is still listed")
	}
}

func TestRemoteMCPWithOAuth(t *testing.T) {
	_, store, h := newApp(t)
	srv := httptest.NewServer(h)
	defer srv.Close()
	_, _, access, _ := grant(t, h, store)
	cs, err := connectMCP(t, srv.URL, access)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_test_address", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("get_test_address: %v %+v", err, res)
	}
	var addr mcpserver.TestAddress
	b, _ := json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &addr)
	got, err := store.AddressByToken(context.Background(), addr.Token)
	u, _ := scanEmail(store, "oauth@example.com")
	if err != nil || got.UserID != u {
		t.Errorf("address owner = %q %v, want %s", got.UserID, err, u)
	}
	if n, _ := store.Count(context.Background(), "tests:user:"+u, db.Day(store.Now())); n != 1 {
		t.Errorf("the OAuth test was counted %d times", n)
	}
}

func scanEmail(store *db.Store, email string) (string, error) {
	var id string
	err := store.DB.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&id)
	return id, err
}
