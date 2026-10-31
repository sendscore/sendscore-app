package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
)

func cookieNamed(w interface{ Result() *http.Response }, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestSigninLinkIsSingleUse(t *testing.T) {
	a, store, h := newApp(t)
	w := post(h, "/signin", url.Values{"email": {"  Reader@Example.com "}}, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Check your email") {
		t.Fatalf("signin = %d %s", w.Code, w.Body)
	}
	link := mailer(a).lastLink(t)
	if got := mailer(a).msgs[0].To; got != "reader@example.com" {
		t.Errorf("sent to %q", got)
	}

	// Opening the link only shows a button, so a mail scanner cannot use it.
	w = do(h, "GET", "/signin/verify?t="+link, nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="t" value="`+link+`"`) {
		t.Fatalf("verify page = %d %s", w.Code, w.Body)
	}
	w = post(h, "/signin/verify", url.Values{"t": {link}}, "")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account" {
		t.Fatalf("verify = %d %s", w.Code, w.Body)
	}
	c := cookieNamed(w, sessionCookie)
	if c == nil || c.Value == "" {
		t.Fatal("no session cookie")
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure || c.MaxAge != int(db.SessionTTL.Seconds()) {
		t.Errorf("session cookie = %+v", c)
	}
	acct := serve(h, request("GET", "/account", nil, "", c.Value))
	if acct.Code != 200 || !strings.Contains(acct.Body.String(), "reader@example.com") || !strings.Contains(acct.Body.String(), "Sign out") {
		t.Errorf("account = %d", acct.Code)
	}

	// The same link cannot sign in again.
	if w := post(h, "/signin/verify", url.Values{"t": {link}}, ""); w.Code != 400 || cookieNamed(w, sessionCookie) != nil {
		t.Errorf("second use = %d", w.Code)
	}

	// A link past 15 minutes is refused.
	post(h, "/signin", url.Values{"email": {"reader@example.com"}}, "")
	late := mailer(a).lastLink(t)
	store.Now = func() time.Time { return time.Now().Add(db.LoginTokenTTL + time.Minute) }
	if w := post(h, "/signin/verify", url.Values{"t": {late}}, ""); w.Code != 400 {
		t.Errorf("expired link = %d", w.Code)
	}
	store.Now = time.Now

	// Only hashes are stored.
	var n int
	store.DB.QueryRow(`SELECT COUNT(*) FROM login_tokens WHERE token_hash = ? OR selector = ?`, late, late).Scan(&n)
	if n != 0 {
		t.Error("a sign-in token is stored in the clear")
	}
	store.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token_hash = ?`, c.Value).Scan(&n)
	if n != 0 {
		t.Error("a session token is stored in the clear")
	}

	// Signing out ends the session.
	out := post(h, "/signout", nil, c.Value)
	if out.Code != http.StatusSeeOther {
		t.Fatalf("signout = %d", out.Code)
	}
	if gone := cookieNamed(out, sessionCookie); gone == nil || gone.MaxAge >= 0 {
		t.Errorf("signout cookie = %+v", gone)
	}
	if w := serve(h, request("GET", "/account", nil, "", c.Value)); w.Code != http.StatusSeeOther {
		t.Errorf("account after signout = %d", w.Code)
	}
}

func TestSecureCookies(t *testing.T) {
	a, _, h := newApp(t, func(c *Config) { c.SecureCookies = true })
	w := do(h, "GET", "/signin", nil, "")
	if c := cookieNamed(w, "__Host-"+csrfCookie); c == nil || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" {
		t.Errorf("csrf cookie = %+v", c)
	}
	if got := w.Header().Get("Strict-Transport-Security"); !strings.Contains(got, "max-age=") {
		t.Errorf("HSTS = %q", got)
	}
	// A browser sends the cookie under its __Host- name.
	securePost := func(path string, vals url.Values) *httptest.ResponseRecorder {
		vals.Set("csrf", testCSRF)
		req := httptest.NewRequest("POST", path, strings.NewReader(vals.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://test")
		req.AddCookie(&http.Cookie{Name: "__Host-" + csrfCookie, Value: testCSRF})
		return serve(h, req)
	}
	securePost("/signin", url.Values{"email": {"secure@example.com"}})
	w = securePost("/signin/verify", url.Values{"t": {mailer(a).lastLink(t)}})
	if c := cookieNamed(w, "__Host-"+sessionCookie); c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie = %+v", c)
	}
	// The unprefixed cookie a sibling subdomain could set is ignored.
	if w := post(h, "/signin", url.Values{"email": {"secure@example.com"}}, ""); w.Code != http.StatusForbidden {
		t.Errorf("post with an unprefixed csrf cookie = %d", w.Code)
	}
	// Without SecureCookies there is no HSTS.
	_, _, plain := newApp(t)
	if got := do(plain, "GET", "/", nil, "").Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS over http = %q", got)
	}
}

func TestSigninDoesNotRevealAccounts(t *testing.T) {
	_, store, h := newApp(t)
	newUser(t, store, "known@example.com")
	known := post(h, "/signin", url.Values{"email": {"known@example.com"}}, "")
	unknown := post(h, "/signin", url.Values{"email": {"nobody@example.com"}}, "")
	if known.Code != unknown.Code {
		t.Errorf("status %d for an account, %d for none", known.Code, unknown.Code)
	}
	a := strings.ReplaceAll(known.Body.String(), "known@example.com", "X")
	b := strings.ReplaceAll(unknown.Body.String(), "nobody@example.com", "X")
	if a != b {
		t.Error("the response differs for an address with an account")
	}
}

func TestSigninRateLimit(t *testing.T) {
	a, _, h := newApp(t)
	for i := range signinPerHour {
		if w := post(h, "/signin", url.Values{"email": {"busy@example.com"}}, ""); w.Code != 200 {
			t.Fatalf("email %d = %d", i+1, w.Code)
		}
	}
	if w := post(h, "/signin", url.Values{"email": {"busy@example.com"}}, ""); w.Code != http.StatusTooManyRequests {
		t.Errorf("over the limit = %d", w.Code)
	}
	if n := mailer(a).count(); n != signinPerHour {
		t.Errorf("sent %d emails, want %d", n, signinPerHour)
	}
	// The same IP is limited for other addresses too.
	if w := post(h, "/signin", url.Values{"email": {"other@example.com"}}, ""); w.Code != http.StatusTooManyRequests {
		t.Errorf("same IP, new address = %d", w.Code)
	}
}

func TestCSRF(t *testing.T) {
	a, _, h := newApp(t)
	form := "application/x-www-form-urlencoded"
	cases := map[string]*http.Request{
		"no token":    request("POST", "/signin", strings.NewReader("email=a%40example.com"), form, ""),
		"wrong token": request("POST", "/signin", strings.NewReader("email=a%40example.com&csrf=wrongwrongwrongwrongwrongwrongwrong"), form, ""),
		"another site": func() *http.Request {
			r := request("POST", "/signin", strings.NewReader("email=a%40example.com&csrf="+testCSRF), form, "")
			r.Header.Set("Origin", "https://evil.example")
			return r
		}(),
		"another site by referer": func() *http.Request {
			r := request("POST", "/test", strings.NewReader("csrf="+testCSRF), form, "")
			r.Header.Del("Origin")
			r.Header.Set("Referer", "https://evil.example/page")
			return r
		}(),
		"no cookie": httptestRequest("POST", "/test", "csrf="+testCSRF),
	}
	for name, r := range cases {
		if w := serve(h, r); w.Code != http.StatusForbidden {
			t.Errorf("%s = %d", name, w.Code)
		}
	}
	if n := mailer(a).count(); n != 0 {
		t.Errorf("sent %d emails on refused forms", n)
	}
	// The page hands out the token the form needs.
	w := do(h, "GET", "/", nil, "")
	c := cookieNamed(w, csrfCookie)
	if c == nil || !strings.Contains(w.Body.String(), `name="csrf" value="`+c.Value+`"`) {
		t.Error("home page form lacks the CSRF token from its cookie")
	}
}

func httptestRequest(method, path, body string) *http.Request {
	r, _ := http.NewRequest(method, "http://test"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.0.2.1:1234"
	return r
}

func TestAPITokens(t *testing.T) {
	_, store, h := newApp(t)
	u, session, _ := newUser(t, store, "tokens@example.com")

	w := post(h, "/account/tokens", url.Values{"name": {"Claude Code"}}, session)
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	i := strings.Index(body, db.APITokenPrefix)
	if i < 0 {
		t.Fatal("the new token is not shown")
	}
	token := body[i : i+len(db.APITokenPrefix)+52]
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("the token page may be cached")
	}

	// Shown once: the account page lists only the prefix.
	page := serve(h, request("GET", "/account", nil, "", session)).Body.String()
	if strings.Contains(page, token) || !strings.Contains(page, token[:12]+"...") || !strings.Contains(page, "Claude Code") {
		t.Error("the account page shows the full token, or not the prefix")
	}

	// Only the hash and the prefix are stored.
	var hash, sel string
	if err := store.DB.QueryRow(`SELECT token_hash, selector FROM api_tokens WHERE user_id = ? AND name = ?`, u.ID, "Claude Code").Scan(&hash, &sel); err != nil {
		t.Fatal(err)
	}
	if hash != db.HashToken(token) || sel != token[:12] || strings.Contains(hash, token) {
		t.Errorf("stored hash %q selector %q", hash, sel)
	}

	if w := apiDo(h, "POST", "/api/v1/test-addresses", token); w.Code != 201 {
		t.Fatalf("api with the new token = %d", w.Code)
	}
	if page := serve(h, request("GET", "/account", nil, "", session)).Body.String(); strings.Count(page, "Never") != 1 {
		t.Error("last used was not recorded (one of the two tokens is still unused)")
	}

	toks, _ := store.APITokens(context.Background(), u.ID)
	var id string
	for _, tk := range toks {
		if tk.Name == "Claude Code" {
			id = tk.ID
		}
	}
	// Another account cannot revoke it.
	_, otherSession, _ := newUser(t, store, "intruder@example.com")
	post(h, "/account/tokens/"+id+"/revoke", nil, otherSession)
	if w := apiDo(h, "POST", "/api/v1/test-addresses", token); w.Code != 201 {
		t.Errorf("after another account's revoke = %d", w.Code)
	}
	if w := post(h, "/account/tokens/"+id+"/revoke", nil, session); w.Code != http.StatusSeeOther {
		t.Fatalf("revoke = %d", w.Code)
	}
	if w := apiDo(h, "POST", "/api/v1/test-addresses", token); w.Code != 401 {
		t.Errorf("revoked token = %d", w.Code)
	}
	if w := post(h, "/account/tokens", url.Values{"name": {""}}, session); w.Code != 400 {
		t.Errorf("unnamed token = %d", w.Code)
	}
	if w := post(h, "/account/tokens", url.Values{"name": {"x"}}, ""); w.Code != http.StatusSeeOther {
		t.Errorf("signed out = %d", w.Code)
	}
}

func TestAPIRequiresToken(t *testing.T) {
	_, store, h := newApp(t)
	_, _, tok := newUser(t, store, "api@example.com")
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/test-addresses"},
		{"GET", "/api/v1/test-addresses/abc/wait?timeout=0"},
		{"GET", "/api/v1/reports/rpt_x"},
	} {
		for _, bad := range []string{"", "ss_live_wrong", tok + "x", "Basic " + tok} {
			w := apiDo(h, c.method, c.path, "")
			if bad != "" {
				r := httptestRequest(c.method, c.path, "")
				if strings.HasPrefix(bad, "Basic ") {
					r.Header.Set("Authorization", bad)
				} else {
					r.Header.Set("Authorization", "Bearer "+bad)
				}
				w = serve(h, r)
			}
			var e struct{ Error string }
			json.Unmarshal(w.Body.Bytes(), &e)
			if w.Code != 401 || !strings.Contains(e.Error, "Authorization: Bearer") || w.Header().Get("WWW-Authenticate") == "" {
				t.Errorf("%s %s with %q = %d %s", c.method, c.path, bad, w.Code, w.Body)
			}
		}
	}
}

func TestOwnership(t *testing.T) {
	_, store, h := newApp(t)
	_, _, alice := newUser(t, store, "alice@example.com")
	_, _, bob := newUser(t, store, "bob@example.com")

	w := apiDo(h, "POST", "/api/v1/test-addresses", alice)
	var created struct{ Token string }
	json.Unmarshal(w.Body.Bytes(), &created)
	m := saveMessage(t, store, created.Token, "smtp")

	wait := "/api/v1/test-addresses/" + created.Token + "/wait?timeout=1"
	if w := apiDo(h, "GET", wait, alice); w.Code != 200 || !strings.Contains(w.Body.String(), m.ID) {
		t.Errorf("owner's wait = %d", w.Code)
	}
	if w := apiDo(h, "GET", wait, bob); w.Code != 404 {
		t.Errorf("other's wait = %d", w.Code)
	}
	if w := apiDo(h, "GET", "/api/v1/reports/"+m.ID, alice); w.Code != 200 {
		t.Errorf("owner's report = %d", w.Code)
	}
	if w := apiDo(h, "GET", "/api/v1/reports/"+m.ID, bob); w.Code != 404 {
		t.Errorf("other's report = %d", w.Code)
	}
	// Anonymous addresses and uploads belong to nobody's token.
	anon, _ := store.CreateAddress(context.Background(), time.Hour)
	am := saveMessage(t, store, anon.Token, "smtp")
	if w := apiDo(h, "GET", "/api/v1/reports/"+am.ID, alice); w.Code != 404 {
		t.Errorf("anonymous report over the API = %d", w.Code)
	}
	// The report page stays viewable by its link.
	if w := do(h, "GET", "/r/"+m.ID, nil, ""); w.Code != 200 {
		t.Errorf("report page = %d", w.Code)
	}
}

func TestDailyLimits(t *testing.T) {
	_, store, h := newApp(t, func(c *Config) { c.DailyTests = 2; c.AnonDailyTests = 1 })
	u, session, tok := newUser(t, store, "daily@example.com")

	// The API and the signed-in page share the allowance.
	if w := apiDo(h, "POST", "/api/v1/test-addresses", tok); w.Code != 201 {
		t.Fatalf("first = %d", w.Code)
	}
	w := post(h, "/test", nil, session)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("signed-in page = %d", w.Code)
	}
	addr, _ := store.AddressByToken(context.Background(), strings.TrimPrefix(w.Header().Get("Location"), "/t/"))
	if addr.UserID != u.ID {
		t.Errorf("the signed-in page's address belongs to %q", addr.UserID)
	}
	w = apiDo(h, "POST", "/api/v1/test-addresses", tok)
	var e struct{ Error string }
	json.Unmarshal(w.Body.Bytes(), &e)
	if w.Code != http.StatusTooManyRequests || !strings.Contains(e.Error, "daily limit of 2") {
		t.Errorf("over the limit = %d %s", w.Code, w.Body)
	}
	if w := post(h, "/test", nil, session); w.Code != http.StatusTooManyRequests {
		t.Errorf("signed-in page over the limit = %d", w.Code)
	}
	if page := serve(h, request("GET", "/account", nil, "", session)).Body.String(); !strings.Contains(page, "used 2 of your 2") {
		t.Error("the account page does not show today's usage")
	}

	// Anonymous visitors: per IP, for test addresses and uploads alike.
	if w := post(h, "/test", nil, ""); w.Code != http.StatusSeeOther {
		t.Fatalf("anonymous first = %d", w.Code)
	}
	w = post(h, "/test", nil, "")
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "Sign in for 2 a day") {
		t.Errorf("anonymous over the limit = %d", w.Code)
	}
	other := request("POST", "/test", strings.NewReader("csrf="+testCSRF), "application/x-www-form-urlencoded", "")
	other.RemoteAddr = "198.51.100.7:4000"
	if w := serve(h, other); w.Code != http.StatusSeeOther {
		t.Errorf("another IP = %d", w.Code)
	}

	// A new UTC day starts the count again.
	store.Now = func() time.Time { return time.Now().Add(24 * time.Hour) }
	if w := apiDo(h, "POST", "/api/v1/test-addresses", tok); w.Code != 201 {
		t.Errorf("next day = %d", w.Code)
	}
}

func TestClientIPFromProxy(t *testing.T) {
	a, _, _ := newApp(t)
	r := httptestRequest("GET", "/", "")
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.2")
	if ip := a.clientIP(r); ip != "127.0.0.1" {
		t.Errorf("untrusted proxy: ip = %q", ip)
	}
	a.cfg.TrustProxy = true
	if ip := a.clientIP(r); ip != "198.51.100.2" {
		t.Errorf("trusted proxy: ip = %q, want the entry the proxy added", ip)
	}
	r.Header.Set("X-Forwarded-For", "2001:db8:1:2:3:4:5:6")
	if ip := a.clientIP(r); ip != "2001:db8:1::/48" {
		t.Errorf("ipv6 = %q", ip)
	}
	// Not an address: the header is ignored, not used as a counter name.
	r.Header.Set("X-Forwarded-For", "anything-goes")
	if ip := a.clientIP(r); ip != "127.0.0.1" {
		t.Errorf("junk header: ip = %q", ip)
	}
	// Proxies in the chain are skipped, and what comes before them is forged.
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9, 10.0.0.2")
	if ip := a.clientIP(r); ip != "203.0.113.9" {
		t.Errorf("chain: ip = %q", ip)
	}
	// A connection that is not from a trusted proxy cannot set the header.
	r.RemoteAddr = "198.51.100.5:4000"
	if ip := a.clientIP(r); ip != "198.51.100.5" {
		t.Errorf("direct connection: ip = %q, a client chose its own", ip)
	}
}

func TestPolicyLinks(t *testing.T) {
	_, _, h := newApp(t)
	if body := serve(h, request("GET", "/signin", nil, "", "")).Body.String(); strings.Contains(body, "Privacy") {
		t.Error("policy links shown without SENDSCORE_PRIVACY_URL")
	}
	_, _, h = newApp(t, func(c *Config) {
		c.PrivacyURL, c.TermsURL = "https://example.com/privacy/", "https://example.com/terms/"
	})
	body := serve(h, request("GET", "/signin", nil, "", "")).Body.String()
	for _, want := range []string{`href="https://example.com/privacy/">Privacy`, `href="https://example.com/terms/">terms`} {
		if !strings.Contains(body, want) {
			t.Errorf("sign-in page lacks %s", want)
		}
	}
}
