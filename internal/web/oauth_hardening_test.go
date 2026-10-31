package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sendscore/sendscore-app/internal/db"
)

func TestOAuthOmittedRedirectURI(t *testing.T) {
	_, store, h := newApp(t)
	client := newClient(t, h, "Native")
	_, session, _ := newUser(t, store, "omit@example.com")
	verifier, challenge := pkce("o")
	q := authorizeQuery(client, challenge)
	q.Del("redirect_uri")
	// The consent page does not add a redirect_uri the client left out.
	w := serve(h, request("GET", "/oauth/authorize?"+q.Encode(), nil, "", session))
	if w.Code != 200 || strings.Contains(w.Body.String(), `name="redirect_uri"`) {
		t.Fatalf("consent = %d", w.Code)
	}
	code := approveCode(t, h, session, q)
	// Left out of both requests, as RFC 6749 section 4.1.3 allows.
	w = tokenRequest(h, url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "code": {code}, "code_verifier": {verifier}})
	if w.Code != 200 {
		t.Errorf("exchange without redirect_uri = %d %s", w.Code, w.Body)
	}
	// Named at authorize, it must be named at the token endpoint too.
	verifier, challenge = pkce("p")
	code = approveCode(t, h, session, authorizeQuery(client, challenge))
	w = tokenRequest(h, url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "code": {code}, "code_verifier": {verifier}})
	if w.Code != 400 {
		t.Errorf("exchange leaving out a redirect_uri that was named = %d", w.Code)
	}
}

func TestOAuthLoopbackAnyPort(t *testing.T) {
	_, store, h := newApp(t)
	w := registerClient(h, `{"client_name":"Desktop","redirect_uris":["http://127.0.0.1/callback","http://localhost:8080/cb"]}`)
	client := jsonBody(t, w)["client_id"].(string)
	_, session, _ := newUser(t, store, "loop@example.com")
	_, challenge := pkce("l")
	for uri, want := range map[string]int{
		"http://127.0.0.1:53682/callback":  200,
		"http://localhost:49152/cb":        200,
		"http://127.0.0.1:53682/other":     400,
		"http://127.0.0.2:53682/callback":  400,
		"https://127.0.0.1:53682/callback": 400,
	} {
		q := authorizeQuery(client, challenge)
		q.Set("redirect_uri", uri)
		w := serve(h, request("GET", "/oauth/authorize?"+q.Encode(), nil, "", session))
		if w.Code != want {
			t.Errorf("%s = %d, want %d", uri, w.Code, want)
		}
		// The consent form may post back to the port the app listens on.
		if u, _ := url.Parse(uri); want == 200 && !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self' http://"+u.Host) {
			t.Errorf("%s CSP = %q", uri, w.Header().Get("Content-Security-Policy"))
		}
	}
}

func TestOAuthAuthorizeErrorsAreNotRedirected(t *testing.T) {
	_, store, h := newApp(t)
	w := registerClient(h, `{"redirect_uris":["https://evil.example/landing"]}`)
	client := jsonBody(t, w)["client_id"].(string)
	_, session, _ := newUser(t, store, "phish@example.com")
	q := url.Values{"client_id": {client}, "redirect_uri": {"https://evil.example/landing"}, "response_type": {"x"}}
	w = serve(h, request("GET", "/oauth/authorize?"+q.Encode(), nil, "", session))
	if w.Code != 400 || w.Header().Get("Location") != "" {
		t.Errorf("invalid request = %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestOAuthRegistrationLimits(t *testing.T) {
	// The service cap applies whatever the network.
	_, _, h := newApp(t, func(c *Config) { c.RegistrationsPerHour = 2; c.TrustProxy = true })
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		r := request("POST", "/oauth/register", strings.NewReader(`{"redirect_uris":["`+testRedirect+`"]}`), "application/json", "")
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("X-Forwarded-For", ip)
		w := serve(h, r)
		if want := map[bool]int{true: 201, false: 429}[i < 2]; w.Code != want {
			t.Errorf("registration %d = %d, want %d", i, w.Code, want)
		}
	}

	// A full table refuses with a 503 and never hands out a dead client_id.
	defer func(n int) { db.MaxOAuthClients = n }(db.MaxOAuthClients)
	db.MaxOAuthClients = 1
	_, _, h = newApp(t)
	newClient(t, h, "First")
	w := registerClient(h, `{"redirect_uris":["`+testRedirect+`"]}`)
	if w.Code != http.StatusServiceUnavailable || jsonBody(t, w)["client_id"] != nil {
		t.Errorf("full table = %d %s", w.Code, w.Body)
	}
}

func TestOAuthConnectedAppsPerAccount(t *testing.T) {
	_, store, h := newApp(t)
	u, session, _ := newUser(t, store, "apps@example.com")
	ctx := context.Background()
	for range maxConnectedApps {
		c, err := store.CreateOAuthClient(ctx, "App", []string{testRedirect})
		if err != nil {
			t.Fatal(err)
		}
		code, _ := store.CreateOAuthCode(ctx, db.OAuthCode{ClientID: c.ID, UserID: u.ID, RedirectURI: testRedirect, RedirectGiven: true, CodeChallenge: "x"})
		if _, err := store.ExchangeOAuthCode(ctx, code, func(db.OAuthCode) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	client := newClient(t, h, "One too many")
	_, challenge := pkce("m")
	q := authorizeQuery(client, challenge)
	if w := serve(h, request("GET", "/oauth/authorize?"+q.Encode(), nil, "", session)); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Disconnect one") {
		t.Errorf("authorize past the cap = %d", w.Code)
	}
	q.Set("decision", "allow")
	if w := post(h, "/oauth/authorize", q, session); w.Code != http.StatusForbidden {
		t.Errorf("approve past the cap = %d", w.Code)
	}
}
