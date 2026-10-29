package web

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSafeNext(t *testing.T) {
	for _, bad := range []string{
		"/a/../\\evil.com", "/./\\evil.com", "/\\evil.com", "//evil.com", "/a//evil.com", "/%2F%2Fevil.com",
		"https://evil.com", "/a\\b", "evil.com", "/a\tb", "/a\x00", "",
	} {
		if got := safeNext(bad); got != "" {
			t.Errorf("safeNext(%q) = %q, want empty", bad, got)
		}
	}
	for _, good := range []string{"/account", "/oauth/authorize?client_id=c&redirect_uri=https%3A%2F%2Fa.test%2Fcb", "/oauth/authorize?redirect_uri=https://a.test//cb"} {
		if got := safeNext(good); got != good {
			t.Errorf("safeNext(%q) = %q", good, got)
		}
	}
}

func TestSigninNextIsNotAnOpenRedirect(t *testing.T) {
	a, store, h := newApp(t)
	_, session, _ := newUser(t, store, "redirect@example.com")
	for _, next := range []string{"/a/../\\evil.com", "/./\\evil.com", "/a/..//evil.com"} {
		// Already signed in: the redirect happens at once.
		w := serve(h, request("GET", "/signin?next="+url.QueryEscape(next), nil, "", session))
		if loc := w.Header().Get("Location"); loc != "/account" {
			t.Errorf("signed in, next %q: Location = %q", next, loc)
		}
		// Through the emailed link.
		post(h, "/signin", url.Values{"email": {"redirect@example.com"}, "next": {next}}, "")
		w = post(h, "/signin/verify", url.Values{"t": {mailer(a).lastLink(t)}}, "")
		if loc := w.Header().Get("Location"); loc != "/account" {
			t.Errorf("verify, next %q: Location = %q", next, loc)
		}
	}
	// A real path is kept exactly, with nothing cleaned.
	next := "/oauth/authorize?client_id=c&redirect_uri=https%3A%2F%2Fa.test%2Fcb"
	w := serve(h, request("GET", "/signin?next="+url.QueryEscape(next), nil, "", session))
	if loc := w.Header().Get("Location"); loc != next {
		t.Errorf("good next: Location = %q", loc)
	}
}

func TestFormsNeedOriginOrReferer(t *testing.T) {
	_, _, h := newApp(t)
	body := url.Values{"csrf": {testCSRF}, "email": {"o@example.com"}}.Encode()
	r := request("POST", "/signin", strings.NewReader(body), "application/x-www-form-urlencoded", "")
	r.Header.Del("Origin")
	if w := serve(h, r); w.Code != http.StatusForbidden {
		t.Errorf("no Origin or Referer = %d", w.Code)
	}
	r = request("POST", "/signin", strings.NewReader(body), "application/x-www-form-urlencoded", "")
	r.Header.Del("Origin")
	r.Header.Set("Referer", "http://test/signin")
	if w := serve(h, r); w.Code != http.StatusOK {
		t.Errorf("same-site Referer = %d", w.Code)
	}
	r = request("POST", "/signin", strings.NewReader(body), "application/x-www-form-urlencoded", "")
	r.Header.Set("Origin", "https://evil.example")
	if w := serve(h, r); w.Code != http.StatusForbidden {
		t.Errorf("other Origin = %d", w.Code)
	}
}

func uploadBody(t *testing.T, raw []byte) (*bytes.Buffer, *multipart.Writer) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("csrf", testCSRF)
	fw, _ := mw.CreateFormFile("message", "issue.eml")
	fw.Write(raw)
	mw.Close()
	return &body, mw
}

// countingReader records whether a body was read.
type countingReader struct {
	r *bytes.Buffer
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestUploadRefusedBeforeTheBodyIsRead(t *testing.T) {
	_, _, h := newApp(t, func(c *Config) { c.AnonDailyTests = 1 })
	body, mw := uploadBody(t, sample(t))
	if w := postMultipart(h, "/upload", body, mw); w.Code != http.StatusSeeOther {
		t.Fatalf("first upload = %d %s", w.Code, w.Body)
	}
	// Over the daily limit, the body is never read.
	body, mw = uploadBody(t, sample(t))
	cr := &countingReader{r: body}
	w := serve(h, request("POST", "/upload", cr, mw.FormDataContentType(), ""))
	if w.Code != http.StatusTooManyRequests || cr.n != 0 {
		t.Errorf("over the limit = %d, read %d bytes", w.Code, cr.n)
	}
	// A post from another site is refused before reading too.
	body, mw = uploadBody(t, sample(t))
	cr = &countingReader{r: body}
	r := request("POST", "/upload", cr, mw.FormDataContentType(), "")
	r.Header.Set("Origin", "https://evil.example")
	if w := serve(h, r); w.Code != http.StatusForbidden || cr.n != 0 {
		t.Errorf("cross-site upload = %d, read %d bytes", w.Code, cr.n)
	}
	// When every upload slot is taken, the next is turned away at once.
	busy, _, bh := newApp(t)
	for range maxUploads {
		busy.uploads <- struct{}{}
	}
	body, mw = uploadBody(t, sample(t))
	if w := postMultipart(bh, "/upload", body, mw); w.Code != http.StatusServiceUnavailable {
		t.Errorf("busy = %d", w.Code)
	}
}

func TestSignedInUploadBelongsToTheAccount(t *testing.T) {
	_, store, h := newApp(t)
	_, session, tok := newUser(t, store, "up@example.com")
	body, mw := uploadBody(t, sample(t))
	w := serve(h, request("POST", "/upload", body, mw.FormDataContentType(), session))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload = %d %s", w.Code, w.Body)
	}
	id := strings.TrimPrefix(w.Header().Get("Location"), "/r/")
	if w := apiDo(h, "GET", "/api/v1/reports/"+id, tok); w.Code != 200 {
		t.Errorf("own upload through the API = %d", w.Code)
	}
	_, _, other := newUser(t, store, "other@example.com")
	if w := apiDo(h, "GET", "/api/v1/reports/"+id, other); w.Code != 404 {
		t.Errorf("someone else's upload = %d", w.Code)
	}
}

// signinFrom posts the sign-in form from ip (through a trusted proxy), with
// the given extra cookies.
func signinFrom(h http.Handler, ip, email string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	body := url.Values{"csrf": {testCSRF}, "email": {email}}.Encode()
	r := request("POST", "/signin", strings.NewReader(body), "application/x-www-form-urlencoded", "")
	r.Header.Set("X-Forwarded-For", ip)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return serve(h, r)
}

func TestSigninCannotLockTheOwnerOut(t *testing.T) {
	a, _, h := newApp(t, func(c *Config) { c.TrustProxy = true })
	// The owner signs in once, so this browser is known.
	signinFrom(h, "198.51.100.1", "owner@example.com")
	w := post(h, "/signin/verify", url.Values{"t": {mailer(a).lastLink(t)}}, "")
	known := cookieNamed(w, browserCookie)
	if known == nil {
		t.Fatal("no browser cookie after signing in")
	}
	// A stranger uses up the rest of the address's allowance from several
	// networks.
	for i := range signinPerHour - 1 {
		if w := signinFrom(h, "203.0.113."+string(rune('1'+i)), "owner@example.com"); w.Code != 200 {
			t.Fatalf("stranger %d = %d", i, w.Code)
		}
	}
	if w := signinFrom(h, "203.0.113.99", "owner@example.com"); w.Code != http.StatusTooManyRequests {
		t.Errorf("stranger over the limit = %d", w.Code)
	}
	// The owner's browser still gets a link.
	if w := signinFrom(h, "198.51.100.1", "owner@example.com", known); w.Code != 200 {
		t.Errorf("known browser after a stranger used the allowance = %d", w.Code)
	}
	// The cookie only counts for the address it signed in to.
	for i := range signinPerHour {
		signinFrom(h, "192.0.2."+string(rune('1'+i)), "someone@example.com")
	}
	if w := signinFrom(h, "198.51.100.1", "someone@example.com", known); w.Code != http.StatusTooManyRequests {
		t.Errorf("known browser for another address = %d", w.Code)
	}
}

func TestSigninGlobalAndIPv6Limits(t *testing.T) {
	_, _, h := newApp(t, func(c *Config) { c.TrustProxy = true; c.SigninEmailsPerHour = 3 })
	for i := range 3 {
		if w := signinFrom(h, "198.51.100."+string(rune('1'+i)), "g"+string(rune('a'+i))+"@example.com"); w.Code != 200 {
			t.Fatalf("email %d = %d", i, w.Code)
		}
	}
	if w := signinFrom(h, "198.51.100.9", "gz@example.com"); w.Code != http.StatusTooManyRequests {
		t.Errorf("over the service cap = %d", w.Code)
	}
	// Requests one network's limit refuses do not use up the service's.
	_, _, h = newApp(t, func(c *Config) { c.TrustProxy = true; c.SigninEmailsPerHour = signinPerHour + 1 })
	for i := range 3 * signinPerHour {
		signinFrom(h, "203.0.113.7", "flood"+string(rune('a'+i))+"@example.com")
	}
	if w := signinFrom(h, "198.51.100.1", "real@example.com"); w.Code != 200 {
		t.Errorf("after one network's flood = %d", w.Code)
	}

	// Different /64s in one /48 share a network allowance.
	_, _, h = newApp(t, func(c *Config) { c.TrustProxy = true })
	for i := range signinPerHour {
		ip := "2001:db8:1:" + string(rune('a'+i)) + "::1"
		if w := signinFrom(h, ip, "v"+string(rune('a'+i))+"@example.com"); w.Code != 200 {
			t.Fatalf("v6 email %d = %d", i, w.Code)
		}
	}
	if w := signinFrom(h, "2001:db8:1:ff::1", "vz@example.com"); w.Code != http.StatusTooManyRequests {
		t.Errorf("another /64 in the same /48 = %d", w.Code)
	}
	if w := signinFrom(h, "2001:db8:2::1", "vz@example.com"); w.Code != 200 {
		t.Errorf("another /48 = %d", w.Code)
	}
}

func TestVerifyPageNamesTheAccount(t *testing.T) {
	a, _, h := newApp(t)
	post(h, "/signin", url.Values{"email": {"named@example.com"}, "next": {"/oauth/authorize?client_id=x"}}, "")
	w := do(h, "GET", "/signin/verify?t="+mailer(a).lastLink(t), nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "named@example.com") || !strings.Contains(w.Body.String(), "connect an app") {
		t.Errorf("verify page = %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", "/signin/verify?t=unknown", nil, ""); w.Code != 400 {
		t.Errorf("unknown link = %d", w.Code)
	}
}

func TestReportShowsTheAddressOnlyToItsOwner(t *testing.T) {
	_, store, h := newApp(t)
	// An anonymous address belongs to the browser that made it.
	w := post(h, "/test", nil, "")
	token := strings.TrimPrefix(w.Header().Get("Location"), "/t/")
	m := saveMessage(t, store, token, "smtp")
	if w := serve(h, request("GET", "/r/"+m.ID, nil, "", "")); !strings.Contains(w.Body.String(), "t-"+token+"@") {
		t.Error("the browser that made the address does not see it")
	}
	stranger := httptest.NewRequest("GET", "/r/"+m.ID, nil)
	stranger.AddCookie(&http.Cookie{Name: csrfCookie, Value: strings.Repeat("s", 40)})
	if w := serve(h, stranger); w.Code != 200 || strings.Contains(w.Body.String(), token) {
		t.Errorf("a stranger sees the address (%d)", w.Code)
	}
	// An account's address shows to the account only.
	u, session, _ := newUser(t, store, "owner@example.com")
	addr, _ := store.CreateAddressFor(context.Background(), time.Hour, u.ID)
	m = saveMessage(t, store, addr.Token, "smtp")
	if w := serve(h, request("GET", "/r/"+m.ID, nil, "", session)); !strings.Contains(w.Body.String(), "?after="+m.ID) {
		t.Error("the owner has no link to send again")
	}
	if w := serve(h, request("GET", "/r/"+m.ID, nil, "", "")); strings.Contains(w.Body.String(), addr.Token) {
		t.Error("a signed-out viewer sees the account's address")
	}
}

func TestWaitsAfterTheAddressExpires(t *testing.T) {
	_, store, h := newApp(t)
	u, session, tok := newUser(t, store, "late@example.com")
	ctx := context.Background()
	// The address expires after 30 minutes, and its report after an hour.
	addr, _ := store.CreateAddressFor(ctx, 30*time.Minute, u.ID)
	m := saveMessage(t, store, addr.Token, "smtp")
	store.Now = func() time.Time { return time.Now().Add(45 * time.Minute) }
	defer func() { store.Now = time.Now }()
	wait := "/api/v1/test-addresses/" + addr.Token + "/wait?timeout=1"
	// The report that arrived before expiry is still answered.
	if w := apiDo(h, "GET", wait, tok); w.Code != 200 || !strings.Contains(w.Body.String(), m.ID) {
		t.Errorf("wait after expiry = %d %s", w.Code, w.Body)
	}
	// Nothing newer can arrive, so the wait says so at once.
	start := time.Now()
	if w := apiDo(h, "GET", wait+"&after="+m.ID, tok); w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "expired") {
		t.Errorf("wait for a newer message after expiry = %d %s", w.Code, w.Body)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Error("the wait on an expired address did not answer at once")
	}
	if w := serve(h, request("GET", "/t/"+addr.Token, nil, "", "")); w.Header().Get("Location") != "/r/"+m.ID {
		t.Errorf("address page after expiry = %d", w.Code)
	}
	if w := serve(h, request("GET", "/t/"+addr.Token+"?after="+m.ID, nil, "", "")); w.Code != http.StatusGone {
		t.Errorf("address page waiting after expiry = %d", w.Code)
	}
	// The report no longer offers to send again.
	body := serve(h, request("GET", "/r/"+m.ID, nil, "", session)).Body.String()
	if strings.Contains(body, "?after=") || !strings.Contains(body, "no longer accepts mail") {
		t.Error("the report of an expired address still offers to send again")
	}
}

func TestWaitsPerUserAreCapped(t *testing.T) {
	a, store, h := newApp(t)
	a.cfg.MaxWait = 5 * time.Second
	u, _, tok := newUser(t, store, "many@example.com")
	addr, _ := store.CreateAddressFor(context.Background(), time.Hour, u.ID)
	wait := "/api/v1/test-addresses/" + addr.Token + "/wait?timeout=5"
	var wg sync.WaitGroup
	for range maxWaitsPerUser {
		wg.Add(1)
		go func() { defer wg.Done(); apiDo(h, "GET", wait, tok) }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.waitMu.Lock()
		n := a.waits[u.ID]
		a.waitMu.Unlock()
		if n == maxWaitsPerUser || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if w := apiDo(h, "GET", wait, tok); w.Code != http.StatusTooManyRequests {
		t.Errorf("one wait too many = %d %s", w.Code, w.Body)
	}
	a.StopWaits()
	wg.Wait()
	a.waitMu.Lock()
	defer a.waitMu.Unlock()
	if len(a.waits) != 0 {
		t.Errorf("waits left open = %v", a.waits)
	}
}

func TestSecureCookiesNamesAreHostPrefixed(t *testing.T) {
	a, _, _ := newApp(t, func(c *Config) { c.SecureCookies = true })
	if a.cookie(sessionCookie) != "__Host-ss_session" || a.cookie(csrfCookie) != "__Host-ss_csrf" {
		t.Errorf("cookie names = %s, %s", a.cookie(sessionCookie), a.cookie(csrfCookie))
	}
}
