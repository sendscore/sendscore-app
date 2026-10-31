package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/sendscore/sendscore-app/internal/db"
)

func TestClosedSignupsLookTheSameAndMakeNoAccount(t *testing.T) {
	a, store, h := newApp(t, func(c *Config) { c.ClosedSignups = true; c.ProEmails = []string{"listed@example.com"} })
	ctx := context.Background()
	if _, _, _ = newUser(t, store, "member@example.com"); false {
		t.Fatal()
	}
	var pages []string
	for _, email := range []string{"stranger@example.com", "member@example.com", "listed@example.com"} {
		w := post(h, "/signin", url.Values{"email": {email}}, "")
		if w.Code != 200 {
			t.Fatalf("%s = %d", email, w.Code)
		}
		pages = append(pages, strings.ReplaceAll(w.Body.String(), email, "ADDRESS"))
	}
	if pages[0] != pages[1] || pages[0] != pages[2] {
		t.Error("the sign-in page differs by whether the address has an account")
	}
	m := mailer(a)
	if m.count() != 3 {
		t.Fatalf("sent %d emails; a stranger must get one too, so timing says nothing", m.count())
	}
	stranger := m.msgs[0]
	if strings.Contains(stranger.Body, "/signin/verify") {
		t.Errorf("a stranger got a link: %s", stranger.Body)
	}
	for _, i := range []int{1, 2} {
		if !strings.Contains(m.msgs[i].Body, "/signin/verify") {
			t.Errorf("message %d has no link", i)
		}
	}
	if ok, _ := store.HasAccount(ctx, "stranger@example.com"); ok {
		t.Error("a stranger got an account")
	}
}

func TestOpenSignupsStillWork(t *testing.T) {
	a, _, h := newApp(t)
	post(h, "/signin", url.Values{"email": {"new@example.com"}}, "")
	if w := post(h, "/signin/verify", url.Values{"t": {mailer(a).lastLink(t)}}, ""); w.Code != 303 {
		t.Errorf("verify = %d", w.Code)
	}
}

func TestKnownBrowserIsNotLockedOutByTheServiceCap(t *testing.T) {
	a, _, h := newApp(t, func(c *Config) { c.TrustProxy = true; c.SigninEmailsPerHour = 3 })
	signinFrom(h, "198.51.100.1", "owner@example.com")
	w := post(h, "/signin/verify", url.Values{"t": {mailer(a).lastLink(t)}}, "")
	known := cookieNamed(w, browserCookie)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"} {
		signinFrom(h, ip, "s"+strings.ReplaceAll(ip, ".", "")+"@example.com")
	}
	if w := signinFrom(h, "203.0.113.5", "other@example.com"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("stranger past the cap = %d", w.Code)
	}
	if w := signinFrom(h, "198.51.100.1", "owner@example.com", known); w.Code != 200 {
		t.Errorf("known browser = %d, locked out by strangers", w.Code)
	}
}

func TestWiderNetworkLimitsIPv6(t *testing.T) {
	_, _, h := newApp(t, func(c *Config) { c.TrustProxy = true })
	limited := false
	for i := range signinPerNetwork + 2 {
		ip := "2001:db8:" + strings.ToLower(string(rune('a'+i%26))) + string(rune('a'+i/26)) + "::1"
		if w := signinFrom(h, ip, "n"+strconv.Itoa(i)+"@example.com"); w.Code == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Error("many /48s in one /32 were never limited")
	}
}

func TestAnonymousTestsHaveAGlobalCapAndCanBeOff(t *testing.T) {
	_, _, h := newApp(t, func(c *Config) { c.AnonDailyTests = 5; c.AnonDailyTotal = 2; c.TrustProxy = true })
	from := func(ip string) int {
		r := request("POST", "/test", strings.NewReader("csrf="+testCSRF), "application/x-www-form-urlencoded", "")
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set("X-Forwarded-For", ip)
		return serve(h, r).Code
	}
	for i, want := range []int{303, 303, 429} {
		if got := from("198.51.100." + string(rune('1'+i))); got != want {
			t.Errorf("network %d = %d, want %d", i, got, want)
		}
	}
	_, _, h = newApp(t, func(c *Config) { c.AnonDailyTests = 0 })
	w := post(h, "/test", nil, "")
	if w.Code != 429 || !strings.Contains(w.Body.String(), "without an account") {
		t.Errorf("anonymous tests off = %d", w.Code)
	}
}

func TestUploadIsCountedBeforeItsBodyAndOnePerNetwork(t *testing.T) {
	a, _, h := newApp(t, func(c *Config) { c.AnonDailyTests = 1 })
	// A body that is not a usable form still uses the allowance.
	r := request("POST", "/upload", strings.NewReader("garbage"), "multipart/form-data; boundary=x", "")
	serve(h, r)
	body, mw := uploadBody(t, sample(t))
	if w := postMultipart(h, "/upload", body, mw); w.Code != http.StatusTooManyRequests {
		t.Errorf("after a failed upload = %d", w.Code)
	}
	if !a.takeUploadSlot("1.2.3.4") {
		t.Fatal("no slot")
	}
	if a.takeUploadSlot("1.2.3.4") {
		t.Error("one network held two upload slots")
	}
	if !a.takeUploadSlot("5.6.7.8") {
		t.Error("another network was refused")
	}
	a.releaseUploadSlot("1.2.3.4")
	a.releaseUploadSlot("5.6.7.8")
	if len(a.uploads) != 0 || len(a.uploadIPs) != 0 {
		t.Errorf("slots left: %d %v", len(a.uploads), a.uploadIPs)
	}
}

func TestUploadBytesAndStorageAreBounded(t *testing.T) {
	_, _, h := newApp(t, func(c *Config) { c.DailyBytes = 10 })
	body, mw := uploadBody(t, sample(t))
	if w := postMultipart(h, "/upload", body, mw); w.Code != http.StatusTooManyRequests {
		t.Errorf("past the daily bytes = %d", w.Code)
	}
	_, _, h = newApp(t, func(c *Config) { c.MaxStorageBytes = 1 })
	body, mw = uploadBody(t, sample(t))
	if w := postMultipart(h, "/upload", body, mw); w.Code != http.StatusServiceUnavailable {
		t.Errorf("with the database full = %d", w.Code)
	}
}

func TestDatabaseFailureIsNotShownAsALimit(t *testing.T) {
	_, store, h := newApp(t)
	store.DB.Close()
	if w := post(h, "/test", nil, ""); w.Code != 500 || strings.Contains(w.Body.String(), "used all") {
		t.Errorf("test address with no database = %d:\n%s", w.Code, w.Body)
	}
	if w := post(h, "/signin", url.Values{"email": {"a@example.com"}}, ""); w.Code != 500 {
		t.Errorf("sign-in with no database = %d", w.Code)
	}
	if w := serve(h, request("GET", "/account", nil, "", "sometoken1234567890")); w.Code != http.StatusServiceUnavailable {
		t.Errorf("session lookup with no database = %d", w.Code)
	}
}

func TestHealthz(t *testing.T) {
	fail := false
	_, store, h := newApp(t, func(c *Config) {
		c.Health = func(context.Context) error {
			if fail {
				return errors.New("heartbeat stalled")
			}
			return nil
		}
	})
	if w := do(h, "GET", "/healthz", nil, ""); w.Code != 200 || len(w.Result().Cookies()) != 0 {
		t.Errorf("healthy = %d, %d cookies", w.Code, len(w.Result().Cookies()))
	}
	fail = true
	w := do(h, "GET", "/healthz", nil, "")
	if w.Code != 503 || strings.Contains(w.Body.String(), "heartbeat") {
		t.Errorf("failing check = %d %s", w.Code, w.Body)
	}
	fail = false
	store.DB.Close()
	if w := do(h, "GET", "/healthz", nil, ""); w.Code != 503 {
		t.Errorf("no database = %d", w.Code)
	}
}

func proUser(t *testing.T, store *db.Store, email string) (db.User, string) {
	t.Helper()
	u, session, _ := newUser(t, store, email)
	pro(t, store, u)
	return u, session
}

func alertForm(name, alert string) url.Values {
	return url.Values{"name": {name}, "time_zone": {"UTC"}, "alert_email": {alert}}
}

func TestAlertAddressNeedsConfirmation(t *testing.T) {
	a, store, h := newApp(t)
	u, session := proUser(t, store, "owner@example.com")
	ctx := context.Background()
	w := post(h, "/newsletters", alertForm("Letter", "victim@example.net"), session)
	if w.Code != 303 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	pubs, _ := store.Publications(ctx, u.ID)
	p := pubs[0]
	if p.AlertEmail != u.Email || p.AlertPending != "victim@example.net" {
		t.Fatalf("after create: %q pending %q", p.AlertEmail, p.AlertPending)
	}
	m := mailer(a)
	last := m.msgs[len(m.msgs)-1]
	if last.To != "victim@example.net" || strings.Contains(last.Body, "Letter") {
		t.Fatalf("confirmation = %+v", last)
	}
	token := last.Body[strings.Index(last.Body, "confirm?t=")+len("confirm?t="):]
	token = token[:strings.IndexAny(token, "\n ")]

	// Opening the link changes nothing, so a mail scanner cannot accept.
	if w := do(h, "GET", "/alerts/confirm?t="+token, nil, ""); w.Code != 200 {
		t.Fatalf("confirm page = %d", w.Code)
	}
	if got, _ := store.PublicationByID(ctx, p.ID); got.AlertEmail != u.Email {
		t.Fatal("following the link confirmed it")
	}
	if w := post(h, "/alerts/confirm", url.Values{"t": {token}}, ""); w.Code != 200 {
		t.Fatalf("confirm = %d", w.Code)
	}
	if got, _ := store.PublicationByID(ctx, p.ID); got.AlertEmail != "victim@example.net" || got.AlertPending != "" {
		t.Errorf("after confirming: %+v", got)
	}
}

func TestOwnAddressNeedsNoConfirmationAndEditKeepsTheAddress(t *testing.T) {
	a, store, h := newApp(t)
	u, session := proUser(t, store, "owner@example.com")
	ctx := context.Background()
	post(h, "/newsletters", alertForm("Letter", u.Email), session)
	pubs, _ := store.Publications(ctx, u.ID)
	p := pubs[0]
	before := mailer(a).count()
	if w := post(h, "/newsletters/"+p.ID, alertForm("Renamed", u.Email), session); w.Code != 303 {
		t.Fatalf("edit = %d", w.Code)
	}
	if mailer(a).count() != before {
		t.Error("the account's own address was sent a confirmation")
	}
	// Editing to a stranger holds it back, and going back withdraws that.
	post(h, "/newsletters/"+p.ID, alertForm("Renamed", "x@example.net"), session)
	got, _ := store.PublicationByID(ctx, p.ID)
	if got.AlertEmail != u.Email || got.AlertPending != "x@example.net" {
		t.Fatalf("after edit: %+v", got)
	}
	post(h, "/newsletters/"+p.ID, alertForm("Renamed", u.Email), session)
	if got, _ := store.PublicationByID(ctx, p.ID); got.AlertPending != "" {
		t.Errorf("request not withdrawn: %+v", got)
	}
}

func TestAlertConfirmationEmailsAreLimited(t *testing.T) {
	a, store, h := newApp(t)
	u, session := proUser(t, store, "owner@example.com")
	ctx := context.Background()
	post(h, "/newsletters", alertForm("Letter", u.Email), session)
	pubs, _ := store.Publications(ctx, u.ID)
	before := mailer(a).count()
	for range alertConfirmsPerTo + 3 {
		post(h, "/newsletters/"+pubs[0].ID, alertForm("Letter", "x@example.net"), session)
		if _, err := store.RequestAlertEmail(ctx, pubs[0].ID, u.ID, ""); err != nil {
			t.Fatal(err)
		}
	}
	if n := mailer(a).count() - before; n != alertConfirmsPerTo {
		t.Errorf("sent %d confirmations to one address, want %d", n, alertConfirmsPerTo)
	}
}

func TestNewsletterNameRefusesControlCharacters(t *testing.T) {
	_, store, h := newApp(t)
	_, session := proUser(t, store, "owner@example.com")
	if w := post(h, "/newsletters", alertForm("Hi\r\nBcc: x@evil.test", "owner@example.com"), session); w.Code != 400 {
		t.Errorf("name with CRLF = %d", w.Code)
	}
}

func TestOptOutPage(t *testing.T) {
	_, store, h := newApp(t)
	ctx := context.Background()
	token, err := store.AlertStopToken(ctx, "someone@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if w := do(h, "GET", "/alerts/stop/"+token, nil, ""); w.Code != 200 {
		t.Fatalf("page = %d", w.Code)
	}
	if stopped, _ := store.AlertsStopped(ctx, "someone@example.net"); stopped {
		t.Fatal("opening the link opted out, so a mail scanner could")
	}
	if w := post(h, "/alerts/stop/"+token, nil, ""); w.Code != 200 {
		t.Fatalf("stop = %d", w.Code)
	}
	if stopped, _ := store.AlertsStopped(ctx, "someone@example.net"); !stopped {
		t.Error("not stopped")
	}
	if w := do(h, "GET", "/alerts/stop/nope", nil, ""); w.Code != 404 {
		t.Errorf("unknown token = %d", w.Code)
	}
}

func TestStoppedOwnAddressNeedsConfirmationAgain(t *testing.T) {
	a, store, h := newApp(t)
	u, session := proUser(t, store, "owner@example.com")
	ctx := context.Background()
	post(h, "/newsletters", alertForm("Letter", u.Email), session)
	pubs, _ := store.Publications(ctx, u.ID)
	tok, _ := store.AlertStopToken(ctx, u.Email)
	if err := store.StopAlerts(ctx, tok); err != nil {
		t.Fatal(err)
	}
	before := mailer(a).count()
	post(h, "/newsletters/"+pubs[0].ID, alertForm("Letter", u.Email), session)
	if mailer(a).count() != before+1 {
		t.Error("an address that opted out was not asked again")
	}
}

func TestMessageKindCanBeCorrected(t *testing.T) {
	_, store, h := newApp(t)
	u, session := proUser(t, store, "owner@example.com")
	ctx := context.Background()
	post(h, "/newsletters", alertForm("Letter", u.Email), session)
	pubs, _ := store.Publications(ctx, u.ID)
	m := saveIssue(t, store, pubs[0].ID)
	path := "/newsletters/" + pubs[0].ID + "/messages/" + m.ID + "/kind"
	if w := post(h, path, url.Values{"kind": {"signup"}}, session); w.Code != 303 {
		t.Fatalf("kind = %d", w.Code)
	}
	if _, err := store.LatestIssue(ctx, pubs[0].ID); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("still an issue: %v", err)
	}
	if w := post(h, path, url.Values{"kind": {"issue"}}, session); w.Code != 303 {
		t.Fatalf("kind = %d", w.Code)
	}
	if _, err := store.LatestIssue(ctx, pubs[0].ID); err != nil {
		t.Errorf("not an issue again: %v", err)
	}
	if w := post(h, path, url.Values{"kind": {"nonsense"}}, session); w.Code != 400 {
		t.Errorf("bad kind = %d", w.Code)
	}
	_, other, _ := newUser(t, store, "other@example.com")
	if w := post(h, path, url.Values{"kind": {"signup"}}, other); w.Code != 404 {
		t.Errorf("another account = %d", w.Code)
	}
}

func TestMonitoringReportRawIsForTheOwnerOnly(t *testing.T) {
	_, store, h := newApp(t)
	u, session := proUser(t, store, "owner@example.com")
	ctx := context.Background()
	post(h, "/newsletters", alertForm("Letter", u.Email), session)
	pubs, _ := store.Publications(ctx, u.ID)
	m := saveIssue(t, store, pubs[0].ID)
	if w := do(h, "GET", "/r/"+m.ID+"/raw", nil, ""); w.Code != 404 {
		t.Errorf("stranger = %d", w.Code)
	}
	if w := serve(h, request("GET", "/r/"+m.ID+"/raw", nil, "", session)); w.Code != 200 {
		t.Errorf("owner = %d", w.Code)
	}
	if w := do(h, "GET", "/r/"+m.ID, nil, ""); w.Code != 200 || strings.Contains(w.Body.String(), "/raw") {
		t.Errorf("a shared report link offers the raw message: %d", w.Code)
	}
}

func TestCustomRedirectSchemes(t *testing.T) {
	for uri, want := range map[string]bool{
		"cursor://anysphere.cursor-mcp/oauth/callback": true,
		"com.example.app:/oauth2redirect":              true,
		"vscode://publisher.ext/cb":                    true,
		"ms-msdt:/id":                                  false,
		"evilapp://x":                                  false,
	} {
		if got := validRedirect(uri); got != want {
			t.Errorf("validRedirect(%q) = %v", uri, got)
		}
	}
}

func TestSelfHostedMetadataNamesNoOtherHost(t *testing.T) {
	_, _, h := newApp(t)
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/.well-known/mcp/server-card.json"} {
		if w := do(h, "GET", p, nil, ""); strings.Contains(w.Body.String(), "sendscore.ai") {
			t.Errorf("%s names sendscore.ai: %s", p, w.Body)
		}
	}
}
