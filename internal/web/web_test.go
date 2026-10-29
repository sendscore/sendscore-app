package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore/engine"
)

// sentMail records the emails the app sends.
type sentMail struct {
	mu   sync.Mutex
	msgs []struct{ To, Subject, Body string }
}

func (m *sentMail) Send(_ context.Context, to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, struct{ To, Subject, Body string }{to, subject, body})
	return nil
}

func (m *sentMail) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.msgs)
}

// lastLink returns the sign-in token from the newest email.
func (m *sentMail) lastLink(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.msgs) == 0 {
		t.Fatal("no email sent")
	}
	body := m.msgs[len(m.msgs)-1].Body
	i := strings.Index(body, "/signin/verify?t=")
	if i < 0 {
		t.Fatalf("no sign-in link in %q", body)
	}
	return strings.Fields(body[i+len("/signin/verify?t="):])[0]
}

func newApp(t *testing.T, opts ...func(*Config)) (*App, *db.Store, http.Handler) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := Config{BaseURL: "http://test", MailDomain: "in.test", AddressTTL: time.Hour, ReportTTL: time.Hour,
		MaxWait: 2 * time.Second, Resolver: engine.OfflineResolver{}, Mailer: &sentMail{},
		FreeDailyTests: 25, AnonDailyTests: 5}
	for _, o := range opts {
		o(&cfg)
	}
	a, err := New(cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return a, store, a.Routes()
}

func mailer(a *App) *sentMail { return a.cfg.Mailer.(*sentMail) }

func do(h http.Handler, method, path string, body io.Reader, ctype string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// testCSRF is the CSRF cookie and field the form helpers send.
const testCSRF = "csrftesttokencsrftesttokencsrftesttoken"

// request builds a browser request: the CSRF cookie, the Origin of the site,
// and any session cookie.
func request(method, path string, body io.Reader, ctype, session string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("Origin", "http://test")
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: testCSRF})
	if session != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	}
	return req
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// post submits a form the way a browser on the site does, with the CSRF
// token, as the session's user when session is set.
func post(h http.Handler, path string, vals url.Values, session string) *httptest.ResponseRecorder {
	if vals == nil {
		vals = url.Values{}
	}
	vals.Set("csrf", testCSRF)
	return serve(h, request("POST", path, strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded", session))
}

// postMultipart submits a multipart form (an upload) with the CSRF token.
func postMultipart(h http.Handler, path string, body *bytes.Buffer, mw *multipart.Writer) *httptest.ResponseRecorder {
	return serve(h, request("POST", path, body, mw.FormDataContentType(), ""))
}

// newUser signs up an account directly in the store and returns it with a
// session and an API token.
func newUser(t *testing.T, store *db.Store, email string) (u db.User, session, token string) {
	t.Helper()
	ctx := context.Background()
	link, err := store.CreateLoginToken(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	u, session, err = store.ConsumeLoginToken(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err = store.CreateAPIToken(ctx, u.ID, "test", 25)
	if err != nil {
		t.Fatal(err)
	}
	return u, session, token
}

// apiDo calls the JSON API with an API token (none when token is empty).
func apiDo(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return serve(h, req)
}

func sample(t *testing.T) []byte {
	raw, err := os.ReadFile("../../../sendscore/testdata/sample.eml")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPagesAndCSP(t *testing.T) {
	_, _, h := newApp(t)
	for _, p := range []string{"/", "/upload", "/signin", "/assets/app.css"} {
		w := do(h, "GET", p, nil, "")
		if w.Code != 200 {
			t.Errorf("%s = %d", p, w.Code)
		}
		csp := w.Header().Get("Content-Security-Policy")
		if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "script-src 'self'") {
			t.Errorf("%s CSP = %q", p, csp)
		}
		if strings.HasSuffix(p, ".css") {
			continue
		}
		body := w.Body.String()
		if strings.Contains(body, "<script>") || strings.Contains(body, "style=") || strings.Contains(body, " on") && strings.Contains(body, "onclick") {
			t.Errorf("%s has inline script or style", p)
		}
	}
	if w := do(h, "GET", "/r/rpt_missing", nil, ""); w.Code != 404 {
		t.Errorf("missing report = %d", w.Code)
	}
}

func TestTestAddressFlow(t *testing.T) {
	a, store, h := newApp(t)
	_, _, tok := newUser(t, store, "flow@example.com")
	w := apiDo(h, "POST", "/api/v1/test-addresses", tok)
	if w.Code != 201 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	var created struct{ Address, Token string }
	json.Unmarshal(w.Body.Bytes(), &created)
	if created.Address != "t-"+created.Token+"@in.test" {
		t.Errorf("address = %q", created.Address)
	}

	// Nothing yet: the wait times out quietly.
	w = apiDo(h, "GET", "/api/v1/test-addresses/"+created.Token+"/wait?timeout=1", tok)
	if !strings.Contains(w.Body.String(), `"not_received"`) {
		t.Errorf("wait before mail = %s", w.Body)
	}
	if w := do(h, "GET", "/t/"+created.Token, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), created.Address) {
		t.Errorf("address page = %d", w.Code)
	}

	// Store a message as the receiver would, then wait again.
	v, err := engine.Analyze(context.Background(), sample(t), engine.Options{Resolver: engine.OfflineResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	now := store.Now()
	m := &db.Message{Token: created.Token, Source: "smtp", ReceivedAt: now, ExpiresAt: now.Add(time.Hour), Raw: sample(t), Verdict: v}
	if err := store.SaveMessage(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	w = apiDo(h, "GET", "/api/v1/test-addresses/"+created.Token+"/wait?timeout=1", tok)
	var got struct {
		Status   string `json:"status"`
		ReportID string `json:"report_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &got)
	if got.Status != "received" || got.ReportID != m.ID {
		t.Errorf("wait after mail = %s", w.Body)
	}
	if w := do(h, "GET", "/t/"+created.Token, nil, ""); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/r/"+m.ID {
		t.Errorf("address page after mail = %d %s", w.Code, w.Header().Get("Location"))
	}
	w = do(h, "GET", "/r/"+m.ID, nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Shooting into the sun") || !strings.Contains(w.Body.String(), "Fix first") {
		t.Errorf("report page = %d", w.Code)
	}
	if w := apiDo(h, "GET", "/api/v1/reports/"+m.ID, tok); w.Code != 200 || !strings.Contains(w.Body.String(), `"schema": "sendscore.verdict/v1"`) {
		t.Errorf("report json = %d", w.Code)
	}
	// The report page's JSON link works by its link alone, like the page.
	if w := do(h, "GET", "/r/"+m.ID+"/json", nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"schema": "sendscore.verdict/v1"`) {
		t.Errorf("report page json = %d", w.Code)
	}
	_ = a
}

func TestUpload(t *testing.T) {
	_, _, h := newApp(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("message", "issue.eml")
	fw.Write(sample(t))
	mw.WriteField("ip", "")
	mw.WriteField("csrf", testCSRF)
	mw.Close()
	w := postMultipart(h, "/upload", &body, mw)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/r/rpt_") {
		t.Fatalf("upload = %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", w.Header().Get("Location"), nil, ""); w.Code != 200 {
		t.Errorf("report after upload = %d", w.Code)
	}

	body.Reset()
	mw = multipart.NewWriter(&body)
	fw, _ = mw.CreateFormFile("message", "junk.eml")
	fw.Write([]byte("not an email"))
	mw.WriteField("csrf", testCSRF)
	mw.Close()
	if w := postMultipart(h, "/upload", &body, mw); w.Code != 400 {
		t.Errorf("junk upload = %d", w.Code)
	}
}

func saveMessage(t *testing.T, store *db.Store, token, source string) *db.Message {
	t.Helper()
	v, err := engine.Analyze(context.Background(), sample(t), engine.Options{Resolver: engine.OfflineResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	now := store.Now()
	m := &db.Message{Token: token, Source: source, ReceivedAt: now, ExpiresAt: now.Add(time.Hour), Raw: sample(t), Verdict: v}
	if err := store.SaveMessage(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestWaitAfter(t *testing.T) {
	_, store, h := newApp(t)
	u, _, tok := newUser(t, store, "after@example.com")
	addr, _ := store.CreateAddressFor(context.Background(), time.Hour, u.ID)
	first := saveMessage(t, store, addr.Token, "smtp")
	wait := "/api/v1/test-addresses/" + addr.Token + "/wait?timeout=1"

	// Without after, the newest message counts, even one already there.
	if w := apiDo(h, "GET", wait, tok); !strings.Contains(w.Body.String(), first.ID) {
		t.Errorf("wait = %s, want %s", w.Body, first.ID)
	}
	// After the first report, the old one no longer answers.
	if w := apiDo(h, "GET", wait+"&after="+first.ID, tok); !strings.Contains(w.Body.String(), `"not_received"`) {
		t.Errorf("wait after first = %s", w.Body)
	}
	if w := do(h, "GET", "/t/"+addr.Token+"?after="+first.ID, nil, ""); w.Code != 200 {
		t.Errorf("address page after first = %d", w.Code)
	}
	second := saveMessage(t, store, addr.Token, "smtp")
	if w := apiDo(h, "GET", wait+"&after="+first.ID, tok); !strings.Contains(w.Body.String(), second.ID) {
		t.Errorf("wait after first = %s, want %s", w.Body, second.ID)
	}
	if w := do(h, "GET", "/t/"+addr.Token+"?after="+first.ID, nil, ""); w.Header().Get("Location") != "/r/"+second.ID {
		t.Errorf("address page after first = %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := apiDo(h, "GET", wait+"&after=rpt_other", tok); w.Code != 400 {
		t.Errorf("wait after an unknown report = %d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", "/r/"+second.ID+"/raw", nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "Shooting into the sun") {
		t.Errorf("raw = %d", w.Code)
	}
	// The report page offers its owner a link to wait for the next send.
	_, session, _ := newUser(t, store, "after@example.com")
	if w := serve(h, request("GET", "/r/"+second.ID, nil, "", session)); !strings.Contains(w.Body.String(), "/t/"+addr.Token+"?after="+second.ID) {
		t.Error("report page has no link to wait for the next send")
	}
}

func TestStopWaitsAnswersOpenPolls(t *testing.T) {
	a, store, h := newApp(t)
	a.cfg.MaxWait = time.Minute
	u, _, tok := newUser(t, store, "stop@example.com")
	addr, _ := store.CreateAddressFor(context.Background(), time.Hour, u.ID)
	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- apiDo(h, "GET", "/api/v1/test-addresses/"+addr.Token+"/wait?timeout=50", tok) }()
	time.Sleep(100 * time.Millisecond)
	a.StopWaits()
	select {
	case w := <-done:
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"not_received"`) {
			t.Errorf("wait at shutdown = %d %s", w.Code, w.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StopWaits did not end the long poll")
	}
}

func TestUploadTooLarge(t *testing.T) {
	_, _, h := newApp(t)
	for _, size := range []int{MaxUploadBytes + 1, MaxUploadBytes + 2<<20} {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, _ := mw.CreateFormFile("message", "big.eml")
		fw.Write(bytes.Repeat([]byte("a"), size))
		mw.WriteField("csrf", testCSRF)
		mw.Close()
		w := postMultipart(h, "/upload", &body, mw)
		if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "larger than 25 MB") {
			t.Errorf("%d byte upload = %d", size, w.Code)
		}
	}
}

func TestUploadReportSaysSupplied(t *testing.T) {
	_, _, h := newApp(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("message", "issue.eml")
	fw.Write(sample(t))
	mw.WriteField("ip", "203.0.113.10")
	mw.WriteField("mail_from", "bounce@example.com")
	mw.WriteField("csrf", testCSRF)
	mw.Close()
	w := postMultipart(h, "/upload", &body, mw)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload = %d %s", w.Code, w.Body)
	}
	page := do(h, "GET", w.Header().Get("Location"), nil, "").Body.String()
	for _, want := range []string{"uploaded file, not a message SendScore received", "203.0.113.10 (supplied)", "bounce@example.com (supplied)"} {
		if !strings.Contains(page, want) {
			t.Errorf("upload report lacks %q", want)
		}
	}
	if strings.Contains(page, "Fixed something?") {
		t.Error("upload report offers to wait at a test address")
	}
}
