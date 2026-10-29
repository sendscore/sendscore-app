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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore/engine"
)

func newApp(t *testing.T) (*App, *db.Store, http.Handler) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	a, err := New(Config{BaseURL: "http://test", MailDomain: "in.test", AddressTTL: time.Hour, ReportTTL: time.Hour,
		MaxWait: 2 * time.Second, Resolver: engine.OfflineResolver{}}, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return a, store, a.Routes()
}

func do(h http.Handler, method, path string, body io.Reader, ctype string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
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
	for _, p := range []string{"/", "/upload", "/assets/app.css"} {
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
	w := do(h, "POST", "/api/v1/test-addresses", nil, "")
	if w.Code != 201 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	var created struct{ Address, Token string }
	json.Unmarshal(w.Body.Bytes(), &created)
	if created.Address != "t-"+created.Token+"@in.test" {
		t.Errorf("address = %q", created.Address)
	}

	// Nothing yet: the wait times out quietly.
	w = do(h, "GET", "/api/v1/test-addresses/"+created.Token+"/wait?timeout=1", nil, "")
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
	w = do(h, "GET", "/api/v1/test-addresses/"+created.Token+"/wait?timeout=1", nil, "")
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
	if w := do(h, "GET", "/api/v1/reports/"+m.ID, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"schema": "sendscore.verdict/v1"`) {
		t.Errorf("report json = %d", w.Code)
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
	mw.Close()
	w := do(h, "POST", "/upload", &body, mw.FormDataContentType())
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
	mw.Close()
	if w := do(h, "POST", "/upload", &body, mw.FormDataContentType()); w.Code != 400 {
		t.Errorf("junk upload = %d", w.Code)
	}
}
