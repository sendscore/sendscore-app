package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore/engine"
	"github.com/sendscore/sendscore/mcpserver"
)

// bearerTransport adds an API token to every request, as a connector does.
type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// connectMCP opens a session on the remote connector with token (none when
// empty).
func connectMCP(t *testing.T, url, token string) (*mcp.ClientSession, error) {
	t.Helper()
	tr := &mcp.StreamableClientTransport{Endpoint: url + "/api/mcp"}
	if token != "" {
		tr.HTTPClient = &http.Client{Transport: bearerTransport{token}}
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(context.Background(), tr, nil)
	if err == nil {
		t.Cleanup(func() { cs.Close() })
	}
	return cs, err
}

func TestRemoteMCPRequiresToken(t *testing.T) {
	_, _, h := newApp(t)
	srv := httptest.NewServer(h)
	defer srv.Close()
	if _, err := connectMCP(t, srv.URL, ""); err == nil {
		t.Error("connected without a token")
	}
	if _, err := connectMCP(t, srv.URL, "ss_live_notarealtoken"); err == nil {
		t.Error("connected with an unknown token")
	}
	req, _ := http.NewRequest("POST", srv.URL+"/api/mcp", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("no token = %d, WWW-Authenticate %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

func TestRemoteMCP(t *testing.T) {
	_, store, h := newApp(t)
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx := context.Background()
	owner, _, tok := newUser(t, store, "mcp@example.com")
	cs, err := connectMCP(t, srv.URL, tok)
	if err != nil {
		t.Fatal(err)
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_test_address", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("get_test_address: %v %+v", err, res)
	}
	var addr mcpserver.TestAddress
	b, _ := json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &addr)
	if addr.Address != "t-"+addr.Token+"@in.test" {
		t.Fatalf("address = %+v", addr)
	}
	if a, err := store.AddressByToken(ctx, addr.Token); err != nil || a.UserID != owner.ID {
		t.Fatalf("address owner = %q %v, want %s", a.UserID, err, owner.ID)
	}

	// Deliver a message the way the receiver stores one.
	v, err := engine.Analyze(ctx, sample(t), engine.Options{Resolver: engine.OfflineResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	now := store.Now()
	m := &db.Message{Token: addr.Token, Source: "smtp", ReceivedAt: now, ExpiresAt: now.Add(time.Hour), Raw: sample(t), Verdict: v}
	if err := store.SaveMessage(ctx, m); err != nil {
		t.Fatal(err)
	}

	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "wait_for_message", Arguments: map[string]any{"token": addr.Token, "timeout_seconds": 2}})
	if err != nil || res.IsError {
		t.Fatalf("wait_for_message: %v %+v", err, res)
	}
	var got mcpserver.WaitOut
	b, _ = json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &got)
	if got.Status != "received" || got.ReportID != m.ID {
		t.Errorf("wait = %+v, want report %s", got, m.ID)
	}

	// With after_report_id, the report already seen does not answer again.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "wait_for_message", Arguments: map[string]any{"token": addr.Token, "timeout_seconds": 1, "after_report_id": m.ID}})
	if err != nil || res.IsError {
		t.Fatalf("wait_for_message after: %v %+v", err, res)
	}
	got = mcpserver.WaitOut{}
	b, _ = json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &got)
	if got.Status != "not_received" {
		t.Errorf("wait after %s = %+v, want not_received", m.ID, got)
	}

	// Another account sees neither the address nor the report.
	_, _, otherTok := newUser(t, store, "other@example.com")
	other, err := connectMCP(t, srv.URL, otherTok)
	if err != nil {
		t.Fatal(err)
	}
	res, err = other.CallTool(ctx, &mcp.CallToolParams{Name: "get_report", Arguments: map[string]any{"report_id": m.ID}})
	if err != nil || !res.IsError {
		t.Errorf("another account's get_report: %v %+v", err, res)
	}
	res, err = other.CallTool(ctx, &mcp.CallToolParams{Name: "wait_for_message", Arguments: map[string]any{"token": addr.Token, "timeout_seconds": 1}})
	if err != nil || !res.IsError {
		t.Errorf("another account's wait_for_message: %v %+v", err, res)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_report", Arguments: map[string]any{"report_id": m.ID}})
	if err != nil || res.IsError {
		t.Errorf("owner's get_report: %v %+v", err, res)
	}
}

func TestRemoteMCPDailyLimit(t *testing.T) {
	_, store, h := newApp(t, func(c *Config) { c.DailyTests = 1 })
	srv := httptest.NewServer(h)
	defer srv.Close()
	_, _, tok := newUser(t, store, "limit@example.com")
	cs, err := connectMCP(t, srv.URL, tok)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_test_address", Arguments: map[string]any{}}); err != nil || res.IsError {
		t.Fatalf("first get_test_address: %v %+v", err, res)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_test_address", Arguments: map[string]any{}})
	if err != nil || !res.IsError {
		t.Fatalf("second get_test_address = %v %+v, want the limit", err, res)
	}
	b, _ := json.Marshal(res.Content)
	if !strings.Contains(string(b), "daily limit of 1") {
		t.Errorf("limit error = %s", b)
	}
}
