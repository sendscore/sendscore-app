package web

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore/engine"
	"github.com/sendscore/sendscore/mcpserver"
)

func TestRemoteMCP(t *testing.T) {
	_, store, h := newApp(t)
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx := context.Background()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/api/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

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
}
