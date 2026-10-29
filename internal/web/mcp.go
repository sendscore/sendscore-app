package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore/mcpserver"
	"github.com/sendscore/sendscore/verdict"
)

// storeBackend serves the MCP tools straight from the database, so the
// remote connector needs no HTTP round trip to itself.
type storeBackend struct{ a *App }

func (b storeBackend) CreateTestAddress(ctx context.Context) (mcpserver.TestAddress, error) {
	addr, err := b.a.store.CreateAddress(ctx, b.a.cfg.AddressTTL)
	if err != nil {
		return mcpserver.TestAddress{}, err
	}
	return mcpserver.TestAddress{
		Address: b.a.address(addr.Token), Token: addr.Token, ExpiresAt: addr.ExpiresAt,
		PageURL: b.a.cfg.BaseURL + "/t/" + addr.Token,
	}, nil
}

func (b storeBackend) Wait(ctx context.Context, token string, timeout time.Duration) (*verdict.Verdict, error) {
	if _, err := b.a.store.AddressByToken(ctx, token); err != nil {
		return nil, translate(err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		m, err := b.a.store.LatestForToken(ctx, token)
		if err == nil {
			return m.Verdict, nil
		}
		if !errors.Is(err, db.ErrNotFound) && ctx.Err() == nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, mcpserver.ErrNotReceived
		case <-tick.C:
		}
	}
}

func (b storeBackend) Report(ctx context.Context, id string) (*verdict.Verdict, error) {
	m, err := b.a.store.MessageByID(ctx, id)
	if err != nil {
		return nil, translate(err)
	}
	return m.Verdict, nil
}

func translate(err error) error {
	if errors.Is(err, db.ErrNotFound) {
		return mcpserver.ErrNotFound
	}
	return err
}

// mcpHandler is the remote connector at /api/mcp (streamable HTTP).
func (a *App) mcpHandler() http.Handler {
	srv := mcpserver.New(storeBackend{a}, "app")
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, Logger: a.log,
		// The SDK refuses loopback requests with a public Host header, which
		// guards a laptop against DNS rebinding but is exactly what nginx
		// sends in production.
		DisableLocalhostProtection: a.cfg.BehindProxy,
	})
}
