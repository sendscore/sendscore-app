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
// remote connector needs no HTTP round trip to itself. It acts for the
// token's owner: new addresses are theirs and count against their daily
// allowance, and only their addresses and reports can be read.
type storeBackend struct {
	a    *App
	user *db.User
}

func (b storeBackend) CreateTestAddress(ctx context.Context) (mcpserver.TestAddress, error) {
	if limit, err := b.a.takeTest(ctx, b.user, ""); err != nil {
		if errors.Is(err, db.ErrLimit) {
			return mcpserver.TestAddress{}, errors.New(limitError(limit))
		}
		return mcpserver.TestAddress{}, err
	}
	addr, err := b.a.store.CreateAddressFor(ctx, b.a.cfg.AddressTTL, b.user.ID)
	if err != nil {
		return mcpserver.TestAddress{}, err
	}
	return mcpserver.TestAddress{
		Address: b.a.address(addr.Token), Token: addr.Token, ExpiresAt: addr.ExpiresAt,
		PageURL: b.a.cfg.BaseURL + "/t/" + addr.Token,
	}, nil
}

func (b storeBackend) Wait(ctx context.Context, token, after string, timeout time.Duration) (*verdict.Verdict, error) {
	// An expired address still answers while its reports are kept.
	addr, err := b.a.store.AnyAddressByToken(ctx, token)
	if err != nil {
		return nil, translate(err)
	}
	if addr.UserID != b.user.ID {
		return nil, mcpserver.ErrNotFound
	}
	m, err := b.a.wait(ctx, b.user.ID, addr, after, timeout)
	switch {
	case err == nil:
		return m.Verdict, nil
	case errors.Is(err, errNotReceived):
		return nil, mcpserver.ErrNotReceived
	case errors.Is(err, errExpired):
		return nil, errors.New(expiredMessage(addr))
	case errors.Is(err, db.ErrUnknownAfter):
		return nil, errors.New("after_report_id is not a report from this test address")
	}
	return nil, err
}

func (b storeBackend) Report(ctx context.Context, id string) (*verdict.Verdict, error) {
	m, err := b.a.store.MessageForUser(ctx, id, b.user.ID)
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

// mcpHandler is the remote connector at /api/mcp (streamable HTTP). It is
// stateless, so each request gets a server for the user mcpAuth found.
func (a *App) mcpHandler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		u := userFrom(r.Context())
		if u == nil {
			return nil
		}
		s := mcpserver.New(storeBackend{a: a, user: u}, "app")
		a.addPublicationTools(s, u)
		return s
	}, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, Logger: a.log,
		// The SDK refuses loopback requests with a public Host header, which
		// guards a laptop against DNS rebinding but is exactly what nginx
		// sends in production.
		DisableLocalhostProtection: a.cfg.BehindProxy,
	})
}
