package db

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fillClients adds n clients created at created, each holding a live
// refresh token when live is set.
func fillClients(t *testing.T, s *Store, n int, created time.Time, live bool) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO users (id, email, created_at) VALUES ('usr_fill', 'fill@example.com', 0)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		id := "cli_" + NewToken(10)
		if _, err := tx.Exec(`INSERT INTO oauth_clients (id, name, redirect_uris, created_at) VALUES (?, '', '[]', ?)`, id, created.Unix()); err != nil {
			t.Fatal(err)
		}
		if live {
			tok := NewToken(32)
			if _, err := tx.Exec(`INSERT INTO oauth_tokens (selector, token_hash, kind, client_id, user_id, family, created_at, expires_at)
				VALUES (?, ?, 'refresh', ?, 'usr_fill', ?, ?, ?)`, selector(tok), HashToken(tok), id, "fam_"+id, created.Unix(), s.Now().Add(time.Hour).Unix()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestClientCapNeverDeletesTheNewClient(t *testing.T) {
	defer func(n int) { MaxOAuthClients = n }(MaxOAuthClients)
	MaxOAuthClients = 50
	s := open(t)
	ctx := context.Background()
	old := s.Now().Add(-2 * ClientPruneAge)
	// Every registration holds a live token, so none can go: the new one
	// is refused, not registered and then deleted.
	fillClients(t, s, MaxOAuthClients, old, true)
	if _, err := s.CreateOAuthClient(ctx, "New", []string{"https://a.test/cb"}); !errors.Is(err, ErrClientLimit) {
		t.Fatalf("full table: err = %v, want ErrClientLimit", err)
	}

	// Recent registrations that never connected are kept too, since a
	// client may be in the middle of signing in.
	s2 := open(t)
	fillClients(t, s2, MaxOAuthClients-1, old, true)
	fillClients(t, s2, 1, s2.Now(), false)
	if _, err := s2.CreateOAuthClient(ctx, "New", []string{"https://a.test/cb"}); !errors.Is(err, ErrClientLimit) {
		t.Fatalf("only a recent client to prune: err = %v, want ErrClientLimit", err)
	}

	// An old registration that never connected goes, and the new one stays.
	s3 := open(t)
	fillClients(t, s3, MaxOAuthClients-1, old, true)
	fillClients(t, s3, 1, old, false)
	c, err := s3.CreateOAuthClient(ctx, "New", []string{"https://a.test/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3.OAuthClientByID(ctx, c.ID); err != nil {
		t.Errorf("the new client is gone: %v", err)
	}
	var n int
	s3.DB.QueryRow(`SELECT COUNT(*) FROM oauth_clients`).Scan(&n)
	if n != MaxOAuthClients {
		t.Errorf("clients = %d, want %d", n, MaxOAuthClients)
	}
}

func TestRefreshGrace(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	fillClients(t, s, 0, s.Now(), false)
	c, _ := s.CreateOAuthClient(ctx, "C", []string{"https://a.test/cb"})
	link, _ := s.CreateLoginToken(ctx, "grace@example.com")
	u, _, _ := s.ConsumeLoginToken(ctx, link)
	code, _ := s.CreateOAuthCode(ctx, OAuthCode{ClientID: c.ID, UserID: u.ID, RedirectURI: "https://a.test/cb", RedirectGiven: true, CodeChallenge: "x"})
	first, err := s.ExchangeOAuthCode(ctx, code, func(OAuthCode) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// Concurrent refreshes of one token all succeed within the grace.
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.RefreshOAuth(ctx, first.Refresh, c.ID); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 10 {
		t.Errorf("concurrent refreshes that succeeded = %d, want 10", ok)
	}
	second, err := s.RefreshOAuth(ctx, first.Refresh, c.ID)
	if err != nil {
		t.Fatalf("retry within the grace: %v", err)
	}
	// Past the grace, reuse revokes the grant.
	s.Now = func() time.Time { return time.Now().Add(RefreshGrace + time.Second) }
	if _, err := s.RefreshOAuth(ctx, first.Refresh, c.ID); !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("reuse after the grace: err = %v", err)
	}
	if _, err := s.RefreshOAuth(ctx, second.Refresh, c.ID); !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("a pair from the grace survived the reuse: err = %v", err)
	}
}

func TestConnectedSinceSurvivesRefresh(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	start := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return start }
	c, _ := s.CreateOAuthClient(ctx, "C", []string{"https://a.test/cb"})
	link, _ := s.CreateLoginToken(ctx, "since@example.com")
	u, _, _ := s.ConsumeLoginToken(ctx, link)
	code, _ := s.CreateOAuthCode(ctx, OAuthCode{ClientID: c.ID, UserID: u.ID, RedirectURI: "https://a.test/cb", RedirectGiven: true, CodeChallenge: "x"})
	t1, err := s.ExchangeOAuthCode(ctx, code, func(OAuthCode) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return start.Add(10 * 24 * time.Hour) }
	if _, err := s.RefreshOAuth(ctx, t1.Refresh, c.ID); err != nil {
		t.Fatal(err)
	}
	apps, err := s.ConnectedApps(ctx, u.ID)
	if err != nil || len(apps) != 1 {
		t.Fatalf("apps = %v, %v", apps, err)
	}
	if !apps[0].Since.Equal(start) {
		t.Errorf("since = %v, want %v", apps[0].Since, start)
	}
}

func TestAPITokenCapUnderConcurrency(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	link, _ := s.CreateLoginToken(ctx, "cap@example.com")
	u, _, _ := s.ConsumeLoginToken(ctx, link)
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.CreateAPIToken(ctx, u.ID, "t", 25)
		}()
	}
	wg.Wait()
	toks, _ := s.APITokens(ctx, u.ID)
	if len(toks) != 25 {
		t.Errorf("tokens = %d, want 25", len(toks))
	}
	if _, _, err := s.CreateAPIToken(ctx, u.ID, "t", 25); !errors.Is(err, ErrLimit) {
		t.Errorf("26th token: err = %v", err)
	}
}

func TestKnownBrowserAndPeek(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	link, _ := s.CreateLoginTokenNext(ctx, "Peek@Example.com", "/oauth/authorize?x=1")
	email, next, err := s.PeekLoginToken(ctx, link)
	if err != nil || email != "peek@example.com" || next != "/oauth/authorize?x=1" {
		t.Errorf("peek = %q %q %v", email, next, err)
	}
	// Peeking does not use the link up.
	if _, _, err := s.ConsumeLoginToken(ctx, link); err != nil {
		t.Errorf("consume after peek: %v", err)
	}
	if _, _, err := s.PeekLoginToken(ctx, link); !errors.Is(err, ErrNotFound) {
		t.Errorf("peek after use: %v", err)
	}
	if ok, _ := s.KnownBrowser(ctx, "browser", "peek@example.com"); ok {
		t.Error("unknown browser is known")
	}
	s.RememberBrowser(ctx, "browser", "Peek@example.com", time.Hour)
	if ok, _ := s.KnownBrowser(ctx, "browser", "peek@example.com"); !ok {
		t.Error("remembered browser is not known")
	}
	if ok, _ := s.KnownBrowser(ctx, "browser", "other@example.com"); ok {
		t.Error("browser is known for another address")
	}
}
