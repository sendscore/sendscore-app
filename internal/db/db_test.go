package db

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendscore/sendscore/verdict"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func save(t *testing.T, s *Store, token string) *Message {
	t.Helper()
	now := s.Now()
	m := &Message{Token: token, Source: "smtp", ReceivedAt: now, ExpiresAt: now.Add(time.Hour), Raw: []byte("raw"), Verdict: &verdict.Verdict{}}
	if err := s.SaveMessage(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestLatestForTokenAfter(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	a, _ := s.CreateAddress(ctx, time.Hour)
	other, _ := s.CreateAddress(ctx, time.Hour)
	first := save(t, s, a.Token)
	foreign := save(t, s, other.Token)

	if m, err := s.LatestForToken(ctx, a.Token, ""); err != nil || m.ID != first.ID {
		t.Errorf("latest = %v %v, want %s", m, err, first.ID)
	}
	if _, err := s.LatestForToken(ctx, a.Token, first.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after the only message: err = %v, want ErrNotFound", err)
	}
	if _, err := s.LatestForToken(ctx, a.Token, foreign.ID); !errors.Is(err, ErrUnknownAfter) {
		t.Errorf("after another address's report: err = %v, want ErrUnknownAfter", err)
	}
	second := save(t, s, a.Token)
	if m, err := s.LatestForToken(ctx, a.Token, first.ID); err != nil || m.ID != second.ID {
		t.Errorf("after first = %v %v, want %s", m, err, second.ID)
	}
	if m, _ := s.LatestForToken(ctx, a.Token, ""); m.Raw != nil {
		t.Error("LatestForToken loaded the raw message")
	}
	if raw, err := s.RawByID(ctx, second.ID); err != nil || string(raw) != "raw" {
		t.Errorf("raw = %q %v", raw, err)
	}
}

func TestSweepKeepsRecentlyExpiredAddresses(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	recent, _ := s.CreateAddress(ctx, -time.Minute)
	old, _ := s.CreateAddress(ctx, -AddressGrace-time.Minute)
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	count := func(token string) (n int) {
		s.DB.QueryRow(`SELECT COUNT(*) FROM addresses WHERE token = ?`, token).Scan(&n)
		return n
	}
	if count(recent.Token) != 1 {
		t.Error("swept an address inside the grace period")
	}
	if count(old.Token) != 0 {
		t.Error("kept an address past the grace period")
	}
	// A message whose RCPT was accepted just before expiry can still be saved.
	save(t, s, recent.Token)
}
