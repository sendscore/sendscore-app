package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendscore/sendscore/verdict"
)

func TestTakeAllCountsAllOrNone(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	caps := []Cap{{Name: "a", Bucket: "d", Limit: 5, Keep: time.Hour}, {Name: "b", Bucket: "d", Limit: 100, N: 60, Keep: time.Hour}}
	if i, err := s.TakeAll(ctx, caps); err != nil || i != -1 {
		t.Fatalf("first = %d %v", i, err)
	}
	if i, err := s.TakeAll(ctx, caps); !errors.Is(err, ErrLimit) || i != 1 {
		t.Fatalf("second = %d %v, want the bytes cap refused", i, err)
	}
	if n, _ := s.Count(ctx, "a", "d"); n != 1 {
		t.Errorf("a refused request counted: %d", n)
	}
	if i, err := s.TakeAll(ctx, []Cap{{Name: "zero", Bucket: "d", Limit: 0}}); !errors.Is(err, ErrLimit) || i != 0 {
		t.Errorf("a limit of 0 = %d %v", i, err)
	}
}

func TestRawIsDroppedAndTheReportStays(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	s.Now = func() time.Time { return now }
	s.RawKeep = time.Hour
	m := &Message{Source: "upload", ReceivedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(time.Hour), Raw: []byte("hello"), Verdict: &verdict.Verdict{}}
	if err := s.SaveMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	if raw, err := s.RawByID(ctx, m.ID); err != nil || string(raw) != "hello" {
		t.Fatalf("raw = %q %v", raw, err)
	}
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RawByID(ctx, m.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("raw after RawKeep: %v", err)
	}
	if _, err := s.MessageByID(ctx, m.ID); err != nil {
		t.Errorf("report after RawKeep: %v", err)
	}
}

func TestSweepCarriesOnAfterAFailure(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.Take(ctx, "gone", "b", 5, -time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DROP TABLE message_raw`); err != nil {
		t.Fatal(err)
	}
	s.RawKeep = time.Hour
	if _, err := s.Sweep(ctx); err == nil {
		t.Error("Sweep hid the failure")
	}
	if n, _ := s.Count(ctx, "gone", "b"); n != 0 {
		t.Error("a failed step stopped the steps after it")
	}
}

func TestAPITokenUseIsWrittenAtMostOnceAMinute(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	s.Now = func() time.Time { return now }
	u := fillAccount(t, s, "api@example.com")
	_, token, err := s.CreateAPIToken(ctx, u.ID, "new", 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := func() (n int64) {
		if err := s.DB.QueryRow(`SELECT last_used_at FROM api_tokens WHERE token_hash = ?`, HashToken(token)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := s.UserByAPIToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	first := seen()
	now = now.Add(30 * time.Second)
	_, _ = s.UserByAPIToken(ctx, token)
	if seen() != first {
		t.Error("written twice within a minute")
	}
	now = now.Add(time.Minute)
	_, _ = s.UserByAPIToken(ctx, token)
	if seen() == first {
		t.Error("not written after a minute")
	}
}

func TestDatabaseFileIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, p := range []string{path, path + "-wal"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o", p, fi.Mode().Perm())
		}
	}
}

func TestBackupIsAWorkingCopyAndNeverOverwrites(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	fillAccount(t, s, "kept@example.com")
	path := filepath.Join(t.TempDir(), "backup.db")
	if err := s.Backup(ctx, path); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, path); err == nil {
		t.Error("a second backup overwrote the first")
	}
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if ok, err := c.HasAccount(ctx, "kept@example.com"); err != nil || !ok {
		t.Errorf("backup has the account = %v %v", ok, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode = %o", fi.Mode().Perm())
	}
}

func TestSizeBytesGrowsWithData(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	before, err := s.SizeBytes(ctx)
	if err != nil || before <= 0 {
		t.Fatalf("size = %d %v", before, err)
	}
	now := time.Now()
	m := &Message{Source: "upload", ReceivedAt: now, ExpiresAt: now.Add(time.Hour), Raw: make([]byte, 1<<20), Verdict: &verdict.Verdict{}}
	if err := s.SaveMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	if after, _ := s.SizeBytes(ctx); after < before+1<<19 {
		t.Errorf("size went from %d to %d", before, after)
	}
}

func TestAlertAddressConfirmationAndOptOut(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	u := fillAccount(t, s, "owner@example.com")
	p := &Publication{UserID: u.ID, Name: "L", AlertEmail: u.Email, TimeZone: "UTC"}
	if err := s.CreatePublication(ctx, p, 10); err != nil {
		t.Fatal(err)
	}
	tok, _ := s.AlertStopToken(ctx, "boss@example.com")
	if err := s.StopAlerts(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := s.StopAlerts(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown opt-out token: %v", err)
	}
	confirm, err := s.RequestAlertEmail(ctx, p.ID, u.ID, "boss@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.PublicationByID(ctx, p.ID); err != nil || got.AlertEmail != u.Email || got.AlertPending != "boss@example.com" {
		t.Fatalf("before confirming: %+v %v", got, err)
	}
	if e, err := s.PeekAlertConfirm(ctx, confirm); err != nil || e != "boss@example.com" {
		t.Fatalf("peek = %q %v", e, err)
	}
	if _, err := s.ConfirmAlertEmail(ctx, confirm); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmAlertEmail(ctx, confirm); !errors.Is(err, ErrNotFound) {
		t.Errorf("link used twice: %v", err)
	}
	got, _ := s.PublicationByID(ctx, p.ID)
	if got.AlertEmail != "boss@example.com" || got.AlertPending != "" {
		t.Errorf("after confirming: %+v", got)
	}
	if stopped, _ := s.AlertsStopped(ctx, "BOSS@example.com"); stopped {
		t.Error("confirming did not lift the opt-out")
	}
	again, _ := s.AlertStopToken(ctx, "boss@example.com")
	if again != tok {
		t.Error("the opt-out token changed")
	}
}

func TestAddAlertStoresCappedInOneStep(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	u := fillAccount(t, s, "caps@example.com")
	p := &Publication{UserID: u.ID, Name: "L", AlertEmail: u.Email, TimeZone: "UTC"}
	if err := s.CreatePublication(ctx, p, 10); err != nil {
		t.Fatal(err)
	}
	caps := []Cap{{Name: "c", Bucket: "d", Limit: 1, Keep: time.Hour}}
	a := &Alert{PublicationID: p.ID, Kind: "worse", Key: "1", To: u.Email}
	if added, err := s.AddAlert(ctx, a, caps...); err != nil || !added || a.Status != AlertPending {
		t.Fatalf("first = %v %v %q", added, err, a.Status)
	}
	if added, err := s.AddAlert(ctx, &Alert{PublicationID: p.ID, Kind: "worse", Key: "1", To: u.Email}, caps...); err != nil || added {
		t.Fatalf("same key = %v %v", added, err)
	}
	b := &Alert{PublicationID: p.ID, Kind: "worse", Key: "2", To: u.Email}
	if added, err := s.AddAlert(ctx, b, caps...); err != nil || !added || b.Status != AlertCapped {
		t.Fatalf("over the cap = %v %v %q", added, err, b.Status)
	}
	pending, _ := s.PendingAlerts(ctx, 10)
	for _, al := range pending {
		if al.ID == b.ID {
			t.Error("the capped alert is waiting to be sent")
		}
	}
}
