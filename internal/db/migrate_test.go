package db

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendscore/sendscore/verdict"
)

// oldDatabase makes a database with a schema from the project's history,
// holding one account and one message with its original in messages.raw.
func oldDatabase(t *testing.T, schemaFile string) string {
	t.Helper()
	schema, err := os.ReadFile(filepath.Join("testdata", schemaFile))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "old.db")
	d, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Exec(string(schema)); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO addresses (token, created_at, expires_at) VALUES ('oldtoken', 1, 4000000000)`,
		`INSERT INTO messages (id, token, source, received_at, expires_at, remote_ip, helo, mail_from, rcpt_to, raw, verdict)
			VALUES ('rpt_1', 'oldtoken', 'smtp', 1, 4000000000, '', '', '', '', x'6f6c64', '{}')`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// The first schema had no accounts.
	if _, err := d.Exec(`INSERT INTO users (id, email, created_at) VALUES ('usr_1', 'old@example.com', 1)`); err != nil &&
		!strings.Contains(err.Error(), "no such table") {
		t.Fatal(err)
	}
	return path
}

func TestEveryHistoricalSchemaMigrates(t *testing.T) {
	for _, file := range []string{"schema-first.sql", "schema-billing.sql"} {
		t.Run(file, func(t *testing.T) {
			path := oldDatabase(t, file)
			for range 2 { // a second start finds nothing left to do
				s, err := Open(path)
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				if raw, err := s.RawByID(ctx, "rpt_1"); err != nil || string(raw) != "old" {
					t.Errorf("raw = %q %v", raw, err)
				}
				var left int
				if err := s.DB.QueryRow(`SELECT COUNT(*) FROM messages WHERE length(raw) > 0`).Scan(&left); err != nil || left != 0 {
					t.Errorf("originals left in messages: %d %v", left, err)
				}
				if n, err := s.StoredBytes(ctx, ""); err != nil || n != 3 {
					t.Errorf("StoredBytes = %d %v", n, err)
				}
				rows, err := s.DB.Query(`SELECT name FROM sqlite_master WHERE name IN ('creem_events', 'subscriptions')
					UNION ALL SELECT name FROM pragma_table_info('users') WHERE name = 'plan'`)
				if err != nil {
					t.Fatal(err)
				}
				for rows.Next() {
					var name string
					rows.Scan(&name)
					t.Errorf("%s is still there", name)
				}
				rows.Close()
				s.Close()
			}
		})
	}
}

func TestSweepDropsAMovedOriginal(t *testing.T) {
	s, err := Open(oldDatabase(t, "schema-billing.sql"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.RawKeep = time.Hour
	ctx := context.Background()
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RawByID(ctx, "rpt_1"); err != ErrNotFound {
		t.Errorf("raw after RawKeep: %v", err)
	}
	if n, _ := s.StoredBytes(ctx, ""); n != 0 {
		t.Errorf("StoredBytes = %d after the original was dropped", n)
	}
}

func TestDeletedMailLeavesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	a, err := s.CreateAddress(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte(strings.Repeat("SECRETMAILMARKER", 2000))
	now := s.Now().UTC()
	m := &Message{Token: a.Token, Source: "smtp", ReceivedAt: now, ExpiresAt: now.Add(time.Hour), Raw: marker, Verdict: &verdict.Verdict{}}
	if err := s.SaveMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DELETE FROM messages`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("SECRETMAILMARKER")) {
		t.Error("a deleted message can still be read from the database file")
	}
}

func TestBackupIsPrivateFromTheStart(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.db")
	if err := s.Backup(ctx, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || info.Size() == 0 {
		t.Errorf("backup mode %v size %d", info.Mode().Perm(), info.Size())
	}
	if err := s.Backup(ctx, path); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("a second backup to the same path: %v", err)
	}
	// A failed backup leaves nothing behind.
	s.DB.Close()
	failed := filepath.Join(dir, "failed.db")
	if err := s.Backup(ctx, failed); err == nil {
		t.Error("no error from a closed database")
	}
	if _, err := os.Stat(failed); !os.IsNotExist(err) {
		t.Errorf("a failed backup left a file: %v", err)
	}
}

func TestPathIsEscapedInTheDatabaseURI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a?b#c%20d.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAddress(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	s.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Error("the database went to another file")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "a?b#c%20d.db") {
			t.Errorf("stray file %s", e.Name())
		}
	}
}

func TestRecipientsAreHashedWithAKeyAndForgotten(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if s.recipientHash("a@example.com") == HashToken("a@example.com") {
		t.Error("the hash has no key")
	}
	now := time.Unix(2_000_000_000, 0)
	s.Now = func() time.Time { return now }
	s.AlertKeep = 24 * time.Hour
	idle, _ := s.AlertStopToken(ctx, "idle@example.com")
	stopped, _ := s.AlertStopToken(ctx, "stopped@example.com")
	if err := s.StopAlerts(ctx, stopped); err != nil {
		t.Fatal(err)
	}
	now = now.Add(23 * time.Hour)
	active, _ := s.AlertStopToken(ctx, "active@example.com")
	again, err := s.AlertStopToken(ctx, "stopped@example.com")
	if err != nil || again != stopped {
		t.Fatalf("token changed: %v", err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	for token, want := range map[string]bool{idle: false, stopped: true, active: true} {
		if known, err := s.AlertStopKnown(ctx, token); err != nil || known != want {
			t.Errorf("known = %v %v, want %v", known, err, want)
		}
	}
}

func TestDeletingAnAccountForgetsItsRecipientsButNotOptOuts(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	link, err := s.CreateLoginToken(ctx, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := s.ConsumeLoginToken(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	p := Publication{UserID: u.ID, Name: "n", TimeZone: "UTC", AlertEmail: "kept@example.com"}
	if err := s.CreatePublication(ctx, &p, 5); err != nil {
		t.Fatal(err)
	}
	kept, _ := s.AlertStopToken(ctx, "kept@example.com")
	own, _ := s.AlertStopToken(ctx, "owner@example.com")
	out, _ := s.AlertStopToken(ctx, "out@example.com")
	if err := s.StopAlerts(ctx, out); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	for token, want := range map[string]bool{kept: false, own: false, out: true} {
		if known, _ := s.AlertStopKnown(ctx, token); known != want {
			t.Errorf("known = %v, want %v", known, want)
		}
	}
}
