package receiver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore-app/internal/mail"
	"github.com/sendscore/sendscore-app/internal/monitor"
	"github.com/sendscore/sendscore/engine"
)

type alerts struct {
	mu   sync.Mutex
	sent []mail.Alert
}

func (a *alerts) SendAlert(_ context.Context, m mail.Alert) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sent = append(a.sent, m)
	return nil
}

func (a *alerts) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.sent)
}

// owner makes an account.
func owner(t *testing.T, store *db.Store, email string) db.User {
	t.Helper()
	ctx := context.Background()
	link, err := store.CreateLoginToken(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := store.ConsumeLoginToken(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func publication(t *testing.T, store *db.Store, u db.User, paused bool) db.Publication {
	t.Helper()
	p := db.Publication{UserID: u.ID, Name: "Daily Tips", TimeZone: "UTC", GraceMinutes: 30, AlertEmail: u.Email, Paused: paused}
	if err := store.CreatePublication(context.Background(), &p, 5); err != nil {
		t.Fatal(err)
	}
	return p
}

// startMonitored starts a receiver that tells a monitor about publication
// messages, and returns the store, the SMTP address, and the alerts sent.
func startMonitored(t *testing.T, opts ...func(*Config)) (*db.Store, string, *alerts) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	out := &alerts{}
	cfg := Config{MailDomain: "in.test", ReportTTL: time.Hour, HistoryTTL: 365 * 24 * time.Hour, Resolver: engine.OfflineResolver{},
		Monitor: &monitor.Monitor{Store: store, Mailer: out, BaseURL: "http://test", Log: log}}
	for _, o := range opts {
		o(&cfg)
	}
	r := New(cfg, store, log)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go r.Serve(l)
	t.Cleanup(func() { r.Close() })
	return store, l.Addr().String(), out
}

func TestMonitoringAddressComparesWithThePreviousIssue(t *testing.T) {
	store, addr, out := startMonitored(t)
	u := owner(t, store, "pub@example.com")
	p := publication(t, store, u, false)
	to := "m-" + p.Token + "@in.test"
	ctx := context.Background()

	if err := deliver(addr, "bounce@real.test", to, sample(t)); err != nil {
		t.Fatal(err)
	}
	first, err := store.LatestIssue(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicationID != p.ID || first.UserID != u.ID || first.Kind != db.KindIssue || first.Token != "" {
		t.Errorf("first issue stored as publication %q user %q kind %q token %q", first.PublicationID, first.UserID, first.Kind, first.Token)
	}
	if first.Verdict.Publication != p.ID || len(first.Verdict.Changes) != 0 {
		t.Errorf("first issue: publication %q, %d changes", first.Verdict.Publication, len(first.Verdict.Changes))
	}
	if d := first.ExpiresAt.Sub(first.ReceivedAt); d != 365*24*time.Hour {
		t.Errorf("a pro account's issue is kept for %s, want 365 days", d)
	}
	if m, err := store.MessageForUser(ctx, first.ID, u.ID); err != nil || m.ID != first.ID {
		t.Errorf("the owner cannot read the report through the API: %v", err)
	}

	// The next issue drops its List-Unsubscribe header, which is worse.
	worse := strings.Replace(string(sample(t)), "List-Unsubscribe: <https://example.com/unsubscribe?u=1>\n", "", 1)
	if err := deliver(addr, "bounce@real.test", to, []byte(worse)); err != nil {
		t.Fatal(err)
	}
	second, err := store.LatestIssue(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID {
		t.Fatal("the second issue was not stored")
	}
	found := false
	for _, c := range second.Verdict.Changes {
		if c.Field == "unsub.list_unsubscribe" && c.Worsened != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("the second issue was not compared with the first: %+v", second.Verdict.Changes)
	}
	if out.count() != 1 {
		t.Errorf("sent %d alerts, want 1 for the worse issue", out.count())
	}

	// Mail for an unknown monitoring address is refused.
	err = deliver(addr, "a@b.test", "m-nope@in.test", sample(t))
	if se, ok := err.(*smtp.SMTPError); !ok || se.Code != 550 {
		t.Errorf("unknown monitoring address: err = %v, want 550", err)
	}
}

func TestPausedPublicationStillReceives(t *testing.T) {
	store, addr, out := startMonitored(t)
	u := owner(t, store, "pub@example.com")
	p := publication(t, store, u, true)
	to := "m-" + p.Token + "@in.test"
	if err := deliver(addr, "bounce@real.test", to, sample(t)); err != nil {
		t.Fatal(err)
	}
	worse := strings.Replace(string(sample(t)), "List-Unsubscribe: <https://example.com/unsubscribe?u=1>\n", "", 1)
	if err := deliver(addr, "bounce@real.test", to, []byte(worse)); err != nil {
		t.Fatal(err)
	}
	msgs, err := store.PublicationMessages(context.Background(), p.ID, 10)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("stored %d messages (%v), want 2", len(msgs), err)
	}
	if out.count() != 0 {
		t.Errorf("a paused publication sent %d alerts", out.count())
	}
}

func TestSignupMessageIsStoredButNotCompared(t *testing.T) {
	store, addr, out := startMonitored(t)
	u := owner(t, store, "pub@example.com")
	p := publication(t, store, u, false)
	to := "m-" + p.Token + "@in.test"
	if err := deliver(addr, "bounce@real.test", to, sample(t)); err != nil {
		t.Fatal(err)
	}
	confirm := strings.Replace(string(sample(t)), "Subject: Shooting into the sun", "Subject: Please confirm your subscription", 1)
	confirm = strings.Replace(confirm, "List-Unsubscribe: <https://example.com/unsubscribe?u=1>\n", "", 1)
	if err := deliver(addr, "bounce@real.test", to, []byte(confirm)); err != nil {
		t.Fatal(err)
	}
	msgs, _ := store.PublicationMessages(context.Background(), p.ID, 10)
	if len(msgs) != 2 || msgs[0].Kind != db.KindSignup || len(msgs[0].Verdict.Changes) != 0 {
		t.Fatalf("newest message: kind %q, %d changes", msgs[0].Kind, len(msgs[0].Verdict.Changes))
	}
	if out.count() != 0 {
		t.Errorf("a signup message sent %d alerts", out.count())
	}
	if latest, _ := store.LatestIssue(context.Background(), p.ID); latest.ID != msgs[1].ID {
		t.Error("a signup message became the issue to compare with")
	}
}

func TestMonitoringAddressDailyLimit(t *testing.T) {
	store, addr, _ := startMonitored(t, func(c *Config) {
		c.PublicationDailyMessages = 3
		c.MessagesPerAddress = 1
		c.DailyMessages = 1
	})
	u := owner(t, store, "pub@example.com")
	p := publication(t, store, u, false)
	to := "m-" + p.Token + "@in.test"
	// The test address limits do not apply to a monitoring address.
	for i := range 3 {
		if err := deliver(addr, "bounce@real.test", to, numbered(t, i)); err != nil {
			t.Fatalf("message %d: %v", i+1, err)
		}
	}
	err := deliver(addr, "bounce@real.test", to, numbered(t, 99))
	if se, ok := err.(*smtp.SMTPError); !ok || se.Code != 452 {
		t.Errorf("past the daily limit: err = %v, want 452", err)
	}
}
