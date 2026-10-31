package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore-app/internal/mail"
	"github.com/sendscore/sendscore/verdict"
)

// clock is a fake clock for the store.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// outbox is a fake alert sender. While fail is set, sends fail.
type outbox struct {
	mu   sync.Mutex
	sent []mail.Alert
	fail bool
}

func (o *outbox) SendAlert(_ context.Context, a mail.Alert) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail {
		return errors.New("ses is down")
	}
	o.sent = append(o.sent, a)
	return nil
}

func (o *outbox) all() []mail.Alert {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]mail.Alert(nil), o.sent...)
}

func (o *outbox) setFail(f bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.fail = f
}

type fixture struct {
	store *db.Store
	clock *clock
	out   *outbox
	mon   *Monitor
	user  db.User
}

func setup(t *testing.T, start time.Time) *fixture {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	c := &clock{now: start}
	store.Now = c.Now
	ctx := context.Background()
	link, err := store.CreateLoginToken(ctx, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := store.ConsumeLoginToken(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{store: store, clock: c, out: &outbox{}, user: u}
	f.mon = f.newMonitor()
	return f
}

// newMonitor is a fresh monitor over the same database, as after a restart.
func (f *fixture) newMonitor() *Monitor {
	return &Monitor{Store: f.store, Mailer: f.out, BaseURL: "http://test", PerDay: 10,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func (f *fixture) publication(t *testing.T, p db.Publication) db.Publication {
	t.Helper()
	p.UserID = f.user.ID
	if p.Name == "" {
		p.Name = "The Friday Letter"
	}
	if p.TimeZone == "" {
		p.TimeZone = "UTC"
	}
	p.AlertEmail = "alerts@example.com"
	if err := f.store.CreatePublication(context.Background(), &p, 5); err != nil {
		t.Fatal(err)
	}
	return p
}

func good() *verdict.Verdict {
	return &verdict.Verdict{Verdict: verdict.Pass, ReadyToSend: true, Message: verdict.Message{Subject: "Issue"},
		Checks: []verdict.Check{{ID: "auth.dkim", Title: "DKIM signature", Status: verdict.Pass}}, Changes: []verdict.Change{}}
}

func bad() *verdict.Verdict {
	return &verdict.Verdict{Verdict: verdict.Fail, ReadyToSend: false, Message: verdict.Message{Subject: "Issue"},
		Checks:  []verdict.Check{{ID: "auth.dkim", Title: "DKIM signature", Status: verdict.Fail}},
		Changes: []verdict.Change{{Field: "auth.dkim", Before: "pass", After: "fail", Worsened: "auth.dkim"}}}
}

// receive saves an issue as the receiver does and tells the monitor.
func (f *fixture) receive(t *testing.T, p db.Publication, v *verdict.Verdict) *db.Message {
	t.Helper()
	ctx := context.Background()
	now := f.clock.Now()
	m := &db.Message{PublicationID: p.ID, UserID: p.UserID, Kind: db.KindIssue, Source: "smtp", ReceivedAt: now,
		ExpiresAt: now.Add(365 * 24 * time.Hour), Raw: []byte("raw"), Verdict: v}
	if s, ok := ScheduleOf(p); ok {
		m.SlotAt, m.Late = s.Place(now)
	}
	prev, err := f.store.LatestIssue(ctx, p.ID)
	if errors.Is(err, db.ErrNotFound) {
		prev = nil
	} else if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	f.mon.Received(ctx, p, m, prev)
	return m
}

func kinds(t *testing.T, f *fixture, p db.Publication) []string {
	t.Helper()
	as, err := f.store.Alerts(context.Background(), p.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, a := range as {
		out = append(out, a.Kind+":"+a.Status)
	}
	return out
}

func TestWorseIssueAlertsOnce(t *testing.T) {
	f := setup(t, utc("2026-10-26T09:00:00Z"))
	p := f.publication(t, db.Publication{})
	f.receive(t, p, good())
	f.receive(t, p, good())
	if n := len(f.out.all()); n != 0 {
		t.Fatalf("%d alerts for issues that did not get worse", n)
	}
	m := f.receive(t, p, bad())
	sent := f.out.all()
	if len(sent) != 1 {
		t.Fatalf("sent %d alerts, want 1", len(sent))
	}
	a := sent[0]
	if a.To != "alerts@example.com" || !strings.Contains(a.Subject, "worse") {
		t.Errorf("alert to %q subject %q", a.To, a.Subject)
	}
	for _, want := range []string{"DKIM signature now fails (auth.dkim).", "which made auth.dkim worse", "http://test/r/" + m.ID,
		"http://test/newsletters/" + p.ID, "You get this email because"} {
		if !strings.Contains(a.Text, want) {
			t.Errorf("text is missing %q:\n%s", want, a.Text)
		}
	}
	if !strings.Contains(a.HTML, `href="http://test/newsletters/`+p.ID+`"`) || strings.Contains(a.HTML, "<img") {
		t.Errorf("html:\n%s", a.HTML)
	}
	// The same report again (a retry, or a second heartbeat) sends nothing.
	f.mon.Received(context.Background(), p, m, m)
	f.mon.Tick(context.Background())
	if n := len(f.out.all()); n != 1 {
		t.Errorf("sent %d alerts after a repeat, want 1", n)
	}
	// A further failing issue is not worse than the failing one before it.
	still := bad()
	still.Changes = []verdict.Change{}
	f.receive(t, p, still)
	if n := len(f.out.all()); n != 1 {
		t.Errorf("sent %d alerts for an issue no worse than the last, want 1", n)
	}
}

func TestPausedPublicationSendsNothing(t *testing.T) {
	f := setup(t, utc("2026-10-26T06:00:00Z"))
	p := f.publication(t, db.Publication{Days: everyDay, At: "07:00", GraceMinutes: 30, Paused: true})
	f.clock.Set(utc("2026-10-26T07:00:00Z"))
	f.receive(t, p, good())
	f.receive(t, p, bad()) // worse, and a second issue in the slot
	// A day later the next issue is missed.
	f.clock.Set(utc("2026-10-27T08:00:00Z"))
	f.mon.Tick(context.Background())
	if n := len(f.out.all()); n != 0 {
		t.Errorf("a paused publication sent %d alerts", n)
	}
	if k := kinds(t, f, p); len(k) != 0 {
		t.Errorf("alerts recorded for a paused publication: %v", k)
	}
}

func TestMissedIssueAlertsOnceAndSurvivesRestart(t *testing.T) {
	f := setup(t, utc("2026-10-26T06:00:00Z"))
	// Mondays at 07:00 in Toronto (11:00 UTC in summer time), 30 minutes of grace.
	p := f.publication(t, db.Publication{Days: 1 << 1, At: "07:00", TimeZone: "America/Toronto", GraceMinutes: 30})
	ctx := context.Background()

	f.clock.Set(utc("2026-10-26T11:29:00Z"))
	f.mon.Tick(ctx)
	if n := len(f.out.all()); n != 0 {
		t.Fatalf("alerted %d times before the deadline", n)
	}
	// At the deadline an issue may still be being checked, so it waits.
	f.clock.Set(utc("2026-10-26T11:30:00Z"))
	f.mon.Tick(ctx)
	if n := len(f.out.all()); n != 0 {
		t.Fatalf("alerted %d times with an issue possibly still being checked", n)
	}
	f.clock.Set(utc("2026-10-26T11:32:00Z"))
	f.mon.Tick(ctx)
	sent := f.out.all()
	if len(sent) != 1 || !strings.Contains(sent[0].Subject, "has not arrived") {
		t.Fatalf("sent %v, want one missed alert", sent)
	}
	if !strings.Contains(sent[0].Text, "Monday 26 Oct 2026 at 07:00 EDT") {
		t.Errorf("the alert does not give the local time:\n%s", sent[0].Text)
	}
	// Every minute after, and after a restart, nothing more is sent.
	for i := range 5 {
		f.clock.Set(utc("2026-10-26T11:33:00Z").Add(time.Duration(i) * time.Minute))
		f.mon.Tick(ctx)
	}
	f.mon = f.newMonitor()
	f.mon.Tick(ctx)
	if n := len(f.out.all()); n != 1 {
		t.Errorf("sent %d alerts for one missed slot, want 1", n)
	}
	// The issue then arrives late, and is marked so.
	f.clock.Set(utc("2026-10-26T13:00:00Z"))
	m := f.receive(t, p, good())
	if !m.Late || !m.SlotAt.Equal(utc("2026-10-26T11:00:00Z")) {
		t.Errorf("late issue: slot %s late %v", m.SlotAt, m.Late)
	}
	// The next Monday is after the change to winter time: 07:00 EST is
	// 12:00 UTC, so 11:30 UTC is not yet late.
	f.clock.Set(utc("2026-11-02T11:30:00Z"))
	f.mon.Tick(ctx)
	if n := len(f.out.all()); n != 1 {
		t.Errorf("alerted at the summer time deadline in winter")
	}
	f.clock.Set(utc("2026-11-02T12:32:00Z"))
	f.mon.Tick(ctx)
	if n := len(f.out.all()); n != 2 {
		t.Errorf("sent %d alerts, want a second one for 2 November", n)
	}
}

func TestMissedIgnoresSlotsBeforeTheScheduleAndLateArrivals(t *testing.T) {
	ctx := context.Background()
	// Made after Monday's deadline: that Monday is not reported.
	f := setup(t, utc("2026-10-26T12:00:00Z"))
	p := f.publication(t, db.Publication{Days: 1 << 1, At: "07:00", GraceMinutes: 30})
	f.mon.Tick(ctx)
	if n := len(f.out.all()); n != 0 {
		t.Errorf("alerted for a slot before the publication existed")
	}
	// Next Monday the heartbeat is down at the deadline, and the issue
	// arrives late before it runs again: no missed alert.
	f.clock.Set(utc("2026-11-02T08:00:00Z"))
	f.receive(t, p, good())
	f.clock.Set(utc("2026-11-02T08:01:00Z"))
	f.mon.Tick(ctx)
	if n := len(f.out.all()); n != 0 {
		t.Errorf("alerted for an issue that arrived late")
	}
	// An outage longer than a day does not send a stale alert.
	f.clock.Set(utc("2026-11-10T12:00:00Z"))
	f.mon.Tick(ctx)
	if n := len(f.out.all()); n != 0 {
		t.Errorf("sent a stale missed alert")
	}
}

func TestDuplicateIssueAlertsOnce(t *testing.T) {
	f := setup(t, utc("2026-10-26T06:00:00Z"))
	p := f.publication(t, db.Publication{Days: everyDay, At: "07:00", GraceMinutes: 30})
	f.clock.Set(utc("2026-10-26T07:01:00Z"))
	f.receive(t, p, good())
	f.clock.Set(utc("2026-10-26T07:05:00Z"))
	f.receive(t, p, good())
	f.clock.Set(utc("2026-10-26T07:09:00Z"))
	f.receive(t, p, good())
	sent := f.out.all()
	if len(sent) != 1 || !strings.Contains(sent[0].Subject, "Two issues") {
		t.Fatalf("sent %v, want one duplicate alert", sent)
	}
	// The next day's single issue is fine.
	f.clock.Set(utc("2026-10-27T07:00:00Z"))
	f.receive(t, p, good())
	if n := len(f.out.all()); n != 1 {
		t.Errorf("sent %d alerts, want 1", n)
	}
}

func TestSignupMessagesAreNotAlerted(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	p := f.publication(t, db.Publication{})
	m := &db.Message{PublicationID: p.ID, UserID: p.UserID, Kind: db.KindSignup, Source: "smtp", ReceivedAt: f.clock.Now(),
		ExpiresAt: f.clock.Now().Add(time.Hour), Raw: []byte("raw"), Verdict: bad()}
	if err := f.store.SaveMessage(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	f.mon.Received(context.Background(), p, m, &db.Message{Verdict: good()})
	if n := len(f.out.all()); n != 0 {
		t.Errorf("a signup message sent %d alerts", n)
	}
}

func TestAlertsAreCappedPerDay(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	f.mon.PerDay = 2
	p := f.publication(t, db.Publication{})
	f.receive(t, p, good())
	for range 3 {
		f.receive(t, p, bad())
		f.receive(t, p, good())
	}
	if n := len(f.out.all()); n != 2 {
		t.Errorf("sent %d alerts, want the cap of 2", n)
	}
	k := kinds(t, f, p)
	if len(k) != 3 || k[0] != "worse:capped" {
		t.Errorf("alerts = %v, want the third capped", k)
	}
}

func TestFailedAlertIsRetriedByTheHeartbeat(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	p := f.publication(t, db.Publication{})
	f.receive(t, p, good())
	f.out.setFail(true)
	f.receive(t, p, bad())
	if k := kinds(t, f, p); len(k) != 1 || k[0] != "worse:pending" {
		t.Fatalf("alerts = %v, want one pending", k)
	}
	f.out.setFail(false)
	f.mon = f.newMonitor() // as after a restart
	f.clock.Set(f.clock.Now().Add(time.Minute))
	f.mon.Tick(context.Background())
	f.mon.Tick(context.Background())
	if n := len(f.out.all()); n != 1 {
		t.Errorf("sent %d, want the retried alert once", n)
	}
	if k := kinds(t, f, p); k[0] != "worse:sent" {
		t.Errorf("alerts = %v", k)
	}
}

func TestHalfSentAlertIsNotResent(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	p := f.publication(t, db.Publication{})
	ctx := context.Background()
	a := &db.Alert{PublicationID: p.ID, Kind: KindWorse, Key: "report:x", To: "alerts@example.com", Subject: "s", Text: "t", HTML: "h"}
	if _, err := f.store.AddAlert(ctx, a); err != nil {
		t.Fatal(err)
	}
	// The process claimed it, then stopped before recording the result.
	if _, err := f.store.ClaimAlert(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	f.clock.Set(f.clock.Now().Add(10 * time.Minute))
	f.newMonitor().Tick(ctx)
	if n := len(f.out.all()); n != 0 {
		t.Errorf("a half sent alert was sent again")
	}
	if k := kinds(t, f, p); k[0] != "worse:failed" {
		t.Errorf("alerts = %v", k)
	}
}
