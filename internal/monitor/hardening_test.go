package monitor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore-app/internal/mail"
	"github.com/sendscore/sendscore/verdict"
)

func TestAlertOutlivesALongOutage(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	ctx := context.Background()
	p := f.publication(t, db.Publication{})
	f.receive(t, p, good())
	f.out.setFail(true)
	f.receive(t, p, bad())
	// Six hours of heartbeats with SES down.
	for range 6 * 60 {
		f.clock.Set(f.clock.Now().Add(time.Minute))
		f.mon.Tick(ctx)
	}
	if k := kinds(t, f, p); k[0] != "worse:pending" {
		t.Fatalf("after six hours: %v", k)
	}
	f.out.setFail(false)
	for range 4*60 + 1 {
		f.clock.Set(f.clock.Now().Add(time.Minute))
		f.mon.Tick(ctx)
	}
	if n := len(f.out.all()); n != 1 {
		t.Errorf("sent %d after SES came back", n)
	}
}

func TestAlertRetriesBackOff(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	ctx := context.Background()
	p := f.publication(t, db.Publication{})
	f.receive(t, p, good())
	f.out.setFail(true)
	f.receive(t, p, bad())
	attempts := func() int {
		as, _ := f.store.Alerts(ctx, p.ID, 1)
		return as[0].Attempts
	}
	for range 30 {
		f.clock.Set(f.clock.Now().Add(time.Minute))
		f.mon.Tick(ctx)
	}
	// The first send, then +1, +5, and +15 minutes.
	if n := attempts(); n != 4 {
		t.Errorf("attempts in 30 minutes = %d, want 4", n)
	}
}

func TestAlertIsGivenUpAfterADay(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	ctx := context.Background()
	p := f.publication(t, db.Publication{})
	f.receive(t, p, good())
	f.out.setFail(true)
	f.receive(t, p, bad())
	for range 26 * 4 {
		f.clock.Set(f.clock.Now().Add(15 * time.Minute))
		f.mon.Tick(ctx)
	}
	if k := kinds(t, f, p); k[0] != "worse:failed" {
		t.Errorf("after a day: %v", k)
	}
}

type refusing struct{ sends int }

func (r *refusing) SendAlert(context.Context, mail.Alert) error {
	r.sends++
	return fmt.Errorf("send alert: %w", &types.MessageRejected{})
}

func TestPermanentRefusalIsNotRetried(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	p := f.publication(t, db.Publication{})
	f.receive(t, p, good())
	r := &refusing{}
	f.mon.Mailer = r
	f.receive(t, p, bad())
	if k := kinds(t, f, p); k[0] != "worse:failed" || r.sends != 1 {
		t.Errorf("alerts = %v after %d sends", k, r.sends)
	}
}

func TestThirdIssueInASlotThatIsWorseAlerts(t *testing.T) {
	f := setup(t, utc("2026-10-26T09:00:00Z")) // a Monday
	p := f.publication(t, db.Publication{Days: 1 << 1, At: "09:00", GraceMinutes: 60})
	f.receive(t, p, good())
	f.clock.Set(f.clock.Now().Add(time.Minute))
	f.receive(t, p, good())
	f.clock.Set(f.clock.Now().Add(time.Minute))
	f.receive(t, p, bad())
	k := strings.Join(kinds(t, f, p), " ")
	if !strings.Contains(k, "duplicate:sent") || !strings.Contains(k, "worse:sent") {
		t.Errorf("alerts = %s, want the duplicate and the worse issue", k)
	}
	if n := len(f.out.all()); n != 2 {
		t.Errorf("sent %d", n)
	}
}

func TestRepeatingReceivedSendsNoSecondAlert(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	ctx := context.Background()
	p := f.publication(t, db.Publication{})
	prev := f.receive(t, p, good())
	m := f.receive(t, p, bad())
	f.mon.Received(ctx, p, m, prev)
	if n := len(f.out.all()); n != 1 {
		t.Errorf("sent %d", n)
	}
}

// worseEach delivers a good and a bad issue, n times, to fresh publications
// of the fixture's account, deleting each, as an abuser would to reset the
// per-newsletter cap.
func (f *fixture) worseEach(t *testing.T, n int, alertTo string) {
	t.Helper()
	ctx := context.Background()
	for range n {
		p := f.publication(t, db.Publication{AlertEmail: alertTo})
		f.receive(t, p, good())
		f.receive(t, p, bad())
		if err := f.store.DeletePublication(ctx, p.ID, f.user.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAccountCapSurvivesDeletingNewsletters(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	f.mon.PerAccount = 3
	f.worseEach(t, 5, "owner@example.com")
	if n := len(f.out.all()); n != 3 {
		t.Errorf("sent %d, want the account cap of 3", n)
	}
}

func TestRecipientCapHoldsAcrossAddresses(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	f.mon.PerRecipient = 2
	f.worseEach(t, 4, "victim@example.net")
	if n := len(f.out.all()); n != 2 {
		t.Errorf("sent %d, want the recipient cap of 2", n)
	}
}

func TestHourlyCapHoldsForTheInstance(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	f.mon.PerHour = 2
	f.worseEach(t, 4, "owner@example.com")
	if n := len(f.out.all()); n != 2 {
		t.Errorf("sent %d, want the hourly cap of 2", n)
	}
}

func TestOptOutStopsAlertsAndLinkIsInEveryAlert(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	ctx := context.Background()
	p := f.publication(t, db.Publication{})
	f.receive(t, p, good())
	f.receive(t, p, bad())
	sent := f.out.all()
	if len(sent) != 1 {
		t.Fatalf("sent %d", len(sent))
	}
	token, _ := f.store.AlertStopToken(ctx, p.AlertEmail)
	link := "http://test/alerts/stop/" + token
	if !strings.Contains(sent[0].Text, link) || !strings.Contains(sent[0].HTML, link) {
		t.Errorf("no opt-out link in the alert:\n%s", sent[0].Text)
	}
	if err := f.store.StopAlerts(ctx, token); err != nil {
		t.Fatal(err)
	}
	f.receive(t, p, good())
	f.receive(t, p, bad())
	if n := len(f.out.all()); n != 1 {
		t.Errorf("sent %d after opting out", n)
	}
	if k := kinds(t, f, p); k[0] != "worse:stopped" {
		t.Errorf("alerts = %v", k)
	}
}

func TestOptOutStopsARetry(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	ctx := context.Background()
	p := f.publication(t, db.Publication{})
	f.receive(t, p, good())
	f.out.setFail(true)
	f.receive(t, p, bad())
	f.out.setFail(false)
	token, _ := f.store.AlertStopToken(ctx, p.AlertEmail)
	if err := f.store.StopAlerts(ctx, token); err != nil {
		t.Fatal(err)
	}
	f.clock.Set(f.clock.Now().Add(time.Minute))
	f.mon.Tick(ctx)
	if n := len(f.out.all()); n != 0 {
		t.Errorf("sent %d", n)
	}
}

func TestAlertTextIsBoundedAndHasNoControlCharacters(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	p := f.publication(t, db.Publication{Name: "Hi\r\nBcc: x@evil.test"})
	f.receive(t, p, good())
	long := bad()
	long.Message.Subject = strings.Repeat("spam ", 40000)
	for i := range 100 {
		long.Checks = append(long.Checks, verdict.Check{ID: fmt.Sprintf("x.%d", i), Title: strings.Repeat("t", 5000), Status: verdict.Fail})
	}
	f.receive(t, p, long)
	sent := f.out.all()
	if len(sent) != 1 {
		t.Fatalf("sent %d", len(sent))
	}
	if strings.ContainsAny(sent[0].Subject, "\r\n") {
		t.Errorf("subject = %q", sent[0].Subject)
	}
	if n := len(sent[0].Text); n > 10000 {
		t.Errorf("alert text is %d bytes", n)
	}
}

func TestLastTickIsSet(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	if !f.mon.LastTick().IsZero() {
		t.Fatal("set before a tick")
	}
	f.mon.Tick(context.Background())
	if f.mon.LastTick().IsZero() {
		t.Error("not set after a tick")
	}
}

func TestSlotInTheSpringGapMovesForward(t *testing.T) {
	loc, err := time.LoadLocation("America/Toronto")
	if err != nil {
		t.Fatal(err)
	}
	s := Schedule{Days: 127, Hour: 2, Minute: 30, Loc: loc, Grace: 30 * time.Minute}
	got := s.at(time.Date(2026, 3, 8, 12, 0, 0, 0, loc))
	if want := time.Date(2026, 3, 8, 7, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("slot = %v, want the end of the gap, %v", got.UTC(), want)
	}
	// An ordinary day is untouched.
	got = s.at(time.Date(2026, 3, 9, 12, 0, 0, 0, loc))
	if got.Hour() != 2 || got.Minute() != 30 {
		t.Errorf("ordinary day = %v", got)
	}
}

func TestPermanentOnlyMatchesRefusals(t *testing.T) {
	if !mail.Permanent(fmt.Errorf("x: %w", &types.MessageRejected{})) || mail.Permanent(errors.New("timeout")) {
		t.Error("Permanent")
	}
}

// slowMailer takes longer than the status write's timeout, then fails, as a
// send does when SES hangs.
type slowMailer struct {
	wait  time.Duration
	calls int
}

func (m *slowMailer) SendAlert(context.Context, mail.Alert) error {
	m.calls++
	time.Sleep(m.wait)
	return errors.New("deadline exceeded")
}

func TestASendThatTimesOutIsStillRetried(t *testing.T) {
	old := statusTimeout
	statusTimeout = 20 * time.Millisecond
	t.Cleanup(func() { statusTimeout = old })
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	f.mon.Mailer = &slowMailer{wait: 60 * time.Millisecond}
	p := f.publication(t, db.Publication{})
	f.receive(t, p, good())
	f.receive(t, p, bad())
	if k := strings.Join(kinds(t, f, p), " "); k != "worse:pending" {
		t.Errorf("alerts = %s, want it waiting to be retried", k)
	}
}

func TestSkippedChecksAloneAreNotWorse(t *testing.T) {
	cur := good()
	cur.ReadyToSend = false
	cur.Checks = []verdict.Check{{ID: "auth.dkim", Status: verdict.Skipped}}
	if w := Worse(good(), cur); len(w) != 0 {
		t.Errorf("Worse = %v, want nothing when a check could not run", w)
	}
}

func TestPausingStopsAQueuedRetry(t *testing.T) {
	for name, change := range map[string]func(*db.Publication){
		"paused": func(p *db.Publication) { p.Paused = true },
		"moved":  func(p *db.Publication) { p.AlertEmail = "new@example.com" },
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t, utc("2026-10-26T07:00:00Z"))
			ctx := context.Background()
			p := f.publication(t, db.Publication{})
			f.out.setFail(true)
			f.receive(t, p, good())
			f.receive(t, p, bad())
			f.out.setFail(false)
			change(&p)
			if err := f.store.UpdatePublication(ctx, &p); err != nil {
				t.Fatal(err)
			}
			f.clock.Set(f.clock.Now().Add(time.Hour))
			f.mon.Tick(ctx)
			if n := len(f.out.all()); n != 0 {
				t.Errorf("sent %d", n)
			}
			if k := strings.Join(kinds(t, f, p), " "); k != "worse:stopped" {
				t.Errorf("alerts = %s", k)
			}
		})
	}
}

func TestReceivedReportsAnAlertItCouldNotStore(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	p := f.publication(t, db.Publication{})
	prev := f.receive(t, p, good())
	m := f.receive(t, p, good())
	m.Verdict = bad()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.mon.Received(ctx, p, m, prev); err == nil {
		t.Error("no error, so the sender would not retry")
	}
}

func TestATickWithFailedQueriesDoesNotCount(t *testing.T) {
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	f.mon.Tick(context.Background())
	if f.mon.LastTick().IsZero() {
		t.Fatal("a clean tick was not recorded")
	}
	m := f.newMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Tick(ctx)
	if !m.LastTick().IsZero() {
		t.Error("a tick whose queries failed counted as healthy")
	}
}

func TestATickStopsSendingAtItsBudget(t *testing.T) {
	old := tickSendBudget
	tickSendBudget = 10 * time.Millisecond
	t.Cleanup(func() { tickSendBudget = old })
	f := setup(t, utc("2026-10-26T07:00:00Z"))
	ctx := context.Background()
	for i := range 5 {
		p := f.publication(t, db.Publication{Name: fmt.Sprint("n", i)})
		if _, err := f.store.AddAlert(ctx, &db.Alert{PublicationID: p.ID, Kind: KindWorse, Key: "k", To: p.AlertEmail}); err != nil {
			t.Fatal(err)
		}
	}
	slow := &slowMailer{wait: 30 * time.Millisecond}
	f.mon.Mailer = slow
	f.mon.Tick(ctx)
	if slow.calls != 1 {
		t.Errorf("sent %d in one tick, want the budget to stop it after 1", slow.calls)
	}
}
