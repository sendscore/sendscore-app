package monitor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"strings"
	"text/template"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore-app/internal/mail"
	"github.com/sendscore/sendscore/verdict"
)

// Alert kinds.
const (
	KindWorse     = "worse"
	KindMissed    = "missed"
	KindDuplicate = "duplicate"
)

// DefaultAlertsPerDay caps the alerts one publication sends in a UTC day.
const DefaultAlertsPerDay = 10

// maxAttempts is how often a failed alert is tried before it is given up.
const maxAttempts = 5

// staleSending is how long an alert may stay claimed before the process is
// taken to have stopped while sending it.
const staleSending = 5 * time.Minute

// missedWindow is how long after a deadline a missed issue is still
// reported, so a restart after a long outage does not send stale alerts.
const missedWindow = 24 * time.Hour

// Monitor decides on and sends alerts. Its clock is the store's Now.
type Monitor struct {
	Store   *db.Store
	Mailer  mail.Alerter
	BaseURL string
	// PerDay caps alerts per publication per UTC day.
	PerDay int
	Log    *slog.Logger
}

// Received is called once a publication's message is saved, with the
// issue before it (nil for the first). It sends at most one alert for the
// message: when it is a second issue in the same slot, or when it is worse
// than the previous issue. A paused publication gets none.
func (m *Monitor) Received(ctx context.Context, p db.Publication, msg, prev *db.Message) {
	if p.Paused || msg.Kind != db.KindIssue {
		return
	}
	var worse []string
	if prev != nil {
		worse = Worse(prev.Verdict, msg.Verdict)
	}
	dup := false
	if !msg.SlotAt.IsZero() {
		n, err := m.Store.IssuesInSlot(ctx, p.ID, msg.SlotAt, msg.ID)
		if err != nil {
			m.Log.Error("count issues in slot", "publication", p.ID, "err", err)
		}
		dup = n > 0
	}
	switch {
	case dup:
		// Two issues for one send: one alert for the slot, which also says
		// what got worse.
		m.enqueue(ctx, p, KindDuplicate, slotKey(msg.SlotAt), msg.ID, m.duplicateAlert(p, msg, worse))
	case len(worse) > 0:
		m.enqueue(ctx, p, KindWorse, "report:"+msg.ID, msg.ID, m.worseAlert(p, msg, worse))
	}
}

func slotKey(t time.Time) string { return fmt.Sprintf("slot:%d", t.Unix()) }

// Worse lists how cur is worse than prev, in sentences: a check that fails
// now and did not before, a change that made a check worse, and ready to
// send turning from yes to no. It is empty when nothing got worse.
func Worse(prev, cur *verdict.Verdict) []string {
	var out []string
	before := map[string]verdict.Status{}
	for _, c := range prev.Checks {
		before[c.ID] = c.Status
	}
	for _, c := range cur.Checks {
		if c.Status == verdict.Fail && before[c.ID] != verdict.Fail {
			out = append(out, fmt.Sprintf("%s now fails (%s).", strings.TrimSuffix(c.Title, "."), c.ID))
		}
	}
	for _, c := range cur.Changes {
		if c.Worsened != "" {
			out = append(out, fmt.Sprintf("%s changed from %v to %v, which made %s worse.", c.Field, show(c.Before), show(c.After), c.Worsened))
		}
	}
	if prev.ReadyToSend && !cur.ReadyToSend {
		out = append(out, "The previous issue was ready to send, and this one is not.")
	}
	return out
}

func show(v any) string {
	if s := fmt.Sprint(v); s != "" {
		return s
	}
	return "nothing"
}

// Tick runs one heartbeat: it sends the missed-issue alert for each
// scheduled publication whose latest deadline passed with no issue, sends
// alerts waiting to be sent, and gives up on any left half sent by a
// process that stopped.
func (m *Monitor) Tick(ctx context.Context) {
	now := m.Store.Now()
	pubs, err := m.Store.ScheduledPublications(ctx)
	if err != nil {
		m.Log.Error("heartbeat publications", "err", err)
	}
	for _, p := range pubs {
		m.checkMissed(ctx, p, now)
	}
	if n, err := m.Store.FailStaleAlerts(ctx, now.Add(-staleSending)); err != nil {
		m.Log.Error("stale alerts", "err", err)
	} else if n > 0 {
		m.Log.Warn("alerts left half sent were not retried", "count", n)
	}
	pending, err := m.Store.PendingAlerts(ctx, 100)
	if err != nil {
		m.Log.Error("pending alerts", "err", err)
	}
	for _, a := range pending {
		m.deliver(ctx, a.ID)
	}
}

func (m *Monitor) checkMissed(ctx context.Context, p db.Publication, now time.Time) {
	s, ok := ScheduleOf(p)
	if !ok {
		return
	}
	slot := s.LastDue(now)
	deadline := s.Deadline(slot)
	// A deadline from before the schedule was set (or alerts were turned
	// back on), or from long ago, is not reported.
	if !deadline.After(p.WatchSince) || now.Sub(deadline) > missedWindow {
		return
	}
	key := slotKey(slot)
	if done, err := m.Store.HasAlert(ctx, p.ID, KindMissed, key); err != nil || done {
		if err != nil {
			m.Log.Error("missed alert lookup", "publication", p.ID, "err", err)
		}
		return
	}
	// An issue anywhere in the slot's window, even a late one that arrived
	// after the deadline while the heartbeat was not running, means it was
	// not missed.
	start, end := s.Window(slot)
	n, err := m.Store.IssuesBetween(ctx, p.ID, start, minTime(end, now.Add(time.Second)))
	if err != nil {
		m.Log.Error("count issues", "publication", p.ID, "err", err)
		return
	}
	if n > 0 {
		return
	}
	m.enqueue(ctx, p, KindMissed, key, "", m.missedAlert(p, s, slot))
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Run calls Tick every minute until ctx is done.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		m.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// enqueue stores an alert, once per publication, kind, and key, then sends
// it. Over the daily cap it is kept as capped and never sent.
func (m *Monitor) enqueue(ctx context.Context, p db.Publication, kind, key, reportID string, a mail.Alert) {
	row := &db.Alert{PublicationID: p.ID, Kind: kind, Key: key, ReportID: reportID, To: p.AlertEmail,
		Subject: a.Subject, Text: a.Text, HTML: a.HTML}
	added, err := m.Store.AddAlert(ctx, row)
	if err != nil {
		m.Log.Error("add alert", "publication", p.ID, "err", err)
		return
	}
	if !added {
		return
	}
	perDay := m.PerDay
	if perDay == 0 {
		perDay = DefaultAlertsPerDay
	}
	if _, err := m.Store.Take(ctx, "alerts:pub:"+p.ID, db.Day(m.Store.Now()), perDay, 48*time.Hour); err != nil {
		if errors.Is(err, db.ErrLimit) {
			m.Log.Warn("alert over the daily cap, not sent", "publication", p.ID, "kind", kind)
			_ = m.Store.SetAlertStatus(ctx, row.ID, db.AlertCapped, "")
			return
		}
		m.Log.Error("alert cap", "err", err)
	}
	m.deliver(ctx, row.ID)
}

// deliver sends a pending alert if this call claims it. A failure leaves it
// pending for the next heartbeat, up to maxAttempts.
func (m *Monitor) deliver(ctx context.Context, id string) {
	a, err := m.Store.ClaimAlert(ctx, id)
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			m.Log.Error("claim alert", "err", err)
		}
		return
	}
	err = m.Mailer.SendAlert(ctx, mail.Alert{To: a.To, Subject: a.Subject, Text: a.Text, HTML: a.HTML})
	status, errText := db.AlertSent, ""
	if err != nil {
		m.Log.Error("send alert", "alert", a.ID, "publication", a.PublicationID, "err", err)
		status, errText = db.AlertPending, err.Error()
		if a.Attempts >= maxAttempts {
			status = db.AlertFailed
		}
	} else {
		m.Log.Info("alert sent", "alert", a.ID, "publication", a.PublicationID, "kind", a.Kind)
	}
	// A fresh context, so a request that ended cannot leave it claimed.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := m.Store.SetAlertStatus(sctx, a.ID, status, errText); err != nil {
		m.Log.Error("alert status", "err", err)
	}
}

// Alert emails

type alertData struct {
	Name      string
	Intro     string
	Items     []string
	ReportURL string
	PageURL   string
}

var textAlert = template.Must(template.New("text").Parse(`{{.Intro}}
{{range .Items}}
- {{.}}{{end}}
{{if .ReportURL}}
Open the report at {{.ReportURL}}
{{end}}
You get this email because this address receives the alerts for {{.Name}}, which you monitor on SendScore. To change where alerts go, pause them, or change the schedule, open {{.PageURL}}

Receipt at SendScore does not prove inbox placement at Gmail or any other provider.
`))

var htmlAlert = htmltemplate.Must(htmltemplate.New("html").Parse(`<!doctype html>
<html><body style="font-family: Georgia, serif; font-size: 16px; line-height: 1.5; color: #111;">
<p>{{.Intro}}</p>
{{if .Items}}<ul>{{range .Items}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .ReportURL}}<p><a href="{{.ReportURL}}">Open the report</a></p>{{end}}
<p style="color: #666; font-size: 14px;">You get this email because this address receives the alerts for {{.Name}}, which you monitor on SendScore. To change where alerts go, pause them, or change the schedule, open <a href="{{.PageURL}}">the newsletter's page</a>.</p>
<p style="color: #666; font-size: 14px;">Receipt at SendScore does not prove inbox placement at Gmail or any other provider.</p>
</body></html>
`))

func (m *Monitor) render(subject string, d alertData) mail.Alert {
	var t, h bytes.Buffer
	if err := textAlert.Execute(&t, d); err != nil {
		m.Log.Error("alert text", "err", err)
	}
	if err := htmlAlert.Execute(&h, d); err != nil {
		m.Log.Error("alert html", "err", err)
	}
	return mail.Alert{Subject: subject, Text: t.String(), HTML: h.String()}
}

func (m *Monitor) pageURL(p db.Publication) string { return m.BaseURL + "/newsletters/" + p.ID }

// localTime formats t in the publication's time zone.
func localTime(p db.Publication, t time.Time) string {
	if loc, err := time.LoadLocation(p.TimeZone); err == nil {
		t = t.In(loc)
	}
	return t.Format("Monday 2 Jan 2006 at 15:04 MST")
}

func subjectOf(msg *db.Message) string {
	if s := msg.Verdict.Message.Subject; s != "" {
		return "“" + s + "”"
	}
	return "with no subject"
}

func (m *Monitor) worseAlert(p db.Publication, msg *db.Message, worse []string) mail.Alert {
	return m.render(fmt.Sprintf("The new issue of %s is worse than the last one", p.Name), alertData{
		Name: p.Name, PageURL: m.pageURL(p), ReportURL: m.BaseURL + "/r/" + msg.ID, Items: worse,
		Intro: fmt.Sprintf("The issue of %s %s arrived on %s and is worse than the issue before it.", p.Name, subjectOf(msg), localTime(p, msg.ReceivedAt)),
	})
}

func (m *Monitor) duplicateAlert(p db.Publication, msg *db.Message, worse []string) mail.Alert {
	intro := fmt.Sprintf("A second issue of %s arrived for the send expected on %s. The newer one is %s and arrived on %s. Check whether it went out twice.",
		p.Name, localTime(p, msg.SlotAt), subjectOf(msg), localTime(p, msg.ReceivedAt))
	if len(worse) > 0 {
		intro += " It is also worse than the issue before it."
	}
	return m.render(fmt.Sprintf("Two issues of %s arrived for the same send", p.Name), alertData{
		Name: p.Name, PageURL: m.pageURL(p), ReportURL: m.BaseURL + "/r/" + msg.ID, Items: worse, Intro: intro,
	})
}

func (m *Monitor) missedAlert(p db.Publication, s Schedule, slot time.Time) mail.Alert {
	return m.render(fmt.Sprintf("The expected issue of %s has not arrived", p.Name), alertData{
		Name: p.Name, PageURL: m.pageURL(p),
		Intro: fmt.Sprintf("An issue of %s was expected on %s, and none had arrived at its monitoring address by the end of the %s grace period. "+
			"It may not have been sent, or it may have been delayed or blocked on the way.", p.Name, localTime(p, slot), minutes(int(s.Grace/time.Minute))),
	})
}

// signupWords mark a subscription confirmation or welcome email by its
// subject. Such messages are stored but are not issues: they are never
// compared, placed in a slot, or alerted on.
var signupWords = []string{
	"confirm", "verify", "verification", "activate", "welcome", "opt-in", "opt in", "double opt",
	"subscription request", "complete your subscription", "finish subscribing", "you're subscribed",
	"you are subscribed", "thanks for subscribing", "thank you for subscribing", "subscription confirmed",
}

// IsSignup reports whether a subject looks like a subscription confirmation
// or welcome email.
func IsSignup(subject string) bool {
	s := strings.ToLower(strings.ReplaceAll(subject, "’", "'"))
	for _, w := range signupWords {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}
