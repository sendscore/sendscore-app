package monitor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"strings"
	"sync/atomic"
	"text/template"
	"time"
	"unicode"

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

// Default caps on alerts. Alerts go through the operator's sending account
// and carry text from a message anyone can send, so one newsletter, one
// account, one recipient, and the whole instance are each bounded.
const (
	// DefaultAlertsPerDay caps one publication in a UTC day.
	DefaultAlertsPerDay = 10
	// DefaultAlertsPerAccount caps one account in a UTC day, and outlives
	// deleting a newsletter.
	DefaultAlertsPerAccount = 30
	// DefaultAlertsPerRecipient caps one address in a UTC day, and outlives
	// deleting an account.
	DefaultAlertsPerRecipient = 20
	// DefaultAlertsPerHour caps the whole instance in an hour.
	DefaultAlertsPerHour = 200
)

// retryDelays is the wait after each failed send; the last repeats until
// giveUpAfter. Long enough to outlast an SES outage or a key rotation.
var retryDelays = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 4 * time.Hour}

// giveUpAfter is how long after it was made a failing alert is still tried.
const giveUpAfter = 24 * time.Hour

// Bounds on text from a message or a form that goes into an alert.
const (
	maxQuoted = 120 // a subject or a name
	maxItem   = 300 // one line of what got worse
	maxItems  = 20
)

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
	// PerDay caps alerts per publication per UTC day; PerAccount, per
	// account per UTC day; PerRecipient, per address per UTC day; and
	// PerHour, for the instance per hour. Zero means the default.
	PerDay       int
	PerAccount   int
	PerRecipient int
	PerHour      int
	Log          *slog.Logger

	lastTick atomic.Int64
}

// LastTick is when the heartbeat last finished, or zero before the first.
func (m *Monitor) LastTick() time.Time {
	if n := m.lastTick.Load(); n != 0 {
		return time.Unix(n, 0)
	}
	return time.Time{}
}

// Received is called once a publication's message is saved, with the
// issue before it (nil for the first). It sends at most one alert for the
// message: when it is a second issue in the same slot, or when it is worse
// than the previous issue. A paused publication gets none, and neither does
// one whose owner's Pro plan has lapsed.
func (m *Monitor) Received(ctx context.Context, p db.Publication, msg, prev *db.Message) {
	if p.Paused || p.OwnerLapsed || msg.Kind != db.KindIssue {
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
	if dup {
		// Two issues for one send: one alert for the slot, which also says
		// what got worse. A later issue in the slot has no duplicate alert to
		// send, so what it made worse needs its own.
		if m.enqueue(ctx, p, KindDuplicate, slotKey(msg.SlotAt), msg.ID, m.duplicateAlert(ctx, p, msg, worse)) || len(worse) == 0 {
			return
		}
	}
	if len(worse) > 0 {
		m.enqueue(ctx, p, KindWorse, "report:"+msg.ID, msg.ID, m.worseAlert(ctx, p, msg, worse))
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
	m.lastTick.Store(time.Now().Unix())
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
	m.enqueue(ctx, p, KindMissed, key, "", m.missedAlert(ctx, p, s, slot))
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

func orDefault(n, fallback int) int {
	if n == 0 {
		return fallback
	}
	return n
}

// caps are the limits one alert to p's address counts against.
func (m *Monitor) caps(p db.Publication) []db.Cap {
	now := m.Store.Now()
	day, hour := db.Day(now), db.Hour(now)
	return []db.Cap{
		{Name: "alerts:pub:" + p.ID, Bucket: day, Limit: orDefault(m.PerDay, DefaultAlertsPerDay), Keep: 48 * time.Hour},
		{Name: "alerts:user:" + p.UserID, Bucket: day, Limit: orDefault(m.PerAccount, DefaultAlertsPerAccount), Keep: 48 * time.Hour},
		{Name: "alerts:to:" + db.RecipientKey(p.AlertEmail), Bucket: day, Limit: orDefault(m.PerRecipient, DefaultAlertsPerRecipient), Keep: 48 * time.Hour},
		{Name: "alerts:all", Bucket: hour, Limit: orDefault(m.PerHour, DefaultAlertsPerHour), Keep: 2 * time.Hour},
	}
}

// enqueue stores an alert, once per publication, kind, and key, then sends
// it, and reports whether it was new. Over a cap it is kept as capped and
// never sent. An alert to an address that opted out is not counted, and
// deliver stops it.
func (m *Monitor) enqueue(ctx context.Context, p db.Publication, kind, key, reportID string, a mail.Alert) bool {
	row := &db.Alert{PublicationID: p.ID, Kind: kind, Key: key, ReportID: reportID, To: p.AlertEmail,
		Subject: a.Subject, Text: a.Text, HTML: a.HTML}
	var caps []db.Cap
	if stopped, err := m.Store.AlertsStopped(ctx, p.AlertEmail); err != nil {
		m.Log.Error("alert opt-out", "err", err)
		caps = m.caps(p)
	} else if !stopped {
		caps = m.caps(p)
	}
	added, err := m.Store.AddAlert(ctx, row, caps...)
	if err != nil {
		m.Log.Error("add alert", "publication", p.ID, "err", err)
		return false
	}
	if !added {
		return false
	}
	if row.Status == db.AlertCapped {
		m.Log.Warn("alert over a cap, not sent", "publication", p.ID, "kind", kind)
		return true
	}
	m.deliver(ctx, row.ID)
	return true
}

// retryAt is when an alert that has failed attempts times may be tried
// again, or false when it is given up.
func retryAt(a db.Alert, now time.Time) (time.Time, bool) {
	if now.Sub(a.CreatedAt) >= giveUpAfter {
		return time.Time{}, false
	}
	return now.Add(retryDelays[min(a.Attempts, len(retryDelays))-1]), true
}

// deliver sends a pending alert if this call claims it. A failure leaves it
// pending, to be tried again after a longer wait each time (see retryDelays),
// unless SES says trying again cannot help.
func (m *Monitor) deliver(ctx context.Context, id string) {
	a, err := m.Store.ClaimAlert(ctx, id)
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			m.Log.Error("claim alert", "err", err)
		}
		return
	}
	// A fresh context, so a request that ended cannot leave it claimed.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	setStatus := func(status, errText string) {
		if err := m.Store.SetAlertStatus(sctx, a.ID, status, errText); err != nil {
			m.Log.Error("alert status", "err", err)
		}
	}
	// Checked here too, since a retry may come after the recipient opted out.
	if stopped, err := m.Store.AlertsStopped(ctx, a.To); err == nil && stopped {
		setStatus(db.AlertStopped, "")
		return
	}
	err = m.Mailer.SendAlert(ctx, mail.Alert{To: a.To, Subject: a.Subject, Text: a.Text, HTML: a.HTML})
	if err == nil {
		m.Log.Info("alert sent", "alert", a.ID, "publication", a.PublicationID, "kind", a.Kind)
		setStatus(db.AlertSent, "")
		return
	}
	m.Log.Error("send alert", "alert", a.ID, "publication", a.PublicationID, "attempt", a.Attempts, "err", err)
	next, again := retryAt(a, m.Store.Now())
	if !again || mail.Permanent(err) {
		m.Log.Error("alert given up", "alert", a.ID, "publication", a.PublicationID, "kind", a.Kind)
		setStatus(db.AlertFailed, err.Error())
		return
	}
	if err := m.Store.RetryAlert(sctx, a.ID, err.Error(), next); err != nil {
		m.Log.Error("alert retry", "err", err)
	}
}

// Alert emails

type alertData struct {
	Name      string
	Intro     string
	Items     []string
	ReportURL string
	PageURL   string
	StopURL   string
}

var textAlert = template.Must(template.New("text").Parse(`{{.Intro}}
{{range .Items}}
- {{.}}{{end}}
{{if .ReportURL}}
Open the report at {{.ReportURL}}
{{end}}
You get this email because this address receives the alerts for {{.Name}}, which you monitor on SendScore. To change where alerts go, pause them, or change the schedule, open {{.PageURL}}
{{if .StopURL}}
If you did not ask for these, stop every alert to this address at {{.StopURL}}
{{end}}
Receipt at SendScore does not prove inbox placement at Gmail or any other provider.
`))

var htmlAlert = htmltemplate.Must(htmltemplate.New("html").Parse(`<!doctype html>
<html><body style="font-family: Georgia, serif; font-size: 16px; line-height: 1.5; color: #111;">
<p>{{.Intro}}</p>
{{if .Items}}<ul>{{range .Items}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .ReportURL}}<p><a href="{{.ReportURL}}">Open the report</a></p>{{end}}
<p style="color: #666; font-size: 14px;">You get this email because this address receives the alerts for {{.Name}}, which you monitor on SendScore. To change where alerts go, pause them, or change the schedule, open <a href="{{.PageURL}}">the newsletter's page</a>.{{if .StopURL}} If you did not ask for these, <a href="{{.StopURL}}">stop every alert to this address</a>.{{end}}</p>
<p style="color: #666; font-size: 14px;">Receipt at SendScore does not prove inbox placement at Gmail or any other provider.</p>
</body></html>
`))

// base fills in what every alert for p carries, with its text kept short.
func (m *Monitor) base(ctx context.Context, p db.Publication, d alertData) alertData {
	d.Name, d.PageURL = clean(p.Name, maxQuoted), m.pageURL(p)
	d.Items = d.Items[:min(len(d.Items), maxItems)]
	for i, it := range d.Items {
		d.Items[i] = clean(it, maxItem)
	}
	token, err := m.Store.AlertStopToken(ctx, p.AlertEmail)
	if err != nil {
		m.Log.Error("alert opt-out token", "err", err)
		return d
	}
	d.StopURL = m.BaseURL + "/alerts/stop/" + token
	return d
}

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

// clean makes text from a message or a form safe to quote in an alert: no
// control characters, and at most n characters.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > n {
		return strings.TrimSpace(string(r[:n])) + "..."
	}
	return s
}

func subjectOf(msg *db.Message) string {
	if s := clean(msg.Verdict.Message.Subject, maxQuoted); s != "" {
		return "“" + s + "”"
	}
	return "with no subject"
}

func (m *Monitor) worseAlert(ctx context.Context, p db.Publication, msg *db.Message, worse []string) mail.Alert {
	name := clean(p.Name, maxQuoted)
	return m.render(fmt.Sprintf("The new issue of %s is worse than the last one", name), m.base(ctx, p, alertData{
		ReportURL: m.BaseURL + "/r/" + msg.ID, Items: worse,
		Intro: fmt.Sprintf("The issue of %s %s arrived on %s and is worse than the issue before it.", name, subjectOf(msg), localTime(p, msg.ReceivedAt)),
	}))
}

func (m *Monitor) duplicateAlert(ctx context.Context, p db.Publication, msg *db.Message, worse []string) mail.Alert {
	name := clean(p.Name, maxQuoted)
	intro := fmt.Sprintf("A second issue of %s arrived for the send expected on %s. The newer one is %s and arrived on %s. Check whether it went out twice.",
		name, localTime(p, msg.SlotAt), subjectOf(msg), localTime(p, msg.ReceivedAt))
	if len(worse) > 0 {
		intro += " It is also worse than the issue before it."
	}
	return m.render(fmt.Sprintf("Two issues of %s arrived for the same send", name), m.base(ctx, p, alertData{
		ReportURL: m.BaseURL + "/r/" + msg.ID, Items: worse, Intro: intro,
	}))
}

func (m *Monitor) missedAlert(ctx context.Context, p db.Publication, s Schedule, slot time.Time) mail.Alert {
	name := clean(p.Name, maxQuoted)
	return m.render(fmt.Sprintf("The expected issue of %s has not arrived", name), m.base(ctx, p, alertData{
		Intro: fmt.Sprintf("An issue of %s was expected on %s, and none had arrived at its monitoring address by the end of the %s grace period. "+
			"It may not have been sent, or it may have been delayed or blocked on the way.", name, localTime(p, slot), minutes(int(s.Grace/time.Minute))),
	}))
}

// signupPhrases mark a subscription confirmation by its subject, at any time.
// They are whole phrases, since a newsletter may well write about verifying a
// domain or welcome a season. A message taken for a signup message is never
// compared, placed in a slot, or alerted on, and does not count as the issue
// the heartbeat expects, so a wrong match costs more than a missed one.
var signupPhrases = []string{
	"confirm your subscription", "confirm your email", "confirm your address", "confirm your sign", "confirm subscription",
	"verify your email", "verify your subscription", "verify your address", "activate your subscription", "activate your account",
	"subscription request", "complete your subscription", "finish subscribing", "you're subscribed",
	"you are subscribed", "thanks for subscribing", "thank you for subscribing", "subscription confirmed", "opt-in confirmation",
}

// signupWords are looser, and count only before a publication's first issue,
// when a signup message is what is expected.
var signupWords = []string{"confirm", "verify", "verification", "activate", "welcome", "opt-in", "opt in", "double opt"}

// IsSignup reports whether a subject looks like a subscription confirmation
// or welcome email. first is set while the publication has no issue yet. The
// message page can correct a wrong guess.
func IsSignup(subject string, first bool) bool {
	s := strings.ToLower(strings.ReplaceAll(subject, "’", "'"))
	for _, w := range signupPhrases {
		if strings.Contains(s, w) {
			return true
		}
	}
	if first {
		for _, w := range signupWords {
			if strings.Contains(s, w) {
				return true
			}
		}
	}
	return false
}
