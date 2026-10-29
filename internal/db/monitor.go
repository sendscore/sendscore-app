package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Message kinds for a publication's messages.
const (
	KindIssue  = "issue"
	KindSignup = "signup"
)

// Plans. Every account is free until billing (or SENDSCORE_PRO_EMAILS)
// makes it pro.
const (
	PlanFree = "free"
	PlanPro  = "pro"
)

// AlertKeep is how long alerts are kept.
const AlertKeep = 400 * 24 * time.Hour

// Publication is a monitored newsletter.
type Publication struct {
	ID     string
	UserID string
	Name   string
	// Token makes the monitoring address m-<token>@<mail domain>.
	Token string
	// Days is a bit set of weekdays, bit 0 for Sunday as in time.Weekday;
	// zero means no schedule. At is the local time HH:MM in TimeZone.
	Days         int
	At           string
	TimeZone     string
	GraceMinutes int
	AlertEmail   string
	Paused       bool
	// WatchSince is when the schedule last changed or alerts were last
	// turned on; a slot due before it is never reported missed.
	WatchSince time.Time
	CreatedAt  time.Time
	// OwnerPlan is the owner's plan, filled by PublicationByToken.
	OwnerPlan string
}

// Scheduled reports whether the publication has an expected schedule.
func (p Publication) Scheduled() bool { return p.Days != 0 && p.At != "" }

const publicationCols = `id, user_id, name, token, days, at, time_zone, grace_minutes, alert_email, paused, watch_since, created_at`

func scanPublication(row interface{ Scan(...any) error }, extra ...any) (Publication, error) {
	var p Publication
	var since, created int64
	err := row.Scan(append([]any{&p.ID, &p.UserID, &p.Name, &p.Token, &p.Days, &p.At, &p.TimeZone, &p.GraceMinutes,
		&p.AlertEmail, &p.Paused, &since, &created}, extra...)...)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	p.WatchSince, p.CreatedAt = time.Unix(since, 0).UTC(), time.Unix(created, 0).UTC()
	return p, err
}

// CreatePublication stores a new publication for p.UserID, assigning its ID
// and monitoring token. It returns ErrLimit when the user already has max
// publications; the count and the insert are one statement.
func (s *Store) CreatePublication(ctx context.Context, p *Publication, max int) error {
	now := s.Now().UTC().Truncate(time.Second)
	p.ID, p.Token, p.CreatedAt, p.WatchSince = "pub_"+NewToken(8), NewToken(10), now, now
	res, err := s.DB.ExecContext(ctx, `INSERT INTO publications (`+publicationCols+`)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM publications WHERE user_id = ?) < ?`,
		p.ID, p.UserID, p.Name, p.Token, p.Days, p.At, p.TimeZone, p.GraceMinutes, p.AlertEmail, p.Paused,
		now.Unix(), now.Unix(), p.UserID, max)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrLimit
	}
	return nil
}

// UpdatePublication saves the editable fields of one of the user's
// publications and restarts WatchSince, so a slot due before the change is
// never reported missed. Another user's publication is ErrNotFound.
func (s *Store) UpdatePublication(ctx context.Context, p *Publication) error {
	p.WatchSince = s.Now().UTC().Truncate(time.Second)
	res, err := s.DB.ExecContext(ctx, `UPDATE publications SET name = ?, days = ?, at = ?, time_zone = ?, grace_minutes = ?,
		alert_email = ?, paused = ?, watch_since = ? WHERE id = ? AND user_id = ?`,
		p.Name, p.Days, p.At, p.TimeZone, p.GraceMinutes, p.AlertEmail, p.Paused, p.WatchSince.Unix(), p.ID, p.UserID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePublication deletes one of the user's publications with its
// messages and alerts. Another user's publication is ErrNotFound.
func (s *Store) DeletePublication(ctx context.Context, id, userID string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after commit
	var owner string
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM publications WHERE id = ?`, id).Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err != nil || owner != userID || userID == "" {
		return ErrNotFound
	}
	for _, q := range []string{
		`DELETE FROM messages WHERE publication_id = ?`,
		`DELETE FROM alerts WHERE publication_id = ?`,
		`DELETE FROM publications WHERE id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PublicationForUser returns one of the user's publications.
func (s *Store) PublicationForUser(ctx context.Context, id, userID string) (Publication, error) {
	if userID == "" {
		return Publication{}, ErrNotFound
	}
	return scanPublication(s.DB.QueryRowContext(ctx, `SELECT `+publicationCols+` FROM publications WHERE id = ? AND user_id = ?`, id, userID))
}

// PublicationByID returns a publication.
func (s *Store) PublicationByID(ctx context.Context, id string) (Publication, error) {
	return scanPublication(s.DB.QueryRowContext(ctx, `SELECT `+publicationCols+` FROM publications WHERE id = ?`, id))
}

// PublicationByToken returns the publication a monitoring address belongs
// to, with its owner's plan.
func (s *Store) PublicationByToken(ctx context.Context, token string) (Publication, error) {
	var plan string
	p, err := scanPublication(s.DB.QueryRowContext(ctx, `SELECT `+prefixed("p.", publicationCols)+`, u.plan
		FROM publications p JOIN users u ON u.id = p.user_id WHERE p.token = ?`, strings.ToLower(token)), &plan)
	p.OwnerPlan = plan
	return p, err
}

func prefixed(prefix, cols string) string {
	parts := strings.Split(cols, ", ")
	for i, c := range parts {
		parts[i] = prefix + c
	}
	return strings.Join(parts, ", ")
}

// Publications lists the user's publications, oldest first.
func (s *Store) Publications(ctx context.Context, userID string) ([]Publication, error) {
	return s.queryPublications(ctx, `SELECT `+publicationCols+` FROM publications WHERE user_id = ? ORDER BY created_at, rowid`, userID)
}

// ScheduledPublications lists every publication with a schedule and alerts
// on, for the heartbeat.
func (s *Store) ScheduledPublications(ctx context.Context) ([]Publication, error) {
	return s.queryPublications(ctx, `SELECT `+publicationCols+` FROM publications WHERE days != 0 AND at != '' AND paused = 0 ORDER BY rowid`)
}

func (s *Store) queryPublications(ctx context.Context, q string, args ...any) ([]Publication, error) {
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Publication
	for rows.Next() {
		p, err := scanPublication(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PublicationMessages returns a publication's newest messages that have not
// expired, newest first, at most limit.
func (s *Store) PublicationMessages(ctx context.Context, pubID string, limit int) ([]*Message, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+messageCols+` FROM messages WHERE publication_id = ? AND expires_at > ?
		ORDER BY received_at DESC, rowid DESC LIMIT ?`, pubID, s.Now().Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// LatestIssue returns a publication's newest issue (not a signup message)
// that has not expired, or ErrNotFound.
func (s *Store) LatestIssue(ctx context.Context, pubID string) (*Message, error) {
	return scanMessage(s.DB.QueryRowContext(ctx, `SELECT `+messageCols+` FROM messages
		WHERE publication_id = ? AND kind = ? AND expires_at > ? ORDER BY received_at DESC, rowid DESC LIMIT 1`,
		pubID, KindIssue, s.Now().Unix()))
}

// IssuesInSlot counts a publication's issues that counted for the slot,
// other than the message except.
func (s *Store) IssuesInSlot(ctx context.Context, pubID string, slot time.Time, except string) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM messages WHERE publication_id = ? AND kind = ? AND slot_at = ? AND id != ?`,
		pubID, KindIssue, slot.Unix(), except).Scan(&n)
	return n, err
}

// IssuesBetween counts a publication's issues received in [from, to).
func (s *Store) IssuesBetween(ctx context.Context, pubID string, from, to time.Time) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM messages WHERE publication_id = ? AND kind = ? AND received_at >= ? AND received_at < ?`,
		pubID, KindIssue, from.Unix(), to.Unix()).Scan(&n)
	return n, err
}

// SetPlan sets a user's plan.
func (s *Store) SetPlan(ctx context.Context, userID, plan string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET plan = ? WHERE id = ?`, plan, userID)
	return err
}

// PromoteEmails puts the accounts with these addresses on the pro plan and
// returns how many changed. Addresses without an account are left for
// their first sign-in.
func (s *Store) PromoteEmails(ctx context.Context, emails []string) (int64, error) {
	var total int64
	for _, e := range emails {
		res, err := s.DB.ExecContext(ctx, `UPDATE users SET plan = ? WHERE email = ? AND plan != ?`, PlanPro, NormalizeEmail(e), PlanPro)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// Alert statuses.
const (
	AlertPending = "pending"
	AlertSending = "sending"
	AlertSent    = "sent"
	AlertFailed  = "failed"
	AlertCapped  = "capped"
)

// Alert is one alert email, stored before it is sent.
type Alert struct {
	ID            string
	PublicationID string
	Kind          string
	Key           string
	ReportID      string
	To            string
	Subject       string
	Text          string
	HTML          string
	Status        string
	Attempts      int
	Error         string
	CreatedAt     time.Time
	SentAt        time.Time
}

const alertCols = `id, publication_id, kind, key, report_id, to_addr, subject, text_body, html_body, status, attempts, error, created_at, sent_at`

func scanAlert(row interface{ Scan(...any) error }) (Alert, error) {
	var a Alert
	var created, sent int64
	err := row.Scan(&a.ID, &a.PublicationID, &a.Kind, &a.Key, &a.ReportID, &a.To, &a.Subject, &a.Text, &a.HTML,
		&a.Status, &a.Attempts, &a.Error, &created, &sent)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	a.CreatedAt = time.Unix(created, 0).UTC()
	if sent != 0 {
		a.SentAt = time.Unix(sent, 0).UTC()
	}
	return a, err
}

// AddAlert stores a pending alert, assigning its ID. It returns false when an
// alert of the same kind and key already exists for the publication, which
// is how each alert is sent once.
func (s *Store) AddAlert(ctx context.Context, a *Alert) (bool, error) {
	a.ID, a.Status, a.CreatedAt = "alr_"+NewToken(8), AlertPending, s.Now().UTC().Truncate(time.Second)
	res, err := s.DB.ExecContext(ctx, `INSERT INTO alerts (id, publication_id, kind, key, report_id, to_addr, subject, text_body, html_body, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(publication_id, kind, key) DO NOTHING`,
		a.ID, a.PublicationID, a.Kind, a.Key, a.ReportID, a.To, a.Subject, a.Text, a.HTML, a.Status, a.CreatedAt.Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// HasAlert reports whether an alert of this kind and key exists.
func (s *Store) HasAlert(ctx context.Context, pubID, kind, key string) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE publication_id = ? AND kind = ? AND key = ?`, pubID, kind, key).Scan(&n)
	return n > 0, err
}

// SetAlertStatus records an alert's status, with an error for a failure.
func (s *Store) SetAlertStatus(ctx context.Context, id, status, errText string) error {
	var sent int64
	if status == AlertSent {
		sent = s.Now().Unix()
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE alerts SET status = ?, error = ?, sent_at = ? WHERE id = ?`, status, errText, sent, id)
	return err
}

// ClaimAlert marks a pending alert as sending and returns it, or ErrNotFound
// when it is not pending (another sender has it, or it is done). Only the
// caller that claims an alert sends it.
func (s *Store) ClaimAlert(ctx context.Context, id string) (Alert, error) {
	return scanAlert(s.DB.QueryRowContext(ctx, `UPDATE alerts SET status = ?, attempts = attempts + 1, claimed_at = ?
		WHERE id = ? AND status = ? RETURNING `+alertCols, AlertSending, s.Now().Unix(), id, AlertPending))
}

// PendingAlerts lists alerts waiting to be sent (or retried), oldest first.
func (s *Store) PendingAlerts(ctx context.Context, limit int) ([]Alert, error) {
	return s.queryAlerts(ctx, `SELECT `+alertCols+` FROM alerts WHERE status = ? ORDER BY created_at, rowid LIMIT ?`, AlertPending, limit)
}

// FailStaleAlerts marks alerts claimed before cutoff and never finished as
// failed. The process stopped while sending them, so they may or may not
// have gone out, and are never sent again.
func (s *Store) FailStaleAlerts(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `UPDATE alerts SET status = ?, error = 'stopped while sending' WHERE status = ? AND claimed_at < ?`,
		AlertFailed, AlertSending, cutoff.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// LastSentAlert returns the publication's most recent alert that was sent.
func (s *Store) LastSentAlert(ctx context.Context, pubID string) (Alert, error) {
	return scanAlert(s.DB.QueryRowContext(ctx, `SELECT `+alertCols+` FROM alerts WHERE publication_id = ? AND status = ?
		ORDER BY sent_at DESC, rowid DESC LIMIT 1`, pubID, AlertSent))
}

// Alerts lists a publication's alerts, newest first.
func (s *Store) Alerts(ctx context.Context, pubID string, limit int) ([]Alert, error) {
	return s.queryAlerts(ctx, `SELECT `+alertCols+` FROM alerts WHERE publication_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?`, pubID, limit)
}

func (s *Store) queryAlerts(ctx context.Context, q string, args ...any) ([]Alert, error) {
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
