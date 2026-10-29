package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Subscription statuses, as Creem's webhooks set them. Empty means a
// checkout bound the ids and no status has arrived yet.
const (
	SubActive    = "active"
	SubPastDue   = "past_due"
	SubPaused    = "paused"
	SubCancelled = "cancelled"
)

// GoodStanding reports whether a subscription status makes an account Pro:
// active, or past due while Creem retries the payment.
func GoodStanding(status string) bool { return status == SubActive || status == SubPastDue }

// The plan in effect, over users u LEFT JOIN subscriptions s. An account is
// Pro when the operator granted it (users.plan) or its subscription is in
// good standing. It is lapsed when it is not Pro and its subscription ended,
// which is what stops its newsletters' alerts and heartbeat.
const (
	planExpr   = `CASE WHEN u.plan = 'pro' OR s.status IN ('active', 'past_due') THEN 'pro' ELSE 'free' END`
	compedExpr = `u.plan = 'pro'`
	lapsedExpr = `(u.plan != 'pro' AND COALESCE(s.status IN ('paused', 'cancelled'), 0))`
)

// userCols and userTable read a User with the plan in effect.
const (
	userCols  = `u.id, u.email, ` + planExpr + `, ` + compedExpr + `, ` + lapsedExpr + `, u.created_at`
	userTable = `users u LEFT JOIN subscriptions s ON s.user_id = u.id`
)

// PlanOf returns the plan in effect for a user id, or PlanFree for an id
// with no account.
func (s *Store) PlanOf(ctx context.Context, userID string) (string, error) {
	var plan string
	err := s.DB.QueryRowContext(ctx, `SELECT `+planExpr+` FROM `+userTable+` WHERE u.id = ?`, userID).Scan(&plan)
	if errors.Is(err, sql.ErrNoRows) {
		return PlanFree, nil
	}
	return plan, err
}

// Subscription is the Creem subscription behind an account's paid plan.
type Subscription struct {
	UserID         string
	CustomerID     string
	SubscriptionID string
	Status         string
	ProductID      string
	// PeriodEnd is the end of the period paid for, or zero.
	PeriodEnd time.Time
	// Mark is the Creem time in milliseconds of the newest event whose
	// status was applied, or 0 when there is none.
	Mark      int64
	UpdatedAt time.Time
}

// Bound reports whether the subscription names a Creem customer or
// subscription.
func (s Subscription) Bound() bool { return s.CustomerID != "" || s.SubscriptionID != "" }

// Subscription returns the user's subscription, or ErrNotFound.
func (s *Store) Subscription(ctx context.Context, userID string) (Subscription, error) {
	var sub Subscription
	var end, updated int64
	var mark sql.NullInt64
	err := s.DB.QueryRowContext(ctx, `SELECT user_id, customer_id, subscription_id, status, product_id, period_end, event_at, updated_at
		FROM subscriptions WHERE user_id = ?`, userID).Scan(&sub.UserID, &sub.CustomerID, &sub.SubscriptionID, &sub.Status,
		&sub.ProductID, &end, &mark, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Subscription{}, ErrNotFound
	}
	if end != 0 {
		sub.PeriodEnd = time.Unix(end, 0).UTC()
	}
	sub.Mark = mark.Int64
	sub.UpdatedAt = time.Unix(updated, 0).UTC()
	return sub, err
}

// PutSubscription writes the user's subscription whole.
func (s *Store) PutSubscription(ctx context.Context, sub Subscription) error {
	var end int64
	if !sub.PeriodEnd.IsZero() {
		end = sub.PeriodEnd.Unix()
	}
	var mark any
	if sub.Mark != 0 {
		mark = sub.Mark
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO subscriptions (user_id, customer_id, subscription_id, status, product_id, period_end, event_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET customer_id = excluded.customer_id, subscription_id = excluded.subscription_id,
		status = excluded.status, product_id = excluded.product_id, period_end = excluded.period_end,
		event_at = excluded.event_at, updated_at = excluded.updated_at`,
		sub.UserID, sub.CustomerID, sub.SubscriptionID, sub.Status, sub.ProductID, end, mark, s.Now().Unix())
	return err
}

// UserIDExists reports whether an account with this id exists.
func (s *Store) UserIDExists(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id = ?`, id).Scan(&n)
	return n > 0, err
}

// UserForSubscription returns the account bound to a Creem subscription id,
// or ErrNotFound.
func (s *Store) UserForSubscription(ctx context.Context, subscriptionID string) (string, error) {
	return s.boundUser(ctx, `SELECT user_id FROM subscriptions WHERE subscription_id = ? LIMIT 1`, subscriptionID)
}

// UserForCustomer returns the account bound to a Creem customer id, or
// ErrNotFound.
func (s *Store) UserForCustomer(ctx context.Context, customerID string) (string, error) {
	return s.boundUser(ctx, `SELECT user_id FROM subscriptions WHERE customer_id = ? LIMIT 1`, customerID)
}

func (s *Store) boundUser(ctx context.Context, q, id string) (string, error) {
	if id == "" {
		return "", ErrNotFound
	}
	var uid string
	err := s.DB.QueryRowContext(ctx, q, id).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return uid, err
}

// MaxEventBody is how much of a Creem event's body is stored.
const MaxEventBody = 20000

// CreemEvent is one recorded Creem webhook event.
type CreemEvent struct {
	ID     string
	Kind   string
	UserID string // empty when it named no account here
	// At is Creem's time in milliseconds, or 0 for none.
	At         int64
	ReceivedAt time.Time
	Body       string
}

// RecordCreemEvent stores an event and reports whether it is new. The id is
// the primary key, so of two deliveries of one event only one is new.
func (s *Store) RecordCreemEvent(ctx context.Context, e CreemEvent) (bool, error) {
	var uid, at any
	if e.UserID != "" {
		uid = e.UserID
	}
	if e.At != 0 {
		at = e.At
	}
	body := e.Body
	if len(body) > MaxEventBody {
		body = body[:MaxEventBody]
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO creem_events (id, kind, user_id, received_at, event_at, body)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`, e.ID, e.Kind, uid, s.Now().Unix(), at, body)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ForgetCreemEvent deletes a recorded event, so a retry of one that could
// not be applied is applied then.
func (s *Store) ForgetCreemEvent(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM creem_events WHERE id = ?`, id)
	return err
}

// CreemEventByID returns a recorded event, or ErrNotFound.
func (s *Store) CreemEventByID(ctx context.Context, id string) (CreemEvent, error) {
	var e CreemEvent
	var uid sql.NullString
	var at sql.NullInt64
	var received int64
	err := s.DB.QueryRowContext(ctx, `SELECT id, kind, user_id, received_at, event_at, body FROM creem_events WHERE id = ?`, id).
		Scan(&e.ID, &e.Kind, &uid, &received, &at, &e.Body)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	e.UserID, e.At, e.ReceivedAt = uid.String, at.Int64, time.Unix(received, 0).UTC()
	return e, err
}
