package db

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// ErrLimit is returned by Take when a counter has reached its limit.
var ErrLimit = errors.New("limit reached")

// Lifetimes of sign-in links and sessions.
const (
	LoginTokenTTL = 15 * time.Minute
	SessionTTL    = 30 * 24 * time.Hour
)

// APITokenPrefix starts every API token, so a leaked one is easy to spot.
const APITokenPrefix = "ss_live_"

// selectorLen is how much of a token is stored in the clear to find its row:
// the prefix and four characters for an API token ("ss_live_abcd"), or 60
// bits of a 256-bit sign-in or session token.
const selectorLen = 12

// User is an account.
type User struct {
	ID    string
	Email string
	// Plan is the plan in effect: PlanPro when the operator granted it or a
	// subscription is in good standing, otherwise PlanFree.
	Plan string
	// Comped is set when the operator granted Pro (SENDSCORE_PRO_EMAILS),
	// whatever billing says.
	Comped bool
	// Lapsed is set when the account is not Pro and its subscription
	// ended, so its newsletters get no alerts or heartbeat.
	Lapsed    bool
	CreatedAt time.Time
	// Next is set only by ConsumeLoginToken: the path the sign-in link
	// asked to open afterwards, or empty.
	Next string
}

// APIToken is an API token as listed on the account page. The token itself
// is never stored, only its hash and its Prefix.
type APIToken struct {
	ID         string
	Name       string
	Prefix     string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero when never used
}

// HashToken returns the hex SHA-256 of a token, which is all that is stored.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func selector(token string) string {
	if len(token) < selectorLen {
		return token
	}
	return token[:selectorLen]
}

// NormalizeEmail lowercases and trims an address, so one inbox is one
// account.
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// match finds the row whose stored hash equals the token's, comparing hashes
// in constant time. query selects (key, token_hash) for a selector and any
// further args.
func match(ctx context.Context, q querier, query, token string, args ...any) (string, error) {
	want := []byte(HashToken(token))
	rows, err := q.QueryContext(ctx, query, append([]any{selector(token)}, args...)...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	found := ""
	for rows.Next() {
		var key, hash string
		if err := rows.Scan(&key, &hash); err != nil {
			return "", err
		}
		if subtle.ConstantTimeCompare([]byte(hash), want) == 1 {
			found = key
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if found == "" {
		return "", ErrNotFound
	}
	return found, nil
}

// CreateLoginToken stores a single-use sign-in link for email and returns
// the token that goes in the link.
func (s *Store) CreateLoginToken(ctx context.Context, email string) (string, error) {
	return s.CreateLoginTokenNext(ctx, email, "")
}

// CreateLoginTokenNext is CreateLoginToken with a local path to open after
// signing in, which ConsumeLoginToken returns as User.Next.
func (s *Store) CreateLoginTokenNext(ctx context.Context, email, next string) (string, error) {
	token := NewToken(32)
	now := s.Now()
	_, err := s.DB.ExecContext(ctx, `INSERT INTO login_tokens (selector, token_hash, email, next, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		selector(token), HashToken(token), NormalizeEmail(email), next, now.Unix(), now.Add(LoginTokenTTL).Unix())
	return token, err
}

// ConsumeLoginToken uses up a sign-in link, creates the account if this is
// the address's first sign-in, and starts a session. It returns the user and
// the session token for the cookie, or ErrNotFound for a link that is
// unknown, expired, or already used.
func (s *Store) ConsumeLoginToken(ctx context.Context, token string) (User, string, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, "", err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after commit
	now := s.Now()
	hash, err := match(ctx, tx, `SELECT token_hash, token_hash FROM login_tokens WHERE selector = ? AND used_at = 0 AND expires_at > ?`, token, now.Unix())
	if err != nil {
		return User{}, "", err
	}
	var email, next string
	// Claimed inside the transaction, so the same link cannot sign in twice.
	err = tx.QueryRowContext(ctx, `UPDATE login_tokens SET used_at = ? WHERE token_hash = ? AND used_at = 0 RETURNING email, next`, now.Unix(), hash).Scan(&email, &next)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", ErrNotFound
	}
	if err != nil {
		return User{}, "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO users (id, email, created_at) VALUES (?, ?, ?) ON CONFLICT(email) DO NOTHING`,
		"usr_"+NewToken(10), email, now.Unix()); err != nil {
		return User{}, "", err
	}
	u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM `+userTable+` WHERE u.email = ?`, email))
	if err != nil {
		return User{}, "", err
	}
	u.Next = next
	session := NewToken(32)
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (selector, token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		selector(session), HashToken(session), u.ID, now.Unix(), now.Add(SessionTTL).Unix()); err != nil {
		return User{}, "", err
	}
	return u, session, tx.Commit()
}

// PeekLoginToken returns the address and next path of a sign-in link that
// is unused and unexpired, without using it up, so the page it opens can
// say which account it signs in to.
func (s *Store) PeekLoginToken(ctx context.Context, token string) (email, next string, err error) {
	hash, err := match(ctx, s.DB, `SELECT token_hash, token_hash FROM login_tokens WHERE selector = ? AND used_at = 0 AND expires_at > ?`, token, s.Now().Unix())
	if err != nil {
		return "", "", err
	}
	err = s.DB.QueryRowContext(ctx, `SELECT email, next FROM login_tokens WHERE token_hash = ?`, hash).Scan(&email, &next)
	return email, next, err
}

// RememberBrowser records that the browser holding token signed in to email,
// for ttl.
func (s *Store) RememberBrowser(ctx context.Context, token, email string, ttl time.Duration) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO known_browsers (token_hash, email, expires_at) VALUES (?, ?, ?)
		ON CONFLICT(token_hash, email) DO UPDATE SET expires_at = excluded.expires_at`,
		HashToken(token), NormalizeEmail(email), s.Now().Add(ttl).Unix())
	return err
}

// KnownBrowser reports whether the browser holding token has signed in to
// email before.
func (s *Store) KnownBrowser(ctx context.Context, token, email string) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM known_browsers WHERE token_hash = ? AND email = ? AND expires_at > ?`,
		HashToken(token), NormalizeEmail(email), s.Now().Unix()).Scan(&n)
	return n > 0, err
}

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var created int64
	err := row.Scan(&u.ID, &u.Email, &u.Plan, &u.Comped, &u.Lapsed, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.CreatedAt = time.Unix(created, 0).UTC()
	return u, err
}

// UserBySession returns the user a session token belongs to, while the
// session has not expired.
func (s *Store) UserBySession(ctx context.Context, token string) (User, error) {
	if token == "" {
		return User{}, ErrNotFound
	}
	uid, err := match(ctx, s.DB, `SELECT user_id, token_hash FROM sessions WHERE selector = ? AND expires_at > ?`, token, s.Now().Unix())
	if err != nil {
		return User{}, err
	}
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userCols+` FROM `+userTable+` WHERE u.id = ?`, uid))
}

// DeleteSession ends a session (sign out).
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, HashToken(token))
	return err
}

// CreateAPIToken makes a named API token for the user and returns it with
// the full token, which is shown once and never stored. It returns ErrLimit
// when the user already holds max tokens; the count and the insert are one
// statement, so concurrent requests cannot pass the limit.
func (s *Store) CreateAPIToken(ctx context.Context, userID, name string, max int) (APIToken, string, error) {
	token := APITokenPrefix + NewToken(32)
	t := APIToken{ID: "tok_" + NewToken(8), Name: name, Prefix: selector(token), CreatedAt: s.Now().UTC().Truncate(time.Second)}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO api_tokens (id, user_id, name, selector, token_hash, created_at)
		SELECT ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM api_tokens WHERE user_id = ?) < ?`,
		t.ID, userID, name, t.Prefix, HashToken(token), t.CreatedAt.Unix(), userID, max)
	if err != nil {
		return t, "", err
	}
	if n, err := res.RowsAffected(); err != nil {
		return t, "", err
	} else if n == 0 {
		return t, "", ErrLimit
	}
	return t, token, nil
}

// APITokens lists a user's tokens, newest first.
func (s *Store) APITokens(ctx context.Context, userID string) ([]APIToken, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, selector, created_at, last_used_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC, rowid DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var created, used int64
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &created, &used); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(created, 0).UTC()
		if used > 0 {
			t.LastUsedAt = time.Unix(used, 0).UTC()
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken deletes one of the user's tokens. A token that is not the
// user's is ErrNotFound.
func (s *Store) RevokeAPIToken(ctx context.Context, userID, id string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UserByAPIToken returns the owner of an API token and records that the
// token was used.
func (s *Store) UserByAPIToken(ctx context.Context, token string) (User, error) {
	if !strings.HasPrefix(token, APITokenPrefix) {
		return User{}, ErrNotFound
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after commit
	id, err := match(ctx, tx, `SELECT id, token_hash FROM api_tokens WHERE selector = ?`, token)
	if err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, s.Now().Unix(), id); err != nil {
		return User{}, err
	}
	u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM `+userTable+` JOIN api_tokens t ON t.user_id = u.id WHERE t.id = ?`, id))
	if err != nil {
		return User{}, err
	}
	return u, tx.Commit()
}

// Day is the UTC day bucket for daily limits.
func Day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// Hour is the UTC hour bucket for hourly limits.
func Hour(t time.Time) string { return t.UTC().Format("2006-01-02T15") }

// Take counts one use of name in bucket and returns the new count, or
// ErrLimit (counting nothing) when limit uses are already counted. keep is
// how long the counter is kept, at least the length of the bucket. The check
// and the count are one statement, so concurrent requests cannot both take
// the last use.
func (s *Store) Take(ctx context.Context, name, bucket string, limit int, keep time.Duration) (int, error) {
	if limit <= 0 {
		return 0, ErrLimit
	}
	var n int
	err := s.DB.QueryRowContext(ctx, `INSERT INTO counters (name, bucket, count, expires_at) VALUES (?, ?, 1, ?)
		ON CONFLICT(name, bucket) DO UPDATE SET count = count + 1 WHERE count < ?
		RETURNING count`, name, bucket, s.Now().Add(keep).Unix(), limit).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrLimit
	}
	return n, err
}

// Count returns how many uses of name are counted in bucket.
func (s *Store) Count(ctx context.Context, name, bucket string) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT count FROM counters WHERE name = ? AND bucket = ?`, name, bucket).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

// DeleteUser deletes an account and everything that belongs to it, in one
// transaction: its test addresses, its publications, every message received
// at either or uploaded while signed in (raw bodies with them), its alerts,
// sessions, sign-in links, known browsers, API tokens, OAuth codes and
// tokens, usage counters, and subscription. The messages are deleted by
// hand rather than left to the foreign keys, which would keep an upload as
// an anonymous row. Creem events are kept, since they are the payment
// record, with the account taken off them. OAuth clients are shared
// registrations with no owner, so they stay. An unknown id is ErrNotFound.
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after commit
	var email string
	err = tx.QueryRowContext(ctx, `SELECT email FROM users WHERE id = ?`, userID).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) || userID == "" {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	for _, q := range []struct {
		query string
		args  []any
	}{
		{`DELETE FROM messages WHERE user_id = ?1
			OR token IN (SELECT token FROM addresses WHERE user_id = ?1)
			OR publication_id IN (SELECT id FROM publications WHERE user_id = ?1)`, []any{userID}},
		{`DELETE FROM alerts WHERE publication_id IN (SELECT id FROM publications WHERE user_id = ?)`, []any{userID}},
		{`DELETE FROM publications WHERE user_id = ?`, []any{userID}},
		{`DELETE FROM addresses WHERE user_id = ?`, []any{userID}},
		{`DELETE FROM sessions WHERE user_id = ?`, []any{userID}},
		{`DELETE FROM api_tokens WHERE user_id = ?`, []any{userID}},
		{`DELETE FROM oauth_codes WHERE user_id = ?`, []any{userID}},
		{`DELETE FROM oauth_tokens WHERE user_id = ?`, []any{userID}},
		{`DELETE FROM login_tokens WHERE email = ?`, []any{email}},
		{`DELETE FROM known_browsers WHERE email = ?`, []any{email}},
		// Counters about an account are named <what>:user:<id>. Ids are
		// base32 with a prefix, so they hold no GLOB wildcard.
		{`DELETE FROM counters WHERE name GLOB '*:user:' || ?`, []any{userID}},
		{`DELETE FROM subscriptions WHERE user_id = ?`, []any{userID}},
		{`UPDATE creem_events SET user_id = NULL WHERE user_id = ?`, []any{userID}},
		{`DELETE FROM users WHERE id = ?`, []any{userID}},
	} {
		if _, err := tx.ExecContext(ctx, q.query, q.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}
