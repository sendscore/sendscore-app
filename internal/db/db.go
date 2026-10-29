// Package db opens the SQLite database, applies the schema, and holds the
// queries the receiver and the web app share.
package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"

	"github.com/sendscore/sendscore/verdict"
)

//go:embed schema.sql
var schema string

// ErrNotFound is returned when a row does not exist or has expired.
var ErrNotFound = errors.New("not found")

// ErrUnknownAfter is returned when a wait names an after report that is not
// one of the address's reports.
var ErrUnknownAfter = errors.New("unknown after report")

// Store wraps the database.
type Store struct {
	DB  *sql.DB
	Now func() time.Time
}

// Open opens (creating if needed) the SQLite database at path, with the same
// pragmas as Preflight: WAL, a busy timeout, foreign keys, and immediate
// transactions.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf(
		"file:%s?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)",
		path,
	)
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	d.SetMaxOpenConns(10)
	d.SetMaxIdleConns(10)
	if err := d.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if _, err := d.Exec(schema); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := migrate(d); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{DB: d, Now: time.Now}, nil
}

// migrate adds the columns that came after a table was first created. Each
// change is additive, and a column that is already there is left alone.
func migrate(d *sql.DB) error {
	alters := []string{
		// The account an address was made for; NULL for anonymous addresses.
		`ALTER TABLE addresses ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE SET NULL`,
		// Where to go after signing in, such as back to an OAuth consent page.
		`ALTER TABLE login_tokens ADD COLUMN next TEXT NOT NULL DEFAULT ''`,
		// The hash of the CSRF cookie of the browser that made an anonymous
		// address, so its reports show the address only to that browser.
		`ALTER TABLE addresses ADD COLUMN creator TEXT NOT NULL DEFAULT ''`,
		// The account a signed-in upload belongs to; NULL otherwise.
		`ALTER TABLE messages ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE SET NULL`,
		// Whether the authorization request named its redirect_uri, which
		// decides whether the token request must (RFC 6749 section 4.1.3).
		`ALTER TABLE oauth_codes ADD COLUMN redirect_given INTEGER NOT NULL DEFAULT 1`,
		// When the grant a token belongs to was first allowed, kept across
		// refreshes; 0 for rows from before the column, which use created_at.
		`ALTER TABLE oauth_tokens ADD COLUMN granted_at INTEGER NOT NULL DEFAULT 0`,
		// The monitored publication a message was received for, its kind
		// (issue or signup, empty for test addresses and uploads), the
		// scheduled slot it counted for (Unix seconds, 0 for none), and
		// whether it arrived after that slot's deadline.
		`ALTER TABLE messages ADD COLUMN publication_id TEXT REFERENCES publications(id) ON DELETE CASCADE`,
		`ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE messages ADD COLUMN slot_at INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE messages ADD COLUMN late INTEGER NOT NULL DEFAULT 0`,
	}
	for _, a := range alters {
		if _, err := d.Exec(a); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
	}
	for _, idx := range []string{
		`CREATE INDEX IF NOT EXISTS addresses_user ON addresses(user_id)`,
		`CREATE INDEX IF NOT EXISTS messages_user ON messages(user_id)`,
		// For pruning registrations (see CreateOAuthClient).
		`CREATE INDEX IF NOT EXISTS oauth_clients_created ON oauth_clients(created_at)`,
		`CREATE INDEX IF NOT EXISTS oauth_tokens_client ON oauth_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS oauth_codes_client ON oauth_codes(client_id)`,
		`CREATE INDEX IF NOT EXISTS messages_publication ON messages(publication_id, received_at)`,
	} {
		if _, err := d.Exec(idx); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.DB.Close() }

var tokenEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewToken returns n random bytes as lowercase base32, safe in an email
// address and a URL.
func NewToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return tokenEncoding.EncodeToString(b)
}

// Address is a test address.
type Address struct {
	Token  string
	UserID string // empty for an anonymous address
	// Creator is the hash of the CSRF cookie of the browser that made an
	// anonymous address, or empty.
	Creator   string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateAddress makes an anonymous test address that accepts mail for ttl.
func (s *Store) CreateAddress(ctx context.Context, ttl time.Duration) (Address, error) {
	return s.CreateAddressFor(ctx, ttl, "")
}

// CreateAddressFor makes a test address owned by userID (none when empty).
func (s *Store) CreateAddressFor(ctx context.Context, ttl time.Duration, userID string) (Address, error) {
	return s.CreateAddressBy(ctx, ttl, userID, "")
}

// CreateAddressBy makes a test address owned by userID, or for an anonymous
// one, made by the browser whose CSRF cookie hashes to creator.
func (s *Store) CreateAddressBy(ctx context.Context, ttl time.Duration, userID, creator string) (Address, error) {
	now := s.Now().UTC()
	a := Address{Token: NewToken(10), UserID: userID, Creator: creator, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	var uid any
	if userID != "" {
		uid = userID
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO addresses (token, user_id, creator, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		a.Token, uid, creator, a.CreatedAt.Unix(), a.ExpiresAt.Unix())
	return a, err
}

// AddressByToken returns an address that has not expired.
func (s *Store) AddressByToken(ctx context.Context, token string) (Address, error) {
	a, err := s.AnyAddressByToken(ctx, token)
	if err == nil && !a.ExpiresAt.After(s.Now()) {
		return Address{}, ErrNotFound
	}
	return a, err
}

// AnyAddressByToken returns an address, expired or not, while Sweep keeps
// it (as long as any of its reports are kept). Waits use it, so a report
// that arrived just before expiry can still be fetched.
func (s *Store) AnyAddressByToken(ctx context.Context, token string) (Address, error) {
	var a Address
	var created, expires int64
	err := s.DB.QueryRowContext(ctx, `SELECT token, COALESCE(user_id, ''), creator, created_at, expires_at FROM addresses WHERE token = ?`,
		strings.ToLower(token)).Scan(&a.Token, &a.UserID, &a.Creator, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	a.CreatedAt, a.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(expires, 0).UTC()
	return a, err
}

// Expired reports whether the address no longer accepts mail.
func (a Address) Expired(now time.Time) bool { return !a.ExpiresAt.After(now) }

// Message is a stored message and its verdict.
type Message struct {
	ID    string
	Token string // empty for uploads and publications
	// UserID is the account of a signed-in upload or of the publication the
	// message was received for, or empty.
	UserID string
	// PublicationID is the monitored publication, or empty. Kind is
	// KindIssue or KindSignup for a publication's message, and empty
	// otherwise. SlotAt is the scheduled slot an issue counted for (zero
	// without a schedule), and Late is set when it arrived after the slot's
	// deadline.
	PublicationID string
	Kind          string
	SlotAt        time.Time
	Late          bool
	Source        string
	ReceivedAt    time.Time
	ExpiresAt     time.Time
	RemoteIP      string
	Helo          string
	MailFrom      string
	RcptTo        string
	TLS           *bool
	// Raw is written by SaveMessage but never loaded by the queries that
	// read a message, since it can be 25 MB; RawByID loads it.
	Raw     []byte
	Verdict *verdict.Verdict
}

// SaveMessage stores a message. ID is assigned and written into the verdict.
func (s *Store) SaveMessage(ctx context.Context, m *Message) error {
	m.ID = "rpt_" + NewToken(8)
	m.Verdict.ID = m.ID
	vj, err := json.Marshal(m.Verdict)
	if err != nil {
		return err
	}
	var tok, tls, uid, pub any
	if m.Token != "" {
		tok = m.Token
	}
	if m.PublicationID != "" {
		pub = m.PublicationID
	}
	var slot int64
	if !m.SlotAt.IsZero() {
		slot = m.SlotAt.Unix()
	}
	if m.UserID != "" {
		uid = m.UserID
	}
	if m.TLS != nil {
		tls = *m.TLS
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO messages
		(id, token, user_id, publication_id, kind, slot_at, late, source, received_at, expires_at, remote_ip, helo, mail_from, rcpt_to, tls, raw, verdict)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, tok, uid, pub, m.Kind, slot, m.Late, m.Source, m.ReceivedAt.Unix(), m.ExpiresAt.Unix(), m.RemoteIP, m.Helo, m.MailFrom, m.RcptTo, tls, m.Raw, string(vj))
	return err
}

const messageCols = `id, COALESCE(token, ''), COALESCE(user_id, ''), COALESCE(publication_id, ''), kind, slot_at, late, source, received_at, expires_at, remote_ip, helo, mail_from, rcpt_to, tls, verdict`

func scanMessage(row interface{ Scan(...any) error }) (*Message, error) {
	m := &Message{}
	var received, expires, slot int64
	var tls sql.NullBool
	var vj string
	if err := row.Scan(&m.ID, &m.Token, &m.UserID, &m.PublicationID, &m.Kind, &slot, &m.Late, &m.Source, &received, &expires, &m.RemoteIP, &m.Helo, &m.MailFrom, &m.RcptTo, &tls, &vj); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	m.ReceivedAt, m.ExpiresAt = time.Unix(received, 0).UTC(), time.Unix(expires, 0).UTC()
	if slot != 0 {
		m.SlotAt = time.Unix(slot, 0).UTC()
	}
	if tls.Valid {
		t := tls.Bool
		m.TLS = &t
	}
	m.Verdict = &verdict.Verdict{}
	if err := json.Unmarshal([]byte(vj), m.Verdict); err != nil {
		return nil, fmt.Errorf("stored verdict %s: %w", m.ID, err)
	}
	return m, nil
}

// MessageByID returns a message that has not expired.
func (s *Store) MessageByID(ctx context.Context, id string) (*Message, error) {
	return scanMessage(s.DB.QueryRowContext(ctx,
		`SELECT `+messageCols+` FROM messages WHERE id = ? AND expires_at > ?`, id, s.Now().Unix()))
}

// MessageForUser returns a report that has not expired, only when it was
// received at a test address the user owns, uploaded while signed in to the
// user's account, or received for one of the user's publications.
func (s *Store) MessageForUser(ctx context.Context, id, userID string) (*Message, error) {
	if userID == "" {
		return nil, ErrNotFound
	}
	return scanMessage(s.DB.QueryRowContext(ctx,
		`SELECT `+messageCols+` FROM messages WHERE id = ? AND expires_at > ?
		AND (token IN (SELECT token FROM addresses WHERE user_id = ?) OR user_id = ?)`, id, s.Now().Unix(), userID, userID))
}

// RawByID returns the raw message of a report that has not expired.
func (s *Store) RawByID(ctx context.Context, id string) ([]byte, error) {
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `SELECT raw FROM messages WHERE id = ? AND expires_at > ?`, id, s.Now().Unix()).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return raw, err
}

// LatestForToken returns the newest message received at a test address.
// With after set to one of the address's report IDs, it returns only a
// message saved after that report, so a second send to the same address is
// never answered with the first one's report. It returns ErrNotFound when
// there is no such message yet, and ErrUnknownAfter when after is not a
// report from this address.
func (s *Store) LatestForToken(ctx context.Context, token, after string) (*Message, error) {
	token = strings.ToLower(token)
	var since int64
	if after != "" {
		err := s.DB.QueryRowContext(ctx, `SELECT rowid FROM messages WHERE id = ? AND token = ?`, after, token).Scan(&since)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnknownAfter
		}
		if err != nil {
			return nil, err
		}
	}
	return scanMessage(s.DB.QueryRowContext(ctx,
		`SELECT `+messageCols+` FROM messages WHERE token = ? AND expires_at > ? AND rowid > ? ORDER BY rowid DESC LIMIT 1`,
		token, s.Now().Unix(), since))
}

// AddressGrace is how long past expiry Sweep keeps an address, so a message
// whose RCPT was accepted just before expiry can still be saved after its
// checks finish.
const AddressGrace = time.Hour

// Sweep deletes expired messages, addresses that expired more than
// AddressGrace ago and have no messages left, and expired sign-in links,
// sessions, usage counters, OAuth codes and tokens, known browsers, and
// alerts older than AlertKeep.
func (s *Store) Sweep(ctx context.Context) (int64, error) {
	now := s.Now()
	res, err := s.DB.ExecContext(ctx, `DELETE FROM messages WHERE expires_at <= ?`, now.Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	_, err = s.DB.ExecContext(ctx, `DELETE FROM addresses WHERE expires_at <= ?
		AND NOT EXISTS (SELECT 1 FROM messages WHERE messages.token = addresses.token)`, now.Add(-AddressGrace).Unix())
	if err != nil {
		return n, err
	}
	for _, table := range []string{"login_tokens", "sessions", "counters", "oauth_codes", "oauth_tokens", "known_browsers"} {
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM `+table+` WHERE expires_at <= ?`, now.Unix()); err != nil {
			return n, err
		}
	}
	// Alerts are kept a little longer than the longest history.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM alerts WHERE created_at <= ?`, now.Add(-AlertKeep).Unix()); err != nil {
		return n, err
	}
	return n, nil
}
