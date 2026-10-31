// Package db opens the SQLite database, applies the schema, and holds the
// queries the receiver and the web app share.
package db

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	// RawKeep is how long Sweep keeps the original of a message; the verdict
	// stays until the message expires. Zero keeps it as long as the message.
	RawKeep time.Duration
	// AlertKeep is how long Sweep keeps alerts, and the record of a recipient
	// that did not opt out. Zero means DefaultAlertKeep.
	AlertKeep time.Duration
	// recipientKey keys the hash of alert recipients.
	recipientKey []byte
}

// Defaults for what is stored, which the receiver and uploads share.
const (
	// DefaultDailyBytes is what one account, or anonymous senders together,
	// may store in a UTC day.
	DefaultDailyBytes = 1 << 30
	// DefaultAccountBytes is the originals one account, or anonymous senders
	// together, may have kept at once, so they cannot fill the server for
	// everyone else.
	DefaultAccountBytes = 2 << 30
	// DefaultMaxStorageBytes is the size of the database at which new mail
	// is turned away with a temporary refusal.
	DefaultMaxStorageBytes = 10 << 30
)

// journalLimit is the size SQLite cuts the WAL back to after a checkpoint, so
// a burst of large messages does not leave it at its high-water mark.
const journalLimit = 64 << 20

// Open opens (creating if needed) the SQLite database at path, with WAL, a
// busy timeout, foreign keys, immediate transactions, synchronous=NORMAL,
// which is safe with WAL and spares an fsync on every commit, and
// secure_delete, so deleted mail is overwritten and not just unlinked. The
// file holds raw mail, so it is readable by its owner only, and SQLite gives
// the -wal and -shm files the same mode.
func Open(path string) (*Store, error) {
	if err := private(path); err != nil {
		return nil, fmt.Errorf("db permissions: %w", err)
	}
	dsn := fmt.Sprintf(
		"file:%s?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(on)&_pragma=journal_size_limit(%d)",
		uriPath.Replace(path), journalLimit,
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
	key, err := recipientKey(d)
	if err != nil {
		return nil, fmt.Errorf("recipient key: %w", err)
	}
	return &Store{DB: d, Now: time.Now, recipientKey: key}, nil
}

// uriPath escapes what would end the path in a SQLite URI filename, so the
// file opened is the file private secured.
var uriPath = strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23")

// recipientKey returns this database's key for hashing alert recipients,
// making it the first time. With a key, a list of addresses cannot be hashed
// ahead of time, or compared across instances.
func recipientKey(d *sql.DB) ([]byte, error) {
	if _, err := d.Exec(`INSERT OR IGNORE INTO settings (name, value) VALUES ('recipient_key', randomblob(32))`); err != nil {
		return nil, err
	}
	var key []byte
	err := d.QueryRow(`SELECT value FROM settings WHERE name = 'recipient_key'`).Scan(&key)
	return key, err
}

// recipientHash is the keyed hash an alert recipient is stored under.
func (s *Store) recipientHash(email string) string {
	h := hmac.New(sha256.New, s.recipientKey)
	h.Write([]byte(NormalizeEmail(email)))
	return hex.EncodeToString(h.Sum(nil))
}

// private creates the database file if needed, and makes it and any -wal and
// -shm files readable by their owner only.
func private(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// migrate adds the columns that came after a table was first created, and a
// column that is already there is left alone. It then removes what billing
// left in an older database, and moves any original still in messages to
// message_raw, where Sweep drops it.
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
		// The hash of a monitoring address's message, so a sender's retry of
		// one already saved is not stored or compared a second time.
		`ALTER TABLE messages ADD COLUMN dedupe TEXT NOT NULL DEFAULT ''`,
		// An alert address waiting for its owner to confirm it, and the hash
		// and expiry of the link that does.
		`ALTER TABLE publications ADD COLUMN alert_pending TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE publications ADD COLUMN alert_confirm_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE publications ADD COLUMN alert_confirm_expires INTEGER NOT NULL DEFAULT 0`,
		// When a failed alert may be tried again (Unix seconds).
		`ALTER TABLE alerts ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0`,
		// The hash of the CSRF cookie of the browser that uploaded a message
		// anonymously, so its original shows only to that browser.
		`ALTER TABLE messages ADD COLUMN creator TEXT NOT NULL DEFAULT ''`,
		// Bytes of the original, 0 once it is dropped.
		`ALTER TABLE messages ADD COLUMN size INTEGER NOT NULL DEFAULT 0`,
		// When a recipient's opt-out link was last put in an alert.
		`ALTER TABLE alert_recipients ADD COLUMN last_used INTEGER NOT NULL DEFAULT 0`,
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
		`CREATE INDEX IF NOT EXISTS messages_dedupe ON messages(publication_id, dedupe) WHERE dedupe != ''`,
		`CREATE INDEX IF NOT EXISTS messages_received ON messages(received_at)`,
		`CREATE INDEX IF NOT EXISTS publications_confirm ON publications(alert_confirm_hash) WHERE alert_confirm_hash != ''`,
	} {
		if _, err := d.Exec(idx); err != nil {
			return err
		}
	}
	for _, q := range []string{
		`DROP TABLE IF EXISTS creem_events`,
		`DROP TABLE IF EXISTS subscriptions`,
		`INSERT OR IGNORE INTO message_raw (id, raw) SELECT id, raw FROM messages WHERE length(raw) > 0`,
		`UPDATE messages SET size = length(raw), raw = x'' WHERE length(raw) > 0`,
	} {
		if _, err := d.Exec(q); err != nil {
			return err
		}
	}
	if _, err := d.Exec(`ALTER TABLE users DROP COLUMN plan`); err != nil && !strings.Contains(err.Error(), "no such column") {
		return err
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
	// Dedupe is the hash of a monitoring address's message as it arrived.
	Dedupe string
	// Creator is the hash of the CSRF cookie of the browser that uploaded a
	// message anonymously, or empty.
	Creator    string
	Source     string
	ReceivedAt time.Time
	ExpiresAt  time.Time
	RemoteIP   string
	Helo       string
	MailFrom   string
	RcptTo     string
	TLS        *bool
	// Raw is written by SaveMessage to message_raw and never loaded by the
	// queries that read a message, since it can be 25 MB; RawByID loads it.
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
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after commit
	if _, err = tx.ExecContext(ctx, `INSERT INTO messages
		(id, token, user_id, publication_id, kind, slot_at, late, dedupe, creator, source, received_at, expires_at, remote_ip, helo, mail_from, rcpt_to, tls, raw, size, verdict)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, x'', ?, ?)`,
		m.ID, tok, uid, pub, m.Kind, slot, m.Late, m.Dedupe, m.Creator, m.Source, m.ReceivedAt.Unix(), m.ExpiresAt.Unix(), m.RemoteIP, m.Helo, m.MailFrom, m.RcptTo, tls, len(m.Raw), string(vj)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO message_raw (id, raw) VALUES (?, ?)`, m.ID, m.Raw); err != nil {
		return err
	}
	return tx.Commit()
}

const messageCols = `id, COALESCE(token, ''), COALESCE(user_id, ''), COALESCE(publication_id, ''), kind, slot_at, late, creator, source, received_at, expires_at, remote_ip, helo, mail_from, rcpt_to, tls, verdict`

func scanMessage(row interface{ Scan(...any) error }) (*Message, error) {
	m := &Message{}
	var received, expires, slot int64
	var tls sql.NullBool
	var vj string
	if err := row.Scan(&m.ID, &m.Token, &m.UserID, &m.PublicationID, &m.Kind, &slot, &m.Late, &m.Creator, &m.Source, &received, &expires, &m.RemoteIP, &m.Helo, &m.MailFrom, &m.RcptTo, &tls, &vj); err != nil {
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
	// No row once dropped after SENDSCORE_RAW_DAYS; the report itself stays.
	err := s.DB.QueryRowContext(ctx, `SELECT r.raw FROM message_raw r JOIN messages m ON m.id = r.id
		WHERE r.id = ? AND m.expires_at > ?`, id, s.Now().Unix()).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return raw, err
}

// StoredBytes is the size of the originals kept for an account, or with
// userID empty, for anonymous test addresses and uploads together.
func (s *Store) StoredBytes(ctx context.Context, userID string) (int64, error) {
	var n int64
	q := `SELECT COALESCE(SUM(size), 0) FROM messages WHERE user_id = ?1 OR token IN (SELECT token FROM addresses WHERE user_id = ?1)`
	if userID == "" {
		q = `SELECT COALESCE(SUM(size), 0) FROM messages WHERE user_id IS NULL AND publication_id IS NULL
			AND (token IS NULL OR token IN (SELECT token FROM addresses WHERE user_id IS NULL))`
		err := s.DB.QueryRowContext(ctx, q).Scan(&n)
		return n, err
	}
	err := s.DB.QueryRowContext(ctx, q, userID).Scan(&n)
	return n, err
}

// MessageByDedupe returns a publication's message with this hash received
// since a time, or ErrNotFound.
func (s *Store) MessageByDedupe(ctx context.Context, pubID, hash string, since time.Time) (*Message, error) {
	return scanMessage(s.DB.QueryRowContext(ctx, `SELECT `+messageCols+` FROM messages
		WHERE publication_id = ? AND dedupe = ? AND received_at >= ? AND expires_at > ? ORDER BY rowid LIMIT 1`,
		pubID, hash, since.Unix(), s.Now().Unix()))
}

// IssueBefore returns the publication's newest issue saved before the
// message id, or ErrNotFound.
func (s *Store) IssueBefore(ctx context.Context, pubID, id string) (*Message, error) {
	return scanMessage(s.DB.QueryRowContext(ctx, `SELECT `+messageCols+` FROM messages
		WHERE publication_id = ? AND kind = ? AND expires_at > ?
		AND rowid < (SELECT rowid FROM messages WHERE id = ?) ORDER BY rowid DESC LIMIT 1`,
		pubID, KindIssue, s.Now().Unix(), id))
}

// SetMessageKind corrects whether a publication's message is an issue or a
// signup message, with the slot it counts for.
func (s *Store) SetMessageKind(ctx context.Context, pubID, id, kind string, slot time.Time, late bool) error {
	var at int64
	if !slot.IsZero() {
		at = slot.Unix()
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE messages SET kind = ?, slot_at = ?, late = ? WHERE id = ? AND publication_id = ?`, kind, at, late, id, pubID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
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
// AddressGrace ago and have no messages left, originals older than RawKeep,
// and expired sign-in links, sessions, usage counters, OAuth codes and
// tokens, known browsers, alerts older than AlertKeep, and recipients unused
// for as long who did not opt out. A step that fails does not stop the ones
// after it; the errors come back together.
func (s *Store) Sweep(ctx context.Context) (int64, error) {
	now := s.Now()
	var errs []error
	exec := func(q string, args ...any) int64 {
		res, err := s.DB.ExecContext(ctx, q, args...)
		if err != nil {
			errs = append(errs, err)
			return 0
		}
		n, _ := res.RowsAffected()
		return n
	}
	n := exec(`DELETE FROM messages WHERE expires_at <= ?`, now.Unix())
	exec(`DELETE FROM addresses WHERE expires_at <= ?
		AND NOT EXISTS (SELECT 1 FROM messages WHERE messages.token = addresses.token)`, now.Add(-AddressGrace).Unix())
	if s.RawKeep > 0 {
		cutoff := now.Add(-s.RawKeep).Unix()
		exec(`DELETE FROM message_raw WHERE id IN (SELECT id FROM messages WHERE received_at <= ?)`, cutoff)
		exec(`UPDATE messages SET size = 0 WHERE received_at <= ? AND size != 0`, cutoff)
	}
	for _, table := range []string{"login_tokens", "sessions", "counters", "oauth_codes", "oauth_tokens", "known_browsers"} {
		exec(`DELETE FROM `+table+` WHERE expires_at <= ?`, now.Unix())
	}
	keep := s.AlertKeep
	if keep == 0 {
		keep = DefaultAlertKeep
	}
	exec(`DELETE FROM alerts WHERE created_at <= ?`, now.Add(-keep).Unix())
	exec(`DELETE FROM alert_recipients WHERE stopped_at = 0 AND MAX(created_at, last_used) <= ?`, now.Add(-keep).Unix())
	return n, errors.Join(errs...)
}

// SizeBytes is how much of the database is in use. It does not count pages
// that are free for reuse, so a sweep brings it back down.
func (s *Store) SizeBytes(ctx context.Context) (int64, error) {
	var n int64
	err := s.DB.QueryRowContext(ctx, `SELECT (page_count - freelist_count) * page_size
		FROM pragma_page_count(), pragma_freelist_count(), pragma_page_size()`).Scan(&n)
	return n, err
}

// Backup writes a consistent copy of the database to a new file, while the
// app keeps running. It refuses a path that already exists. The file is made
// first, readable by its owner only, so no copy of the mail is ever open to
// others while it is written, and a failed backup leaves nothing behind.
func (s *Store) Backup(ctx context.Context, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists", path)
		}
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}
