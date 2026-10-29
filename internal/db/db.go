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
	return &Store{DB: d, Now: time.Now}, nil
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
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateAddress makes a test address that accepts mail for ttl.
func (s *Store) CreateAddress(ctx context.Context, ttl time.Duration) (Address, error) {
	now := s.Now().UTC()
	a := Address{Token: NewToken(10), CreatedAt: now, ExpiresAt: now.Add(ttl)}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO addresses (token, created_at, expires_at) VALUES (?, ?, ?)`,
		a.Token, a.CreatedAt.Unix(), a.ExpiresAt.Unix())
	return a, err
}

// AddressByToken returns an address that has not expired.
func (s *Store) AddressByToken(ctx context.Context, token string) (Address, error) {
	var a Address
	var created, expires int64
	err := s.DB.QueryRowContext(ctx, `SELECT token, created_at, expires_at FROM addresses WHERE token = ? AND expires_at > ?`,
		strings.ToLower(token), s.Now().Unix()).Scan(&a.Token, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	a.CreatedAt, a.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(expires, 0).UTC()
	return a, err
}

// Message is a stored message and its verdict.
type Message struct {
	ID         string
	Token      string // empty for uploads
	Source     string
	ReceivedAt time.Time
	ExpiresAt  time.Time
	RemoteIP   string
	Helo       string
	MailFrom   string
	RcptTo     string
	TLS        *bool
	Raw        []byte
	Verdict    *verdict.Verdict
}

// SaveMessage stores a message. ID is assigned and written into the verdict.
func (s *Store) SaveMessage(ctx context.Context, m *Message) error {
	m.ID = "rpt_" + NewToken(8)
	m.Verdict.ID = m.ID
	vj, err := json.Marshal(m.Verdict)
	if err != nil {
		return err
	}
	var tok, tls any
	if m.Token != "" {
		tok = m.Token
	}
	if m.TLS != nil {
		tls = *m.TLS
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO messages
		(id, token, source, received_at, expires_at, remote_ip, helo, mail_from, rcpt_to, tls, raw, verdict)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, tok, m.Source, m.ReceivedAt.Unix(), m.ExpiresAt.Unix(), m.RemoteIP, m.Helo, m.MailFrom, m.RcptTo, tls, m.Raw, string(vj))
	return err
}

const messageCols = `id, COALESCE(token, ''), source, received_at, expires_at, remote_ip, helo, mail_from, rcpt_to, tls, raw, verdict`

func scanMessage(row interface{ Scan(...any) error }) (*Message, error) {
	m := &Message{}
	var received, expires int64
	var tls sql.NullBool
	var vj string
	if err := row.Scan(&m.ID, &m.Token, &m.Source, &received, &expires, &m.RemoteIP, &m.Helo, &m.MailFrom, &m.RcptTo, &tls, &m.Raw, &vj); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	m.ReceivedAt, m.ExpiresAt = time.Unix(received, 0).UTC(), time.Unix(expires, 0).UTC()
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

// LatestForToken returns the newest message received at a test address.
func (s *Store) LatestForToken(ctx context.Context, token string) (*Message, error) {
	return scanMessage(s.DB.QueryRowContext(ctx,
		`SELECT `+messageCols+` FROM messages WHERE token = ? AND expires_at > ? ORDER BY received_at DESC, rowid DESC LIMIT 1`,
		strings.ToLower(token), s.Now().Unix()))
}

// Sweep deletes expired messages and addresses with no messages left.
func (s *Store) Sweep(ctx context.Context) (int64, error) {
	now := s.Now().Unix()
	res, err := s.DB.ExecContext(ctx, `DELETE FROM messages WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	_, err = s.DB.ExecContext(ctx, `DELETE FROM addresses WHERE expires_at <= ?
		AND NOT EXISTS (SELECT 1 FROM messages WHERE messages.token = addresses.token)`, now)
	return n, err
}
