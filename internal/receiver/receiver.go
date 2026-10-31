// Package receiver is the SMTP server that accepts mail for test addresses
// and monitored publications, runs the engine with the envelope it saw, and
// stores the verdict.
//
// It receives directly instead of through a forwarding service on purpose:
// SPF, reverse DNS, and TLS are only meaningful with the connecting IP and
// the unmodified message.
package receiver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/mail"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore-app/internal/monitor"
	"github.com/sendscore/sendscore/engine"
)

// MaxMessageBytes is the largest message accepted.
const MaxMessageBytes = 25 << 20

const (
	analyzeTimeout = 45 * time.Second
	saveTimeout    = 10 * time.Second
	alertTimeout   = 30 * time.Second
	// maxBodyTime bounds how long one message may take to arrive. Each read
	// of the body gets readTimeout, so a slow but steady sender is fine,
	// and a sender trickling bytes is cut off here.
	maxBodyTime = 10 * time.Minute
	// messagesPerSession is how many messages one connection may deliver.
	messagesPerSession = 10
	// analyzeWait is how long a message waits for a turn to be checked
	// before the sender is told to try again.
	analyzeWait = 30 * time.Second
	// dedupeWindow is how far back a sender's retry is recognized, longer
	// than the days a mail server keeps retrying.
	dedupeWindow = 7 * 24 * time.Hour
)

// readTimeout bounds each read from a sender, and maxSessionTime one whole
// connection, however busy, so a slot cannot be held forever with NOOPs
// (variables for tests).
var (
	readTimeout    = 60 * time.Second
	maxSessionTime = 20 * time.Minute
)

// Defaults for the volume limits in Config.
const (
	DefaultMessagesPerAddress = 20
	DefaultDailyMessages      = 1000
	DefaultMaxSessions        = 50
	DefaultMaxSessionsPerIP   = 5
	// A monitoring address takes this many messages a UTC day, far more
	// than any newsletter sends.
	DefaultPublicationDailyMessages = 50
	// DefaultDailyBytes is what one account, or anonymous senders together,
	// may have stored in a UTC day, across test and monitoring addresses.
	DefaultDailyBytes = 1 << 30
	// DefaultAnonDailyMessages is what all anonymous test addresses accept
	// in a UTC day, together.
	DefaultAnonDailyMessages = 200
	// DefaultMaxStorageBytes is the size of the database at which new mail
	// is turned away with a temporary refusal.
	DefaultMaxStorageBytes = 10 << 30
	// DefaultMaxBufferedBytes bounds messages held in memory across all
	// sessions, and DefaultMaxAnalyzing the messages checked at once.
	DefaultMaxBufferedBytes = 256 << 20
	DefaultMaxAnalyzing     = 8
)

// Config configures the receiver.
type Config struct {
	Addr string
	// MailDomain is the domain test addresses live on, such as
	// in.example.com. Mail for any other domain is refused.
	MailDomain string
	// ReportTTL is how long a received message and its report are kept.
	ReportTTL time.Duration
	// Resolver overrides DNS (tests).
	Resolver engine.Resolver
	// CheckLinks fetches links in received messages.
	CheckLinks bool
	// Blocklists are the domain blocklists link domains are looked up on.
	Blocklists []engine.Blocklist
	// TLS enables STARTTLS. Without it, every message arrives in plain text
	// and auth.tls fails, so production must set it.
	TLS *tls.Config
	// MessagesPerAddress is how many messages one test address takes in its
	// life. DailyMessages is how many messages an account's addresses take
	// per UTC day, together. MaxSessions and MaxSessionsPerIP bound open
	// connections, in all and per sending IP. Zero means the default.
	MessagesPerAddress int
	DailyMessages      int
	MaxSessions        int
	MaxSessionsPerIP   int
	// PublicationDailyMessages is how many messages one monitoring address
	// takes per UTC day. Zero means the default.
	PublicationDailyMessages int
	// DailyBytes is how much one account, or anonymous senders together, may
	// have stored in a UTC day. AnonDailyMessages is what all anonymous
	// addresses accept in a UTC day. MaxStorageBytes is the database size at
	// which mail is refused. MaxBufferedBytes bounds messages in memory, and
	// MaxAnalyzing the messages checked at once. Zero means the default.
	DailyBytes        int
	AnonDailyMessages int
	MaxStorageBytes   int64
	MaxBufferedBytes  int64
	MaxAnalyzing      int
	// HistoryTTL is how long a publication's messages are kept.
	// Other publication messages are kept for ReportTTL.
	HistoryTTL time.Duration
	// Monitor is told about each publication message once it is saved, to
	// send alerts. Nil sends none.
	Monitor *monitor.Monitor
}

// Receiver wraps the SMTP server.
type Receiver struct {
	cfg    Config
	store  *db.Store
	log    *slog.Logger
	server *smtp.Server
	// readTimeout is the package's, taken when the receiver is built.
	readTimeout time.Duration
	sessionTime time.Duration

	connMu sync.Mutex
	conns  map[string]int // open connections per IP, and "" for the total

	buffered  atomic.Int64  // bytes of messages held in memory
	analyzing chan struct{} // a slot per message being checked
}

// New builds a receiver.
func New(cfg Config, store *db.Store, log *slog.Logger) *Receiver {
	if cfg.MessagesPerAddress == 0 {
		cfg.MessagesPerAddress = DefaultMessagesPerAddress
	}
	if cfg.DailyMessages == 0 {
		cfg.DailyMessages = DefaultDailyMessages
	}
	if cfg.MaxSessions == 0 {
		cfg.MaxSessions = DefaultMaxSessions
	}
	if cfg.MaxSessionsPerIP == 0 {
		cfg.MaxSessionsPerIP = DefaultMaxSessionsPerIP
	}
	if cfg.PublicationDailyMessages == 0 {
		cfg.PublicationDailyMessages = DefaultPublicationDailyMessages
	}
	if cfg.HistoryTTL == 0 {
		cfg.HistoryTTL = cfg.ReportTTL
	}
	if cfg.DailyBytes == 0 {
		cfg.DailyBytes = DefaultDailyBytes
	}
	if cfg.AnonDailyMessages == 0 {
		cfg.AnonDailyMessages = DefaultAnonDailyMessages
	}
	if cfg.MaxStorageBytes == 0 {
		cfg.MaxStorageBytes = DefaultMaxStorageBytes
	}
	if cfg.MaxBufferedBytes == 0 {
		cfg.MaxBufferedBytes = DefaultMaxBufferedBytes
	}
	if cfg.MaxAnalyzing == 0 {
		cfg.MaxAnalyzing = DefaultMaxAnalyzing
	}
	r := &Receiver{cfg: cfg, store: store, log: log, conns: map[string]int{}, readTimeout: readTimeout, sessionTime: maxSessionTime,
		analyzing: make(chan struct{}, cfg.MaxAnalyzing)}
	s := smtp.NewServer(r)
	s.Addr = cfg.Addr
	s.Domain = cfg.MailDomain
	s.MaxMessageBytes = MaxMessageBytes
	// A transaction is for one test address (see Rcpt); the cap only bounds
	// how often a sender may repeat that address.
	s.MaxRecipients = 10
	s.ReadTimeout = r.readTimeout
	s.WriteTimeout = 60 * time.Second
	s.TLSConfig = cfg.TLS
	r.server = s
	return r
}

// ListenAndServe serves until Close.
func (r *Receiver) ListenAndServe() error {
	l, err := net.Listen("tcp", r.cfg.Addr)
	if err != nil {
		return err
	}
	return r.Serve(l)
}

// Serve serves on an existing listener.
func (r *Receiver) Serve(l net.Listener) error {
	return r.server.Serve(&limitListener{Listener: l, r: r})
}

// limitListener turns away a connection past MaxSessions in all or
// MaxSessionsPerIP from one address, with a 421 so the sender retries.
type limitListener struct {
	net.Listener
	r *Receiver
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := ""
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			ip = connKey(addr.IP)
		}
		if l.r.takeConn(ip) {
			return &countedConn{Conn: c, timeout: l.r.readTimeout, end: time.Now().Add(l.r.sessionTime), release: func() { l.r.releaseConn(ip) }}, nil
		}
		go func() {
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = c.Write([]byte("421 4.7.0 Too many connections, try again later\r\n"))
			_ = c.Close()
		}()
	}
}

// connKey is what sessions are counted against: an IPv4 address, or an IPv6
// /64, since one host usually has the whole network.
func connKey(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (r *Receiver) takeConn(ip string) bool {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	if r.conns[""] >= r.cfg.MaxSessions || r.conns[ip] >= r.cfg.MaxSessionsPerIP {
		return false
	}
	r.conns[""]++
	r.conns[ip]++
	return true
}

func (r *Receiver) releaseConn(ip string) {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	r.conns[""]--
	if r.conns[ip]--; r.conns[ip] <= 0 {
		delete(r.conns, ip)
	}
}

// countedConn gives its slot back once, when closed. While a message body
// is arriving (bodyUntil is set), each read gets a fresh read deadline,
// because go-smtp sets one only for the DATA line and its body reader fills
// a whole buffer in one call. No read deadline ever passes end, which is what
// bounds a whole session.
type countedConn struct {
	net.Conn
	once      sync.Once
	release   func()
	timeout   time.Duration
	end       time.Time
	bodyUntil atomic.Int64 // Unix nanoseconds, or 0
}

func (c *countedConn) Read(p []byte) (int, error) {
	if end := c.bodyUntil.Load(); end != 0 {
		_ = c.Conn.SetReadDeadline(minTime(minTime(time.Now().Add(c.timeout), time.Unix(0, end)), c.end))
	}
	return c.Conn.Read(p)
}

// SetReadDeadline keeps every deadline go-smtp sets within the session.
func (c *countedConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		t = c.end
	}
	return c.Conn.SetReadDeadline(minTime(t, c.end))
}

// SetDeadline is SetReadDeadline with a write deadline.
func (c *countedConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.SetReadDeadline(t)
}

// counted finds the countedConn under a session's connection, which is a
// tls.Conn after STARTTLS.
func counted(c net.Conn) *countedConn {
	if t, ok := c.(*tls.Conn); ok {
		c = t.NetConn()
	}
	cc, _ := c.(*countedConn)
	return cc
}

func (c *countedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// Close stops the server, dropping open sessions.
func (r *Receiver) Close() error { return r.server.Close() }

// Shutdown stops accepting connections and waits until open sessions end or
// ctx is done, so a message in DATA can finish its checks and be saved.
func (r *Receiver) Shutdown(ctx context.Context) error { return r.server.Shutdown(ctx) }

// NewSession implements smtp.Backend.
func (r *Receiver) NewSession(c *smtp.Conn) (smtp.Session, error) {
	s := &session{r: r, conn: c}
	if addr, ok := c.Conn().RemoteAddr().(*net.TCPAddr); ok {
		s.ip = addr.IP
	}
	return s, nil
}

type session struct {
	r     *Receiver
	conn  *smtp.Conn
	ip    net.IP
	from  string
	token string
	owner string // the account the address belongs to, or empty
	// pub is the monitored publication when the recipient is an m- address.
	pub  *db.Publication
	rcpt string
	sent int // messages delivered in this session
}

func (s *session) Reset() {
	s.from, s.token, s.owner, s.rcpt, s.pub = "", "", "", "", nil
}

func (s *session) Logout() error { return nil }

var errBadSender = &smtp.SMTPError{Code: 501, EnhancedCode: smtp.EnhancedCode{5, 1, 7}, Message: "Invalid sender address"}

var errSessionFull = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 7, 0},
	Message: "Too many messages in one connection, send the rest in a new connection"}

var errTemporary = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Temporary failure, try again"}

var errBusy = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 2}, Message: "Too many messages are being checked right now, try again later"}

var errStorageFull = &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 3, 1}, Message: "This server is out of storage for messages, try again later"}

// storageFull reports whether the database has reached MaxStorageBytes. A
// failed check lets the message through, since a full disk fails on its own.
func (r *Receiver) storageFull(ctx context.Context) bool {
	n, err := r.store.SizeBytes(ctx)
	if err != nil {
		r.log.Error("database size", "err", err)
		return false
	}
	if n >= r.cfg.MaxStorageBytes {
		r.log.Error("refusing mail: the database reached SENDSCORE_MAX_STORAGE_MB", "bytes", n)
		return true
	}
	return false
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if s.sent >= messagesPerSession {
		return errSessionFull
	}
	// The sender is written into Return-Path, so refuse anything that could
	// break that header. go-smtp lets a bare CR through, and unquotes a
	// quoted local part that may hold angle brackets.
	for _, c := range from {
		if c < 0x20 || c == 0x7f || c == '<' || c == '>' {
			s.from = ""
			return errBadSender
		}
	}
	s.from = from
	return nil
}

var errNoMailbox = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "No such test address, or it has expired"}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	local, domain, ok := strings.Cut(strings.ToLower(strings.Trim(to, "<>")), "@")
	if !ok || domain != strings.ToLower(s.r.cfg.MailDomain) {
		return errNoMailbox
	}
	if s.r.storageFull(context.Background()) {
		return errStorageFull
	}
	if strings.HasPrefix(local, "m-") {
		return s.rcptPublication(to, strings.TrimPrefix(local, "m-"))
	}
	if !strings.HasPrefix(local, "t-") {
		return errNoMailbox
	}
	if s.pub != nil {
		return errOneRecipient
	}
	token := strings.TrimPrefix(local, "t-")
	addr, err := s.r.store.AddressByToken(context.Background(), token)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return errNoMailbox
		}
		s.r.log.Error("address lookup", "err", err)
		return errTemporary
	}
	// Refuse here when a limit is already used up, so the body is never
	// sent; Data counts the message.
	for _, l := range s.r.limits(addr.Token, addr.UserID) {
		n, err := s.r.store.Count(context.Background(), l.name, l.bucket)
		if err != nil {
			s.r.log.Error("message count", "err", err)
			return errTemporary
		}
		if n >= l.limit {
			return l.err
		}
	}
	switch {
	case s.token == "":
		s.token, s.owner, s.rcpt = token, addr.UserID, to
	case s.token != token:
		// One test address per transaction, so a message is stored once.
		// RFC 5321 has the client send the rest in another transaction.
		return errOneRecipient
	}
	return nil
}

var errOneRecipient = &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "One test address per message, send to the others separately"}

var errNoPublication = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "No such monitoring address"}

// rcptPublication accepts a monitoring address, which never expires. A
// paused publication still accepts and stores mail; it only sends no alerts.
func (s *session) rcptPublication(to, token string) error {
	if s.token != "" {
		return errOneRecipient
	}
	p, err := s.r.store.PublicationByToken(context.Background(), token)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return errNoPublication
		}
		s.r.log.Error("publication lookup", "err", err)
		return errTemporary
	}
	if s.pub != nil {
		if s.pub.ID != p.ID {
			return errOneRecipient
		}
		return nil
	}
	l := s.r.publicationLimit(p.ID)
	n, err := s.r.store.Count(context.Background(), l.name, l.bucket)
	if err != nil {
		s.r.log.Error("message count", "err", err)
		return errTemporary
	}
	if n >= l.limit {
		return l.err
	}
	s.pub, s.owner, s.rcpt = &p, p.UserID, to
	return nil
}

// publicationLimit is the daily count a monitoring address's messages are
// taken against. It does not count against the account's test messages, so
// a burst of tests cannot cost an issue; the account's bytes cover both.
func (r *Receiver) publicationLimit(pubID string) limit {
	return limit{name: "messages:pub:" + pubID, bucket: db.Day(r.store.Now()), limit: r.cfg.PublicationDailyMessages, keep: 48 * time.Hour,
		err: &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 2, 2},
			Message: fmt.Sprintf("This monitoring address has received its %d messages for today, try again after midnight UTC", r.cfg.PublicationDailyMessages)}}
}

// limit is one count a message is taken against.
type limit struct {
	name, bucket string
	limit        int
	keep         time.Duration
	err          *smtp.SMTPError
	n            int // how much one message counts for, 1 when zero
}

// bytesLimit is the daily count of bytes stored for an account, or for
// anonymous senders together.
func (r *Receiver) bytesLimit(owner string, n int) limit {
	name := "bytes:anon"
	if owner != "" {
		name = "bytes:user:" + owner
	}
	return limit{name: name, bucket: db.Day(r.store.Now()), limit: r.cfg.DailyBytes, keep: 48 * time.Hour, n: n,
		err: &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 2, 2},
			Message: "This account has stored all it may for today, try again after midnight UTC"}}
}

// limits are the counts a message to the address is taken against: the
// address's lifetime allowance, and its account's daily one, or for an
// anonymous address, what all of them take together.
func (r *Receiver) limits(token, owner string) []limit {
	ls := []limit{{name: "messages:addr:" + token, bucket: "all", limit: r.cfg.MessagesPerAddress, keep: 8 * 24 * time.Hour,
		err: &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 2, 2},
			Message: fmt.Sprintf("This test address has taken its %d messages, get a new test address", r.cfg.MessagesPerAddress)}}}
	if owner != "" {
		return append(ls, limit{name: "messages:user:" + owner, bucket: db.Day(r.store.Now()), limit: r.cfg.DailyMessages, keep: 48 * time.Hour,
			err: &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 2, 2},
				Message: fmt.Sprintf("This account has received its %d messages for today, try again after midnight UTC", r.cfg.DailyMessages)}})
	}
	return append(ls, limit{name: "messages:anon", bucket: db.Day(r.store.Now()), limit: r.cfg.AnonDailyMessages, keep: 48 * time.Hour,
		err: &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 2, 2},
			Message: "Test addresses have taken all they may for today, try again after midnight UTC"}})
}

// readBody reads a message into memory, charging it against
// MaxBufferedBytes as it arrives, at twice its size since stamping copies it.
// The charge stands until release is called.
func (r *Receiver) readBody(rd io.Reader) ([]byte, func(), error) {
	var buf bytes.Buffer
	var charged int64
	release := func() { r.buffered.Add(-charged) }
	src := io.LimitReader(rd, MaxMessageBytes+1)
	chunk := make([]byte, 64<<10)
	for {
		n, err := src.Read(chunk)
		buf.Write(chunk[:n])
		charged += 2 * int64(n)
		if r.buffered.Add(2*int64(n)) > r.cfg.MaxBufferedBytes {
			return nil, release, errBusy
		}
		if errors.Is(err, io.EOF) {
			return buf.Bytes(), release, nil
		}
		if err != nil {
			return nil, release, err
		}
	}
}

// redelivered handles a retry of a message already saved, as when the sender
// never saw the 250 because the process stopped or it timed out. The message
// is not stored or counted twice. Alerts are decided again, each sent once,
// so one lost in the stop still goes out.
func (r *Receiver) redelivered(p db.Publication, hash string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), alertTimeout)
	defer cancel()
	m, err := r.store.MessageByDedupe(ctx, p.ID, hash, r.store.Now().Add(-dedupeWindow))
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			r.log.Error("message lookup", "publication", p.ID, "err", err)
		}
		return false
	}
	r.log.Info("redelivered", "report", m.ID, "publication", p.ID)
	if r.cfg.Monitor == nil {
		return true
	}
	prev, err := r.store.IssueBefore(ctx, p.ID, m.ID)
	if errors.Is(err, db.ErrNotFound) {
		prev = nil
	} else if err != nil {
		r.log.Error("previous issue", "publication", p.ID, "err", err)
		return true
	}
	r.cfg.Monitor.Received(ctx, p, m, prev)
	return true
}

func (s *session) Data(rd io.Reader) error {
	s.sent++
	ctx := context.Background()
	// Each read of the body gets a fresh deadline, up to maxBodyTime in all,
	// so a large message over a slow link is not cut off.
	cc := counted(s.conn.Conn())
	if cc != nil {
		cc.bodyUntil.Store(time.Now().Add(maxBodyTime).UnixNano())
	}
	raw, release, err := s.r.readBody(rd)
	defer release()
	if cc != nil {
		cc.bodyUntil.Store(0)
	}
	if err != nil {
		var se *smtp.SMTPError
		if errors.As(err, &se) {
			return se
		}
		// A timeout or a broken connection is temporary, so the sender
		// retries instead of bouncing the message.
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 2}, Message: "The message did not arrive in time, try again"}
	}
	if len(raw) > MaxMessageBytes {
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message too large"}
	}
	dedupe := ""
	if s.pub != nil {
		sum := sha256.Sum256(raw)
		dedupe = hex.EncodeToString(sum[:])
		if s.r.redelivered(*s.pub, dedupe) {
			return nil
		}
	}
	if s.r.storageFull(ctx) {
		return errStorageFull
	}
	// A turn to be checked, held from here to the save.
	wait := time.NewTimer(analyzeWait)
	defer wait.Stop()
	select {
	case s.r.analyzing <- struct{}{}:
		defer func() { <-s.r.analyzing }()
	case <-wait.C:
		return errBusy
	}
	// The allowances count a message that arrived, all of them or none, so a
	// stalled or refused body costs the sender nothing.
	ls := s.r.limits(s.token, s.owner)
	if s.pub != nil {
		ls = []limit{s.r.publicationLimit(s.pub.ID)}
	}
	ls = append(ls, s.r.bytesLimit(s.owner, len(raw)))
	caps := make([]db.Cap, len(ls))
	for i, l := range ls {
		caps[i] = db.Cap{Name: l.name, Bucket: l.bucket, Limit: l.limit, N: l.n, Keep: l.keep}
	}
	if i, err := s.r.store.TakeAll(ctx, caps); err != nil {
		if errors.Is(err, db.ErrLimit) {
			return ls[i].err
		}
		s.r.log.Error("message count", "err", err)
		return errTemporary
	}
	_, isTLS := s.conn.TLSConnectionState()
	env := engine.Envelope{RemoteIP: s.ip, Helo: s.conn.Hostname(), MailFrom: s.from, TLS: &isTLS}

	// The receiving server records the envelope sender, as any MTA does.
	stamped := stripReturnPath("Return-Path: <"+s.from+">\r\n", raw)
	raw = nil

	// The checks get their own deadline, and saving gets a fresh one, so slow
	// DNS can never cost a report that was already checked.
	actx, acancel := context.WithTimeout(context.Background(), analyzeTimeout)
	defer acancel()
	now := s.r.store.Now().UTC()
	opts := engine.Options{
		Envelope: env, Resolver: s.r.cfg.Resolver, CheckLinks: s.r.cfg.CheckLinks,
		Blocklists: s.r.cfg.Blocklists, ReceivedAt: now,
	}
	m := &db.Message{
		Token: s.token, Source: "smtp", ReceivedAt: now, ExpiresAt: now.Add(s.r.cfg.ReportTTL),
		RemoteIP: ipString(s.ip), Helo: env.Helo, MailFrom: s.from, RcptTo: s.rcpt,
		TLS: &isTLS, Raw: stamped, Dedupe: dedupe,
	}
	var prev *db.Message
	if s.pub != nil {
		prev = s.r.preparePublication(actx, *s.pub, m, stamped, &opts)
	}
	v, err := engine.Analyze(actx, stamped, opts)
	sctx, cancel := context.WithTimeout(context.Background(), saveTimeout)
	defer cancel()
	if err != nil {
		return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: "Could not read the message: " + err.Error()}
	}
	m.Verdict = v
	if s.pub != nil {
		v.Publication = s.pub.ID
	}
	if err := s.r.store.SaveMessage(sctx, m); err != nil {
		s.r.log.Error("save message", "err", err)
		return errTemporary
	}
	s.r.log.Info("received", "report", m.ID, "from", s.from, "ip", m.RemoteIP, "verdict", v.Verdict, "publication", m.PublicationID)
	if s.pub != nil && s.r.cfg.Monitor != nil {
		// Its own deadline, covering an alert's send.
		mctx, mcancel := context.WithTimeout(context.Background(), alertTimeout)
		defer mcancel()
		s.r.cfg.Monitor.Received(mctx, *s.pub, m, prev)
	}
	return nil
}

// preparePublication fills in a publication's message before its checks:
// the owner, how long it is kept, whether it is an issue or a signup
// message (a subscription confirmation or welcome email), and for an issue,
// its slot and the previous issue to compare with, which it returns.
func (r *Receiver) preparePublication(ctx context.Context, p db.Publication, m *db.Message, raw []byte, opts *engine.Options) *db.Message {
	m.PublicationID, m.UserID, m.Kind = p.ID, p.UserID, db.KindIssue
	m.ExpiresAt = m.ReceivedAt.Add(r.cfg.HistoryTTL)
	prev, err := r.store.LatestIssue(ctx, p.ID)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		r.log.Error("previous issue", "publication", p.ID, "err", err)
	}
	if monitor.IsSignup(subject(raw), errors.Is(err, db.ErrNotFound)) {
		m.Kind = db.KindSignup
		return nil
	}
	if s, ok := monitor.ScheduleOf(p); ok {
		m.SlotAt, m.Late = s.Place(m.ReceivedAt)
	}
	if err != nil {
		return nil
	}
	opts.Previous = prev.Verdict.Fingerprint
	return prev
}

// subject reads a message's decoded Subject, or empty.
func subject(raw []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	s := msg.Header.Get("Subject")
	if d, err := new(mime.WordDecoder).DecodeHeader(s); err == nil {
		s = d
	}
	return s
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// stripReturnPath returns the message with prefix in front and any
// Return-Path the sender put in it dropped; only the receiving server may
// write it. It copies the message once.
func stripReturnPath(prefix string, raw []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(prefix) + len(raw))
	out.WriteString(prefix)
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 {
		end = bytes.Index(raw, []byte("\n\n"))
	}
	if end < 0 {
		out.Write(raw)
		return out.Bytes()
	}
	lines := bytes.SplitAfter(raw[:end], []byte("\n"))
	skip := false
	for _, l := range lines {
		if len(l) > 0 && (l[0] == ' ' || l[0] == '\t') {
			if !skip {
				out.Write(l)
			}
			continue
		}
		skip = bytes.HasPrefix(bytes.ToLower(l), []byte("return-path:"))
		if !skip {
			out.Write(l)
		}
	}
	out.Write(raw[end:])
	return out.Bytes()
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
