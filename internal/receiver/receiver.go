// Package receiver is the SMTP server that accepts mail for test addresses,
// runs the engine with the envelope it saw, and stores the verdict.
//
// It receives directly instead of through a forwarding service on purpose:
// SPF, reverse DNS, and TLS are only meaningful with the connecting IP and
// the unmodified message.
package receiver

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore/engine"
)

// MaxMessageBytes is the largest message accepted.
const MaxMessageBytes = 25 << 20

const (
	analyzeTimeout = 45 * time.Second
	saveTimeout    = 10 * time.Second
	// maxBodyTime bounds how long one message may take to arrive. Each read
	// of the body gets readTimeout, so a slow but steady sender is fine,
	// and a sender trickling bytes is cut off here.
	maxBodyTime = 10 * time.Minute
	// messagesPerSession is how many messages one connection may deliver.
	messagesPerSession = 10
)

// readTimeout bounds each read from a sender (a variable for tests).
var readTimeout = 60 * time.Second

// Defaults for the volume limits in Config.
const (
	DefaultMessagesPerAddress = 20
	DefaultDailyMessages      = 100
	DefaultMaxSessions        = 50
	DefaultMaxSessionsPerIP   = 5
)

// Config configures the receiver.
type Config struct {
	Addr string
	// MailDomain is the domain test addresses live on, such as
	// in.sendscore.ai. Mail for any other domain is refused.
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
}

// Receiver wraps the SMTP server.
type Receiver struct {
	cfg    Config
	store  *db.Store
	log    *slog.Logger
	server *smtp.Server
	// readTimeout is the package's, taken when the receiver is built.
	readTimeout time.Duration

	connMu sync.Mutex
	conns  map[string]int // open connections per IP, and "" for the total
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
	r := &Receiver{cfg: cfg, store: store, log: log, conns: map[string]int{}, readTimeout: readTimeout}
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
			ip = addr.IP.String()
		}
		if l.r.takeConn(ip) {
			return &countedConn{Conn: c, timeout: l.r.readTimeout, release: func() { l.r.releaseConn(ip) }}, nil
		}
		go func() {
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = c.Write([]byte("421 4.7.0 Too many connections, try again later\r\n"))
			_ = c.Close()
		}()
	}
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
// a whole buffer in one call.
type countedConn struct {
	net.Conn
	once      sync.Once
	release   func()
	timeout   time.Duration
	bodyUntil atomic.Int64 // Unix nanoseconds, or 0
}

func (c *countedConn) Read(p []byte) (int, error) {
	if end := c.bodyUntil.Load(); end != 0 {
		_ = c.Conn.SetReadDeadline(minTime(time.Now().Add(c.timeout), time.Unix(0, end)))
	}
	return c.Conn.Read(p)
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
	rcpt  string
	sent  int // messages delivered in this session
}

func (s *session) Reset() {
	s.from, s.token, s.owner, s.rcpt = "", "", "", ""
}

func (s *session) Logout() error { return nil }

var errBadSender = &smtp.SMTPError{Code: 501, EnhancedCode: smtp.EnhancedCode{5, 1, 7}, Message: "Invalid sender address"}

var errSessionFull = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 7, 0},
	Message: "Too many messages in one connection, send the rest in a new connection"}

var errTemporary = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Temporary failure, try again"}

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
	if !ok || domain != strings.ToLower(s.r.cfg.MailDomain) || !strings.HasPrefix(local, "t-") {
		return errNoMailbox
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
		return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "One test address per message, send to the others separately"}
	}
	return nil
}

// limit is one count a message is taken against.
type limit struct {
	name, bucket string
	limit        int
	keep         time.Duration
	err          *smtp.SMTPError
}

// limits are the counts a message to the address is taken against: the
// address's lifetime allowance, and its account's daily one.
func (r *Receiver) limits(token, owner string) []limit {
	ls := []limit{{"messages:addr:" + token, "all", r.cfg.MessagesPerAddress, 8 * 24 * time.Hour,
		&smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 2, 2},
			Message: fmt.Sprintf("This test address has taken its %d messages, get a new test address", r.cfg.MessagesPerAddress)}}}
	if owner != "" {
		ls = append(ls, limit{"messages:user:" + owner, db.Day(r.store.Now()), r.cfg.DailyMessages, 48 * time.Hour,
			&smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 2, 2},
				Message: fmt.Sprintf("This account has received its %d messages for today, try again after midnight UTC", r.cfg.DailyMessages)}})
	}
	return ls
}

func (s *session) Data(rd io.Reader) error {
	s.sent++
	ctx := context.Background()
	for _, l := range s.r.limits(s.token, s.owner) {
		if _, err := s.r.store.Take(ctx, l.name, l.bucket, l.limit, l.keep); err != nil {
			if errors.Is(err, db.ErrLimit) {
				return l.err
			}
			s.r.log.Error("message count", "err", err)
			return errTemporary
		}
	}
	// Each read of the body gets a fresh deadline, up to maxBodyTime in all,
	// so a large message over a slow link is not cut off.
	cc := counted(s.conn.Conn())
	if cc != nil {
		cc.bodyUntil.Store(time.Now().Add(maxBodyTime).UnixNano())
	}
	raw, err := io.ReadAll(io.LimitReader(rd, MaxMessageBytes+1))
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
	v, err := engine.Analyze(actx, stamped, engine.Options{
		Envelope: env, Resolver: s.r.cfg.Resolver, CheckLinks: s.r.cfg.CheckLinks,
		Blocklists: s.r.cfg.Blocklists, ReceivedAt: now,
	})
	sctx, cancel := context.WithTimeout(context.Background(), saveTimeout)
	defer cancel()
	if err != nil {
		return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: "Could not read the message: " + err.Error()}
	}
	m := &db.Message{
		Token: s.token, Source: "smtp", ReceivedAt: now, ExpiresAt: now.Add(s.r.cfg.ReportTTL),
		RemoteIP: ipString(s.ip), Helo: env.Helo, MailFrom: s.from, RcptTo: s.rcpt,
		TLS: &isTLS, Raw: stamped, Verdict: v,
	}
	if err := s.r.store.SaveMessage(sctx, m); err != nil {
		s.r.log.Error("save message", "err", err)
		return errTemporary
	}
	s.r.log.Info("received", "report", m.ID, "from", s.from, "ip", m.RemoteIP, "verdict", v.Verdict)
	return nil
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
