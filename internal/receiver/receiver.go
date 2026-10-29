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
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore/engine"
	"github.com/sendscore/sendscore/verdict"
)

// MaxMessageBytes is the largest message accepted.
const MaxMessageBytes = 25 << 20

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
}

// Receiver wraps the SMTP server.
type Receiver struct {
	cfg    Config
	store  *db.Store
	log    *slog.Logger
	server *smtp.Server
}

// New builds a receiver.
func New(cfg Config, store *db.Store, log *slog.Logger) *Receiver {
	r := &Receiver{cfg: cfg, store: store, log: log}
	s := smtp.NewServer(r)
	s.Addr = cfg.Addr
	s.Domain = cfg.MailDomain
	s.MaxMessageBytes = MaxMessageBytes
	s.MaxRecipients = 10
	s.ReadTimeout = 60 * time.Second
	s.WriteTimeout = 60 * time.Second
	r.server = s
	return r
}

// ListenAndServe serves until Close.
func (r *Receiver) ListenAndServe() error { return r.server.ListenAndServe() }

// Serve serves on an existing listener (tests).
func (r *Receiver) Serve(l net.Listener) error { return r.server.Serve(l) }

// Close stops the server.
func (r *Receiver) Close() error { return r.server.Close() }

// NewSession implements smtp.Backend.
func (r *Receiver) NewSession(c *smtp.Conn) (smtp.Session, error) {
	s := &session{r: r, conn: c}
	if addr, ok := c.Conn().RemoteAddr().(*net.TCPAddr); ok {
		s.ip = addr.IP
	}
	return s, nil
}

type session struct {
	r      *Receiver
	conn   *smtp.Conn
	ip     net.IP
	from   string
	tokens []string
	rcpts  []string
}

func (s *session) Reset() {
	s.from, s.tokens, s.rcpts = "", nil, nil
}

func (s *session) Logout() error { return nil }

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
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
	if _, err := s.r.store.AddressByToken(context.Background(), token); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return errNoMailbox
		}
		s.r.log.Error("address lookup", "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Temporary failure, try again"}
	}
	s.tokens = append(s.tokens, token)
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *session) Data(rd io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(rd, MaxMessageBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > MaxMessageBytes {
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message too large"}
	}
	_, isTLS := s.conn.TLSConnectionState()
	env := engine.Envelope{RemoteIP: s.ip, Helo: s.conn.Hostname(), MailFrom: s.from, TLS: &isTLS}

	// The receiving server records the envelope sender, as any MTA does.
	stamped := append([]byte("Return-Path: <"+s.from+">\r\n"), stripReturnPath(raw)...)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	now := s.r.store.Now().UTC()
	v, err := engine.Analyze(ctx, stamped, engine.Options{
		Envelope: env, Resolver: s.r.cfg.Resolver, CheckLinks: s.r.cfg.CheckLinks, ReceivedAt: now,
	})
	if err != nil {
		return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: "Could not read the message: " + err.Error()}
	}
	for i, token := range s.tokens {
		m := &db.Message{
			Token: token, Source: "smtp", ReceivedAt: now, ExpiresAt: now.Add(s.r.cfg.ReportTTL),
			RemoteIP: ipString(s.ip), Helo: env.Helo, MailFrom: s.from, RcptTo: s.rcpts[i],
			TLS: &isTLS, Raw: stamped, Verdict: copyVerdict(v),
		}
		if err := s.r.store.SaveMessage(ctx, m); err != nil {
			s.r.log.Error("save message", "err", err)
			return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Temporary failure, try again"}
		}
		s.r.log.Info("received", "report", m.ID, "from", s.from, "ip", m.RemoteIP, "verdict", v.Verdict)
	}
	return nil
}

// copyVerdict gives each recipient its own verdict, since saving one writes
// its report ID into it.
func copyVerdict(v *verdict.Verdict) *verdict.Verdict {
	c := *v
	return &c
}

// stripReturnPath drops any Return-Path the sender put in the message; only
// the receiving server may write it.
func stripReturnPath(raw []byte) []byte {
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 {
		end = bytes.Index(raw, []byte("\n\n"))
	}
	if end < 0 {
		return raw
	}
	lines := bytes.SplitAfter(raw[:end], []byte("\n"))
	var out bytes.Buffer
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
