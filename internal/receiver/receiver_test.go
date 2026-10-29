package receiver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore/engine"
	"github.com/sendscore/sendscore/verdict"
)

func start(t *testing.T) (*db.Store, string) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	r := New(Config{MailDomain: "in.test", ReportTTL: time.Hour, Resolver: engine.OfflineResolver{}},
		store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go r.Serve(l)
	t.Cleanup(func() { r.Close() })
	return store, l.Addr().String()
}

func deliver(addr, from, to string, raw []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("mail.sender.test"); err != nil {
		return err
	}
	if err := c.Mail(from, nil); err != nil {
		return err
	}
	if err := c.Rcpt(to, nil); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	w.Write(raw)
	return w.Close()
}

func sample(t *testing.T) []byte {
	raw, err := os.ReadFile("../../../sendscore/testdata/sample.eml")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReceivesAndStoresVerdict(t *testing.T) {
	store, addr := start(t)
	a, err := store.CreateAddress(context.Background(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// A forged Return-Path in the message must be replaced by the envelope.
	raw := append([]byte("Return-Path: <forged@evil.test>\r\n"), sample(t)...)
	if err := deliver(addr, "bounce@real.test", "t-"+a.Token+"@in.test", raw); err != nil {
		t.Fatal(err)
	}
	m, err := store.LatestForToken(context.Background(), a.Token, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err = store.RawByID(context.Background(), m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m.Raw != nil {
		t.Error("LatestForToken loaded the raw message")
	}
	if m.RemoteIP != "127.0.0.1" || m.Helo != "mail.sender.test" || m.MailFrom != "bounce@real.test" {
		t.Errorf("envelope = %q %q %q", m.RemoteIP, m.Helo, m.MailFrom)
	}
	if strings.Contains(string(raw), "forged@evil.test") || !strings.HasPrefix(string(raw), "Return-Path: <bounce@real.test>") {
		t.Errorf("Return-Path not replaced:\n%s", raw[:200])
	}
	if m.Verdict.ID != m.ID || m.Verdict.Fingerprint.ReturnPathDomain != "real.test" {
		t.Errorf("verdict id %q, return path %q", m.Verdict.ID, m.Verdict.Fingerprint.ReturnPathDomain)
	}
	for _, c := range m.Verdict.Checks {
		if c.ID == "auth.tls" && c.Status != verdict.Fail {
			t.Errorf("auth.tls = %s, want fail for a plain text delivery", c.Status)
		}
	}
}

func TestRefusesUnknownAndExpiredAddresses(t *testing.T) {
	store, addr := start(t)
	a, _ := store.CreateAddress(context.Background(), -time.Minute)
	for _, to := range []string{"t-nope@in.test", "t-" + a.Token + "@in.test", "someone@in.test", "t-x@other.test"} {
		err := deliver(addr, "a@b.test", to, sample(t))
		if se, ok := err.(*smtp.SMTPError); !ok || se.Code != 550 {
			t.Errorf("%s: err = %v, want 550", to, err)
		}
	}
}

func TestRefusesSendersThatBreakReturnPath(t *testing.T) {
	store, addr := start(t)
	// The go-smtp client refuses to send these, so speak SMTP by hand.
	for _, from := range []string{"a@b.example\rX-Injected:yes", `"x>y"@b.example`, `"x<y"@b.example`, "a\x01@b.example"} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		tc := textproto.NewConn(conn)
		tc.ReadResponse(220)
		tc.PrintfLine("EHLO mail.sender.test")
		tc.ReadResponse(250)
		tc.PrintfLine("MAIL FROM:<%s>", from)
		code, _, _ := tc.ReadResponse(250)
		tc.Close()
		if code != 501 {
			t.Errorf("%q: code = %d, want 501", from, code)
		}
	}
	var n int
	store.DB.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n)
	if n != 0 {
		t.Errorf("stored %d messages", n)
	}
}

func TestOneTestAddressPerTransaction(t *testing.T) {
	store, addr := start(t)
	ctx := context.Background()
	a, _ := store.CreateAddress(ctx, time.Hour)
	b, _ := store.CreateAddress(ctx, time.Hour)
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Hello("mail.sender.test")
	if err := c.Mail("bounce@real.test", nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := c.Rcpt("t-"+a.Token+"@in.test", nil); err != nil {
			t.Fatalf("repeated RCPT %d: %v", i, err)
		}
	}
	if err := c.Rcpt("t-"+b.Token+"@in.test", nil); err == nil || err.(*smtp.SMTPError).Code != 452 {
		t.Errorf("second address: err = %v, want 452", err)
	}
	w, _ := c.Data()
	w.Write(sample(t))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var n int
	store.DB.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n)
	if n != 1 {
		t.Errorf("stored %d messages, want 1", n)
	}
}

func TestStartTLS(t *testing.T) {
	cert := selfSigned(t)
	store, err := db.Open(filepath.Join(t.TempDir(), "tls.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	r := New(Config{MailDomain: "in.test", ReportTTL: time.Hour, Resolver: engine.OfflineResolver{},
		TLS: &tls.Config{Certificates: []tls.Certificate{cert}}}, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go r.Serve(l)
	defer r.Close()

	a, _ := store.CreateAddress(context.Background(), time.Hour)
	c, err := smtp.DialStartTLS(l.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("STARTTLS: %v", err)
	}
	defer c.Close()
	if err := c.Mail("bounce@real.test", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("t-"+a.Token+"@in.test", nil); err != nil {
		t.Fatal(err)
	}
	w, _ := c.Data()
	w.Write(sample(t))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	m, err := store.LatestForToken(context.Background(), a.Token, "")
	if err != nil {
		t.Fatal(err)
	}
	if m.TLS == nil || !*m.TLS {
		t.Error("message delivered over STARTTLS was not recorded as TLS")
	}
	for _, ch := range m.Verdict.Checks {
		if ch.ID == "auth.tls" && ch.Status != verdict.Pass {
			t.Errorf("auth.tls = %s", ch.Status)
		}
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "in.test"},
		DNSNames: []string{"in.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
