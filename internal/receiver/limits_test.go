package receiver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

func smtpCode(err error) int {
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

func TestMessagesPerAddress(t *testing.T) {
	store, addr := start(t, func(c *Config) { c.MessagesPerAddress = 3 })
	a, _ := store.CreateAddress(context.Background(), time.Hour)
	to := "t-" + a.Token + "@in.test"
	for i := 0; i < 3; i++ {
		if err := deliver(addr, "bounce@real.test", to, sample(t)); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	// The fourth is refused at RCPT, before any body is sent.
	if err := deliver(addr, "bounce@real.test", to, sample(t)); smtpCode(err) != 550 {
		t.Errorf("fourth message: err = %v, want 550", err)
	}
	var n int
	store.DB.QueryRow(`SELECT COUNT(*) FROM messages WHERE token = ?`, a.Token).Scan(&n)
	if n != 3 {
		t.Errorf("stored %d messages, want 3", n)
	}
}

func TestMessagesPerSession(t *testing.T) {
	store, addr := start(t, func(c *Config) { c.MessagesPerAddress = 100 })
	a, _ := store.CreateAddress(context.Background(), time.Hour)
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Hello("mail.sender.test")
	for i := 0; i <= messagesPerSession; i++ {
		err := c.Mail("bounce@real.test", nil)
		if i == messagesPerSession {
			if smtpCode(err) != 451 {
				t.Errorf("message %d: MAIL err = %v, want 451", i, err)
			}
			break
		}
		if err != nil {
			t.Fatalf("message %d: MAIL: %v", i, err)
		}
		if err := c.Rcpt("t-"+a.Token+"@in.test", nil); err != nil {
			t.Fatal(err)
		}
		w, _ := c.Data()
		w.Write(sample(t))
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDailyMessagesPerAccount(t *testing.T) {
	store, addr := start(t, func(c *Config) { c.DailyMessages = 2 })
	ctx := context.Background()
	if _, err := store.DB.Exec(`INSERT INTO users (id, email, created_at) VALUES ('usr_1', 'a@example.com', 0)`); err != nil {
		t.Fatal(err)
	}
	a, _ := store.CreateAddressFor(ctx, time.Hour, "usr_1")
	b, _ := store.CreateAddressFor(ctx, time.Hour, "usr_1")
	other, _ := store.CreateAddress(ctx, time.Hour)
	for _, tok := range []string{a.Token, b.Token} {
		if err := deliver(addr, "bounce@real.test", "t-"+tok+"@in.test", sample(t)); err != nil {
			t.Fatal(err)
		}
	}
	// The account's addresses share the daily allowance.
	if err := deliver(addr, "bounce@real.test", "t-"+b.Token+"@in.test", sample(t)); smtpCode(err) != 452 {
		t.Errorf("third message today: err = %v, want 452", err)
	}
	// An address of nobody's is not affected.
	if err := deliver(addr, "bounce@real.test", "t-"+other.Token+"@in.test", sample(t)); err != nil {
		t.Errorf("anonymous address: %v", err)
	}
}

func TestSessionsPerIP(t *testing.T) {
	_, addr := start(t, func(c *Config) { c.MaxSessionsPerIP = 1 })
	first, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Hello("mail.sender.test"); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	conn.Close()
	if !strings.HasPrefix(string(buf[:n]), "421 ") {
		t.Errorf("second connection got %q, want 421", buf[:n])
	}
	// Closing the first frees its slot.
	first.Quit()
	time.Sleep(100 * time.Millisecond)
	again, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("after the first closed: %v", err)
	}
	if err := again.Hello("mail.sender.test"); err != nil {
		t.Errorf("after the first closed: %v", err)
	}
	again.Close()
}

// TestSlowBodyIsNotCutOff sends a body slowly, never idle for a whole read
// timeout but taking longer than one in all, which go-smtp alone would cut
// off with a permanent 554.
func TestSlowBodyIsNotCutOff(t *testing.T) {
	old := readTimeout
	readTimeout = time.Second
	defer func() { readTimeout = old }()
	store, addr := start(t)
	a, _ := store.CreateAddress(context.Background(), time.Hour)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte("EHLO mail.sender.test\r\nMAIL FROM:<bounce@real.test>\r\nRCPT TO:<t-" + a.Token + "@in.test>\r\nDATA\r\n"))
	// The body goes in eight parts, 200 ms apart, so it takes 1.6 seconds
	// against a 1 second read timeout, with a wide margin on each read.
	raw := bytes.ReplaceAll(sample(t), []byte("\r\n"), []byte("\n"))
	raw = bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n"))
	chunk := len(raw)/8 + 1
	for i := 0; i < len(raw); i += chunk {
		time.Sleep(200 * time.Millisecond)
		conn.Write(raw[i:min(i+chunk, len(raw))])
	}
	conn.Write([]byte("\r\n.\r\nQUIT\r\n"))
	var got bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		got.Write(buf[:n])
		if err != nil || strings.Contains(got.String(), "221 ") {
			break
		}
	}
	if !strings.Contains(got.String(), "250 2.0.0 OK") {
		t.Errorf("slow body got %q, want 250", got.String())
	}
}

func TestStalledBodyIsTemporary(t *testing.T) {
	old := readTimeout
	readTimeout = 300 * time.Millisecond
	defer func() { readTimeout = old }()
	store, addr := start(t)
	a, _ := store.CreateAddress(context.Background(), time.Hour)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	cmds := "EHLO mail.sender.test\r\nMAIL FROM:<bounce@real.test>\r\nRCPT TO:<t-" + a.Token + "@in.test>\r\nDATA\r\nSubject: half\r\n"
	if _, err := conn.Write([]byte(cmds)); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	buf := make([]byte, 4096)
	for !strings.Contains(got.String(), "451 ") {
		n, err := conn.Read(buf)
		got.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if !strings.Contains(got.String(), "451 ") || strings.Contains(got.String(), "554 ") {
		t.Errorf("stalled body got %q, want a 451", got.String())
	}
}

func writePair(t *testing.T, dir, cn string) (certFile, keyFile string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	return certFile, keyFile
}

func commonName(t *testing.T, l *CertLoader) string {
	t.Helper()
	c, err := l.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestCertLoaderReloadsRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writePair(t, dir, "old.in.test")
	l, err := NewCertLoader(certFile, keyFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	l.now = func() time.Time { return now }
	if got := commonName(t, l); got != "old.in.test" {
		t.Fatalf("first certificate = %s", got)
	}
	writePair(t, dir, "new.in.test")
	later := time.Now().Add(time.Minute)
	os.Chtimes(certFile, later, later)
	os.Chtimes(keyFile, later, later)
	// Within a minute of the last look the files are not checked.
	if got := commonName(t, l); got != "old.in.test" {
		t.Errorf("before the check interval = %s", got)
	}
	now = now.Add(certCheckEvery)
	if got := commonName(t, l); got != "new.in.test" {
		t.Errorf("after renewal = %s", got)
	}
	// A broken renewal keeps the certificate that works.
	os.WriteFile(keyFile, []byte("not a key"), 0o600)
	evenLater := later.Add(time.Minute)
	os.Chtimes(keyFile, evenLater, evenLater)
	var reloadErr error
	l.onError = func(err error) { reloadErr = err }
	now = now.Add(certCheckEvery)
	if got := commonName(t, l); got != "new.in.test" || reloadErr == nil {
		t.Errorf("after a broken renewal = %s, err %v", got, reloadErr)
	}
}
