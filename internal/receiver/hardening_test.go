package receiver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore/engine"
)

// numbered is the sample message made unique, as two sends are.
func numbered(t *testing.T, i int) []byte {
	t.Helper()
	return append([]byte(fmt.Sprintf("X-Number: %d\r\n", i)), sample(t)...)
}

func TestConnKeyGroupsIPv6(t *testing.T) {
	a := connKey(net.ParseIP("2001:db8:1:2:aaaa::1"))
	b := connKey(net.ParseIP("2001:db8:1:2:bbbb::2"))
	c := connKey(net.ParseIP("2001:db8:1:3::1"))
	if a != b || a == c {
		t.Errorf("keys = %q %q %q", a, b, c)
	}
	if k := connKey(net.ParseIP("192.0.2.1")); k != "192.0.2.1" {
		t.Errorf("IPv4 key = %q", k)
	}
}

func TestSessionHasAnAbsoluteDeadline(t *testing.T) {
	old := maxSessionTime
	maxSessionTime = 300 * time.Millisecond
	defer func() { maxSessionTime = old }()
	_, addr := start(t)
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := c.Noop(); err != nil {
			return // the server hung up
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("a session of NOOPs outlived its deadline")
}

func TestRetryOfASavedMessageIsNotStoredTwice(t *testing.T) {
	store, addr, out := startMonitored(t)
	u := owner(t, store, "dup@example.com", db.PlanPro)
	p := publication(t, store, u, false)
	to := "m-" + p.Token + "@in.test"
	raw := numbered(t, 1)
	for range 2 {
		if err := deliver(addr, "bounce@real.test", to, raw); err != nil {
			t.Fatal(err)
		}
	}
	msgs, err := store.PublicationMessages(context.Background(), p.ID, 10)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("messages = %d %v, want the retry recognized", len(msgs), err)
	}
	if n, _ := store.Count(context.Background(), "messages:pub:"+p.ID, db.Day(store.Now())); n != 1 {
		t.Errorf("counted %d", n)
	}
	if out.count() != 0 {
		t.Errorf("sent %d alerts for a retry", out.count())
	}
}

func TestRetryDecidesAnAlertLostInACrash(t *testing.T) {
	store, addr, out := startMonitored(t)
	ctx := context.Background()
	u := owner(t, store, "crash@example.com", db.PlanPro)
	p := publication(t, store, u, false)
	to := "m-" + p.Token + "@in.test"
	if err := deliver(addr, "bounce@real.test", to, numbered(t, 1)); err != nil {
		t.Fatal(err)
	}
	first, err := store.LatestIssue(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := deliver(addr, "bounce@real.test", to, numbered(t, 2)); err != nil {
		t.Fatal(err)
	}
	second, err := store.LatestIssue(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	// As if the process stopped after saving, before any alert was made: the
	// second issue is worse, and nothing has been said about it.
	second.Verdict.ReadyToSend = false
	first.Verdict.ReadyToSend = true
	if _, err := store.DB.Exec(`UPDATE messages SET verdict = json_set(verdict, '$.ready_to_send', json('true')) WHERE id = ?`, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`UPDATE messages SET verdict = json_set(verdict, '$.ready_to_send', json('false')) WHERE id = ?`, second.ID); err != nil {
		t.Fatal(err)
	}
	before := out.count()
	if err := deliver(addr, "bounce@real.test", to, numbered(t, 2)); err != nil {
		t.Fatal(err)
	}
	if out.count() != before+1 {
		t.Errorf("alerts went from %d to %d, want the lost one sent", before, out.count())
	}
}

func TestStalledBodyCostsNothing(t *testing.T) {
	store, addr := start(t)
	ctx := context.Background()
	a, err := store.CreateAddress(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "HELO x\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<t-%s@in.test>\r\nDATA\r\nSubject: partial\r\n", a.Token)
	buf := make([]byte, 512)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	for !bytes.Contains(buf, []byte("354")) {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
	c.Close()
	time.Sleep(100 * time.Millisecond)
	if n, _ := store.Count(ctx, "messages:addr:"+a.Token, "all"); n != 0 {
		t.Errorf("a body that never arrived counted %d", n)
	}
}

func TestRefusedMessageUsesUpNoOtherAllowance(t *testing.T) {
	store, addr := start(t, func(c *Config) { c.DailyMessages = 1 })
	ctx := context.Background()
	u := owner(t, store, "refused@example.com", db.PlanFree)
	a, err := store.CreateAddressFor(ctx, time.Hour, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.CreateAddressFor(ctx, time.Hour, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := deliver(addr, "b@real.test", "t-"+a.Token+"@in.test", sample(t)); err != nil {
		t.Fatal(err)
	}
	if err := deliver(addr, "b@real.test", "t-"+b.Token+"@in.test", sample(t)); smtpCode(err) != 452 {
		t.Fatalf("over the day: %v", err)
	}
	if n, _ := store.Count(ctx, "messages:addr:"+b.Token, "all"); n != 0 {
		t.Errorf("the refused address counted %d", n)
	}
}

func TestDailyBytesCoverTestAndMonitoringAddresses(t *testing.T) {
	size := len(sample(t)) + 100
	store, addr, _ := startMonitored(t, func(c *Config) { c.DailyBytes = 3 * size / 2 })
	ctx := context.Background()
	u := owner(t, store, "bytes@example.com", db.PlanPro)
	p := publication(t, store, u, false)
	a, err := store.CreateAddressFor(ctx, time.Hour, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := deliver(addr, "b@real.test", "m-"+p.Token+"@in.test", numbered(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := deliver(addr, "b@real.test", "t-"+a.Token+"@in.test", numbered(t, 2)); smtpCode(err) != 452 {
		t.Errorf("past the daily bytes: %v", err)
	}
}

func TestAnonymousAddressesShareADailyCap(t *testing.T) {
	store, addr := start(t, func(c *Config) { c.AnonDailyMessages = 1 })
	ctx := context.Background()
	for i, want := range []int{0, 452} {
		a, err := store.CreateAddress(ctx, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := deliver(addr, "b@real.test", "t-"+a.Token+"@in.test", sample(t)); smtpCode(err) != want {
			t.Errorf("message %d: %v, want %d", i, err, want)
		}
	}
}

func TestFullStorageRefusesMailForNow(t *testing.T) {
	store, addr := start(t, func(c *Config) { c.MaxStorageBytes = 1 })
	a, err := store.CreateAddress(context.Background(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := deliver(addr, "b@real.test", "t-"+a.Token+"@in.test", sample(t)); smtpCode(err) != 452 {
		t.Errorf("with the database full: %v", err)
	}
}

func TestMessagesInMemoryAreBounded(t *testing.T) {
	store, addr := start(t, func(c *Config) { c.MaxBufferedBytes = 1024 })
	a, err := store.CreateAddress(context.Background(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	big := append(sample(t), bytes.Repeat([]byte("x"), 8<<10)...)
	if err := deliver(addr, "b@real.test", "t-"+a.Token+"@in.test", big); smtpCode(err) != 451 {
		t.Errorf("over the memory budget: %v", err)
	}
	// The charge comes back, so a small message is fine afterwards.
	small := []byte("From: a@b.test\r\nSubject: s\r\n\r\nhi\r\n")
	if err := deliver(addr, "b@real.test", "t-"+a.Token+"@in.test", small); err != nil {
		t.Errorf("after the refusal: %v", err)
	}
}

func TestShutdownWaitsForAMessageInDATA(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	r := New(Config{MailDomain: "in.test", ReportTTL: time.Hour, Resolver: engine.OfflineResolver{}}, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go r.Serve(l)
	ctx := context.Background()
	a, err := store.CreateAddress(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := smtp.Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello("x"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("b@real.test", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("t-"+a.Token+"@in.test", nil); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(sample(t)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	go func() { done <- r.Shutdown(sctx) }()
	time.Sleep(100 * time.Millisecond)
	if err := w.Close(); err != nil {
		t.Fatalf("the message in flight was refused: %v", err)
	}
	_ = c.Quit()
	if _, err := store.LatestForToken(ctx, a.Token, ""); err != nil {
		t.Errorf("not saved: %v", err)
	}
	if err := <-done; err != nil && !strings.Contains(err.Error(), "closed") {
		t.Errorf("shutdown: %v", err)
	}
}
