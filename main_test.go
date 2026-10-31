package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
)

func TestSecureCookiesFor(t *testing.T) {
	for _, c := range []struct {
		base, setting string
		want, err     bool
	}{
		{"https://app.sendscore.ai", "", true, false},
		{"http://127.0.0.1:3014", "", false, false},
		{"https://app.sendscore.ai", "false", false, false},
		{"http://127.0.0.1:3014", "true", true, false},
		{"https://app.sendscore.ai", "yes", false, true},
	} {
		got, err := secureCookiesFor(c.base, c.setting)
		if got != c.want || (err != nil) != c.err {
			t.Errorf("secureCookiesFor(%q, %q) = %v, %v", c.base, c.setting, got, err)
		}
	}
}

func TestNeedsProxyWarning(t *testing.T) {
	if !needsProxyWarning("https://app.sendscore.ai", false) {
		t.Error("a public base URL without SENDSCORE_TRUST_PROXY gets no warning")
	}
	if needsProxyWarning("https://app.sendscore.ai", true) || needsProxyWarning("http://127.0.0.1:3014", false) {
		t.Error("warned when there is nothing to warn about")
	}
}

func TestParseBool(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "true": true, "0": false, "false": false} {
		if got, err := parseBool("K", v); err != nil || got != want {
			t.Errorf("parseBool(%q) = %v, %v", v, got, err)
		}
	}
	for _, v := range []string{"yes", "on", "TRUE", "2"} {
		if _, err := parseBool("K", v); err == nil {
			t.Errorf("parseBool(%q) accepted a typo", v)
		}
	}
}

func TestCheckConfig(t *testing.T) {
	for _, c := range []struct {
		base, domain string
		secure, ok   bool
	}{
		{"http://127.0.0.1:3014", "localhost", false, true},
		{"https://s.example.com", "in.example.com", true, true},
		{"s.example.com", "in.example.com", false, false},
		{"ftp://s.example.com", "in.example.com", false, false},
		{"https://", "in.example.com", false, false},
		{"https://s.example.com", "localhost", true, false},
		{"http://127.0.0.1:3014", "in.example.com", true, false},
		// A public http base URL gets the same check on its mail domain.
		{"http://s.example.com", "localhost", false, false},
		{"http://s.example.com", "in.example.com", false, true},
	} {
		if err := checkConfig(c.base, c.domain, c.secure); (err == nil) != c.ok {
			t.Errorf("checkConfig(%q, %q, %v) = %v", c.base, c.domain, c.secure, err)
		}
	}
}

func TestSignupDefaults(t *testing.T) {
	for setting, want := range map[string]bool{"": true, "closed": true, "open": false} {
		if got, err := signupsClosed(setting); err != nil || got != want {
			t.Errorf("signupsClosed(%q) = %v, %v", setting, got, err)
		}
	}
	if _, err := signupsClosed("maybe"); err == nil {
		t.Error("accepted a typo")
	}
	if anonDefault(true, false) != 0 || anonDefault(false, false) != 5 || anonDefault(true, true) != 5 {
		t.Error("anonDefault")
	}
}

func TestParseProxies(t *testing.T) {
	got, err := parseProxies("10.1.2.3, 192.168.0.0/16,::1")
	if err != nil || len(got) != 3 || got[0].Bits() != 32 || got[2].Bits() != 128 {
		t.Errorf("parseProxies = %v %v", got, err)
	}
	if got, err := parseProxies(""); err != nil || got != nil {
		t.Errorf("empty = %v %v", got, err)
	}
	if _, err := parseProxies("not-an-ip"); err == nil {
		t.Error("accepted a typo")
	}
}

func TestCheckHealth(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx := context.Background()
	now := time.Now()
	if err := checkHealth(ctx, now, now, now, l.Addr().String()); err != nil {
		t.Errorf("healthy: %v", err)
	}
	if err := checkHealth(ctx, time.Time{}, now, now, l.Addr().String()); err != nil {
		t.Errorf("just started: %v", err)
	}
	if err := checkHealth(ctx, now.Add(-time.Hour), now, now, l.Addr().String()); err == nil {
		t.Error("a stalled heartbeat passed")
	}
	addr := l.Addr().String()
	l.Close()
	if err := checkHealth(ctx, now, now, now, addr); err == nil {
		t.Error("a closed listener passed")
	}
}

func TestLocalAddr(t *testing.T) {
	for in, want := range map[string]string{"0.0.0.0:3014": "127.0.0.1:3014", ":3014": "127.0.0.1:3014", "10.0.0.1:25": "10.0.0.1:25"} {
		if got := localAddr(in); got != want {
			t.Errorf("localAddr(%q) = %q", in, got)
		}
	}
}

func TestHealthcheckCommand(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	t.Setenv("SENDSCORE_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	var out, errOut bytes.Buffer
	if code := command([]string{"healthcheck"}, &out, &errOut); code != 0 {
		t.Errorf("healthy = %d %s", code, errOut.String())
	}
	status = http.StatusServiceUnavailable
	if code := command([]string{"healthcheck"}, &out, &errOut); code != 1 {
		t.Errorf("unhealthy = %d", code)
	}
}

func TestBackupCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "live.db")
	t.Setenv("SENDSCORE_DB", path)
	store, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	var out, errOut bytes.Buffer
	copyPath := filepath.Join(dir, "copy.db")
	if code := command([]string{"backup", copyPath}, &out, &errOut); code != 0 {
		t.Fatalf("backup = %d %s", code, errOut.String())
	}
	if _, err := os.Stat(copyPath); err != nil {
		t.Error(err)
	}
	if code := command([]string{"backup", copyPath}, &out, &errOut); code != 1 {
		t.Error("overwrote a backup")
	}
	if code := command([]string{"nonsense"}, &out, &errOut); code != 64 {
		t.Errorf("unknown command = %d", code)
	}
}

// The real binary, from start to SIGTERM: this is what no unit can show.
func TestBinaryAnswersHealthAndStopsOnSIGTERM(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "sendscore-app")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	web, smtpAddr := freeAddr(t), freeAddr(t)
	cmd := exec.Command(bin)
	cmd.Dir = dir // so it reads no .env.local of the developer's
	cmd.Env = append(os.Environ(), "SENDSCORE_ADDR="+web, "SENDSCORE_SMTP_ADDR="+smtpAddr, "SENDSCORE_DB="+filepath.Join(dir, "t.db"),
		"SENDSCORE_BASE_URL=http://"+web, "SES_ACCESS_KEY_ID=", "SES_SECRET_ACCESS_KEY=", "SENDSCORE_SECURE_COOKIES=")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	healthy := false
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(50 * time.Millisecond) {
		res, err := http.Get("http://" + web + "/healthz")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
	}
	if !healthy {
		t.Fatal("/healthz never answered 200")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("exit after SIGTERM: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the process did not stop on SIGTERM")
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}
