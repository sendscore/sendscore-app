package main

import "testing"

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
