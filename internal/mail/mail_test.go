package mail

import (
	"context"
	"strings"
	"testing"
)

func TestFromEnv(t *testing.T) {
	ctx := context.Background()
	t.Setenv("SES_ACCESS_KEY_ID", "")
	t.Setenv("SES_SECRET_ACCESS_KEY", "")
	if _, ok, err := FromEnv(ctx); ok || err != nil {
		t.Fatalf("no keys = %v %v", ok, err)
	}
	t.Setenv("SES_ACCESS_KEY_ID", "id")
	t.Setenv("SES_SECRET_ACCESS_KEY", "secret")
	t.Setenv("SENDSCORE_MAIL_FROM", "")
	t.Setenv("SENDSCORE_ALERT_FROM", "")
	if _, _, err := FromEnv(ctx); err == nil || !strings.Contains(err.Error(), "SENDSCORE_MAIL_FROM") {
		t.Fatalf("keys without senders: %v", err)
	}
	t.Setenv("SENDSCORE_MAIL_FROM", "a@example.com")
	t.Setenv("SENDSCORE_ALERT_FROM", "b@example.com")
	s, ok, err := FromEnv(ctx)
	if err != nil || !ok || s.From() != "a@example.com" || s.AlertFrom() != "b@example.com" {
		t.Errorf("configured = %+v %v %v", s, ok, err)
	}
}
