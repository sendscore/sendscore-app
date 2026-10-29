package receiver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
)

func TestLapsedPlanKeepsReceivingWithoutAlerts(t *testing.T) {
	store, addr, out := startMonitored(t)
	u := owner(t, store, "pub@example.com", db.PlanFree)
	p := publication(t, store, u, false)
	if err := store.PutSubscription(context.Background(), db.Subscription{UserID: u.ID, CustomerID: "cust_1",
		SubscriptionID: "sub_1", Status: db.SubCancelled}); err != nil {
		t.Fatal(err)
	}
	to := "m-" + p.Token + "@in.test"
	if err := deliver(addr, "bounce@real.test", to, sample(t)); err != nil {
		t.Fatal(err)
	}
	worse := strings.Replace(string(sample(t)), "List-Unsubscribe: <https://example.com/unsubscribe?u=1>\n", "", 1)
	if err := deliver(addr, "bounce@real.test", to, []byte(worse)); err != nil {
		t.Fatal(err)
	}
	msgs, err := store.PublicationMessages(context.Background(), p.ID, 10)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("stored %d messages (%v), want 2", len(msgs), err)
	}
	if out.count() != 0 {
		t.Errorf("a lapsed account was sent %d alerts", out.count())
	}
	// Kept for the free report TTL, not the Pro history.
	if d := msgs[0].ExpiresAt.Sub(msgs[0].ReceivedAt); d != time.Hour {
		t.Errorf("kept for %s, want the report TTL", d)
	}
}
