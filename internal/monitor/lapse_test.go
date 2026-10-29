package monitor

import (
	"context"
	"testing"

	"github.com/sendscore/sendscore-app/internal/db"
)

func subscribe(t *testing.T, f *fixture, status string) {
	t.Helper()
	if err := f.store.PutSubscription(context.Background(), db.Subscription{UserID: f.user.ID, CustomerID: "cust_1",
		SubscriptionID: "sub_1", Status: status}); err != nil {
		t.Fatal(err)
	}
}

// byToken loads the publication as the receiver does, with its owner's plan.
func byToken(t *testing.T, f *fixture, p db.Publication) db.Publication {
	t.Helper()
	got, err := f.store.PublicationByToken(context.Background(), p.Token)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestLapsedPlanStopsAlertsAndTheHeartbeat(t *testing.T) {
	f := setup(t, utc("2026-10-26T06:00:00Z"))
	ctx := context.Background()
	subscribe(t, f, db.SubActive)
	p := f.publication(t, db.Publication{Days: 1 << 1, At: "07:00", TimeZone: "America/Toronto", GraceMinutes: 30})
	if got := byToken(t, f, p); got.OwnerPlan != db.PlanPro || got.OwnerLapsed {
		t.Fatalf("an active subscription reads as plan %q lapsed %v", got.OwnerPlan, got.OwnerLapsed)
	}

	subscribe(t, f, db.SubCancelled)
	p = byToken(t, f, p)
	if p.OwnerPlan != db.PlanFree || !p.OwnerLapsed {
		t.Fatalf("a cancelled subscription reads as plan %q lapsed %v", p.OwnerPlan, p.OwnerLapsed)
	}
	// A worse issue sends nothing.
	f.receive(t, p, good())
	f.receive(t, p, bad())
	// Nor does a missed one (07:00 EST is 12:00 UTC): the heartbeat skips the publication.
	f.clock.Set(utc("2026-11-02T12:30:00Z"))
	f.mon.Tick(ctx)
	if n := len(f.out.all()); n != 0 {
		t.Fatalf("a lapsed account was sent %d alerts", n)
	}
	if pubs, _ := f.store.ScheduledPublications(ctx); len(pubs) != 0 {
		t.Errorf("the heartbeat still lists %d of a lapsed account's publications", len(pubs))
	}
	// Nothing was deleted: the publication and its issues are all there.
	if msgs, _ := f.store.PublicationMessages(ctx, p.ID, 10); len(msgs) != 2 {
		t.Errorf("%d issues kept, want 2", len(msgs))
	}

	// Paying again turns monitoring back on.
	subscribe(t, f, db.SubActive)
	f.clock.Set(utc("2026-11-09T12:30:00Z"))
	f.mon.Tick(ctx)
	if n := len(f.out.all()); n != 1 {
		t.Errorf("sent %d alerts after resubscribing, want the one missed issue", n)
	}
}

func TestCompedAccountIsNeverLapsed(t *testing.T) {
	f := setup(t, utc("2026-10-26T06:00:00Z"))
	if err := f.store.SetPlan(context.Background(), f.user.ID, db.PlanPro); err != nil {
		t.Fatal(err)
	}
	subscribe(t, f, db.SubCancelled)
	p := byToken(t, f, f.publication(t, db.Publication{}))
	if p.OwnerPlan != db.PlanPro || p.OwnerLapsed {
		t.Fatalf("a comped account with a cancelled subscription reads as plan %q lapsed %v", p.OwnerPlan, p.OwnerLapsed)
	}
	f.receive(t, p, good())
	f.receive(t, p, bad())
	if n := len(f.out.all()); n != 1 {
		t.Errorf("sent %d alerts, want 1", n)
	}
}

func TestPastDueKeepsMonitoring(t *testing.T) {
	f := setup(t, utc("2026-10-26T06:00:00Z"))
	subscribe(t, f, db.SubPastDue)
	p := byToken(t, f, f.publication(t, db.Publication{}))
	if p.OwnerPlan != db.PlanPro || p.OwnerLapsed {
		t.Fatalf("past due reads as plan %q lapsed %v", p.OwnerPlan, p.OwnerLapsed)
	}
}
