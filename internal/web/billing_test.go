package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendscore/sendscore-app/internal/billing"
	"github.com/sendscore/sendscore-app/internal/db"
)

const webhookSecret = "whsec_test"

// fakeCreem stands in for Creem's API, recording each request.
type fakeCreem struct {
	mu       sync.Mutex
	requests []fakeRequest
	fail     bool
}

type fakeRequest struct {
	Path string
	Body map[string]any
}

func (f *fakeCreem) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	f.mu.Lock()
	f.requests = append(f.requests, fakeRequest{r.URL.Path, body})
	fail := f.fail
	f.mu.Unlock()
	if fail || r.Header.Get("x-api-key") != "creem_test_key" {
		http.Error(w, `{"message":"no"}`, http.StatusBadGateway)
		return
	}
	switch r.URL.Path {
	case "/v1/checkouts":
		io.WriteString(w, `{"id":"ch_1","checkout_url":"https://checkout.creem.io/ch_1"}`)
	case "/v1/customers/billing":
		io.WriteString(w, `{"customer_portal_link":"https://creem.io/portal/`+body["customer_id"].(string)+`"}`)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeCreem) last() fakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1]
}

func (f *fakeCreem) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// billingApp is an app with billing on, against a fake Creem.
func billingApp(t *testing.T, opts ...func(*Config)) (*App, *db.Store, http.Handler, *fakeCreem) {
	t.Helper()
	fake := &fakeCreem{}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	c := billing.New(billing.Config{APIKey: "creem_test_key", WebhookSecret: webhookSecret, ProductMonthly: "prod_monthly",
		ProductYearly: "prod_yearly", Secret: "0123456789abcdef0123456789abcdef"})
	c.Endpoint = srv.URL
	a, store, h := newApp(t, append([]func(*Config){func(cfg *Config) { cfg.Billing = c; cfg.ProPublications = 3 }}, opts...)...)
	return a, store, h, fake
}

func signBody(body []byte) string {
	m := hmac.New(sha256.New, []byte(webhookSecret))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func webhook(h http.Handler, body []byte, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/creem/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if sig != "" {
		req.Header.Set(billing.SignatureHeader, sig)
	}
	return serve(h, req)
}

// ev describes an event. Claim signs the account into the metadata, and
// Unsigned puts it there without a signature.
type ev struct {
	ID, Kind, Claim, Unsigned     string
	Sub, Customer, Email, Product string
	Status                        string
	At                            int64 // seconds
	PeriodEnd                     time.Time
	Checkout                      bool
}

func (a *App) eventBody(t *testing.T, e ev) []byte {
	t.Helper()
	sub := map[string]any{}
	if e.Sub != "" {
		sub["id"] = e.Sub
	}
	if e.Status != "" {
		sub["status"] = e.Status
	}
	if e.Product != "" {
		sub["product"] = map[string]any{"id": e.Product}
	}
	if e.Customer != "" || e.Email != "" {
		sub["customer"] = map[string]any{"id": e.Customer, "email": e.Email}
	}
	if !e.PeriodEnd.IsZero() {
		sub["current_period_end_date"] = e.PeriodEnd.Format(time.RFC3339)
	}
	switch {
	case e.Claim != "":
		sig, err := a.cfg.Billing.SignClaim(e.Claim)
		if err != nil {
			t.Fatal(err)
		}
		sub["metadata"] = map[string]any{"userId": e.Claim, "sig": sig}
	case e.Unsigned != "":
		sub["metadata"] = map[string]any{"userId": e.Unsigned, "sig": "forged"}
	}
	object := sub
	if e.Checkout {
		object = map[string]any{"id": "ch_" + e.ID, "subscription": sub, "customer": sub["customer"], "metadata": sub["metadata"]}
	}
	m := map[string]any{"id": e.ID, "eventType": e.Kind, "object": object}
	if e.At != 0 {
		m["created_at"] = e.At
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// send delivers a signed event and fails unless Creem is answered want.
func (a *App) send(t *testing.T, h http.Handler, e ev, want int) string {
	t.Helper()
	body := a.eventBody(t, e)
	w := webhook(h, body, signBody(body))
	if w.Code != want {
		t.Fatalf("%s %s = %d %s, want %d", e.Kind, e.ID, w.Code, w.Body, want)
	}
	return strings.TrimSpace(w.Body.String())
}

func subOf(t *testing.T, store *db.Store, userID string) db.Subscription {
	t.Helper()
	s, err := store.Subscription(context.Background(), userID)
	if errors.Is(err, db.ErrNotFound) {
		return db.Subscription{}
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func planOf(t *testing.T, store *db.Store, session string) db.User {
	t.Helper()
	u, err := store.UserBySession(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func eventRow(t *testing.T, store *db.Store, id string) (db.CreemEvent, bool) {
	t.Helper()
	e, err := store.CreemEventByID(context.Background(), id)
	if errors.Is(err, db.ErrNotFound) {
		return e, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return e, true
}

// paid puts the user on an active monthly subscription sub_1 of cust_1.
func (a *App) paid(t *testing.T, h http.Handler, u db.User, at int64, end time.Time) {
	t.Helper()
	a.send(t, h, ev{ID: "evt_paid_" + u.ID, Kind: "subscription.paid", Claim: u.ID, Sub: "sub_1", Customer: "cust_1",
		Product: "prod_monthly", Status: "active", At: at, PeriodEnd: end}, 200)
}

func TestWebhookSignature(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, _, _ := newUser(t, store, "a@example.com")
	body := a.eventBody(t, ev{ID: "evt_1", Kind: "subscription.paid", Claim: u.ID, Sub: "sub_1", Customer: "cust_1", Product: "prod_monthly"})
	good := signBody(body)
	for name, sig := range map[string]string{
		"missing":      "",
		"bad":          strings.Repeat("0", len(good)),
		"wrong length": good[:20],
		"other body":   signBody([]byte(`{}`)),
	} {
		if w := webhook(h, body, sig); w.Code != 401 || strings.Contains(w.Body.String(), "signature") {
			t.Errorf("%s signature = %d %q, want a bare 401", name, w.Code, w.Body)
		}
	}
	if _, ok := eventRow(t, store, "evt_1"); ok {
		t.Fatal("an unsigned event was recorded")
	}
	if w := webhook(h, body, good); w.Code != 200 {
		t.Fatalf("good signature = %d %s", w.Code, w.Body)
	}
	if planOf(t, store, mustSession(t, store, "a@example.com")).Plan != db.PlanPro {
		t.Error("a signed payment did not make the account Pro")
	}

	// Over 1 MB is refused before it is verified.
	big := append([]byte(`{"id":"evt_big","pad":"`), bytes.Repeat([]byte("x"), maxWebhookBytes)...)
	if w := webhook(h, big, signBody(big)); w.Code != 413 {
		t.Errorf("large body = %d", w.Code)
	}
	// Signed but with no id is a fault, so Creem sends it again.
	noID := []byte(`{"eventType":"subscription.canceled","object":{"id":"sub_1"}}`)
	if w := webhook(h, noID, signBody(noID)); w.Code != 500 {
		t.Errorf("event with no id = %d", w.Code)
	}
	if subOf(t, store, u.ID).Status != db.SubActive {
		t.Error("an event with no id was applied")
	}
}

// mustSession signs in again and returns the new session.
func mustSession(t *testing.T, store *db.Store, email string) string {
	t.Helper()
	link, err := store.CreateLoginToken(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	_, s, err := store.ConsumeLoginToken(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWebhookIsIdempotent(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, _, _ := newUser(t, store, "a@example.com")
	pay := ev{ID: "evt_pay", Kind: "subscription.paid", Claim: u.ID, Sub: "sub_1", Customer: "cust_1", Product: "prod_monthly", At: 1000}
	if got := a.send(t, h, pay, 200); got != "ok" {
		t.Fatalf("first delivery = %q", got)
	}
	a.send(t, h, ev{ID: "evt_cancel", Kind: "subscription.canceled", Sub: "sub_1", At: 2000}, 200)
	// The payment delivered again changes nothing.
	if got := a.send(t, h, pay, 200); got != "Already seen" {
		t.Errorf("repeat = %q", got)
	}
	if s := subOf(t, store, u.ID); s.Status != db.SubCancelled {
		t.Errorf("after a repeat the status is %q, want cancelled", s.Status)
	}
	e, ok := eventRow(t, store, "evt_pay")
	if !ok || e.Kind != "subscription.paid" || e.UserID != u.ID || e.At != 1000000 || !strings.Contains(e.Body, "evt_pay") {
		t.Errorf("recorded event %+v", e)
	}
}

func TestWebhookIgnoresOutOfOrderEvents(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, _, _ := newUser(t, store, "a@example.com")
	end := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	a.paid(t, h, u, 2000, end)
	// A cancel from before the payment arrives late, and is recorded only.
	if got := a.send(t, h, ev{ID: "evt_old_cancel", Kind: "subscription.canceled", Sub: "sub_1", At: 1000}, 200); got != "Out of order" {
		t.Errorf("late cancel = %q", got)
	}
	if s := subOf(t, store, u.ID); s.Status != db.SubActive || s.Mark != 2000000 {
		t.Errorf("after a late cancel: %+v", s)
	}
	if e, ok := eventRow(t, store, "evt_old_cancel"); !ok || e.UserID != u.ID {
		t.Error("the late cancel was not recorded")
	}
	// A checkout (no status) after it leaves the mark alone, and an event
	// in milliseconds orders with one in seconds.
	a.send(t, h, ev{ID: "evt_co", Kind: "checkout.completed", Claim: u.ID, Sub: "sub_1", Customer: "cust_1", At: 3000, Checkout: true}, 200)
	if s := subOf(t, store, u.ID); s.Mark != 2000000 {
		t.Errorf("a checkout moved the mark to %d", s.Mark)
	}
	a.send(t, h, ev{ID: "evt_cancel", Kind: "subscription.canceled", Sub: "sub_1", At: 1761900000123}, 200)
	if s := subOf(t, store, u.ID); s.Status != db.SubCancelled || s.Mark != 1761900000123 {
		t.Errorf("after a newer cancel in milliseconds: %+v", s)
	}
}

func TestWebhookIgnoresUnsignedMetadataAndEmail(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, session, _ := newUser(t, store, "victim@example.com")
	// A payment link carrying someone else's id, unsigned, and their email.
	got := a.send(t, h, ev{ID: "evt_1", Kind: "subscription.paid", Unsigned: u.ID, Sub: "sub_x", Customer: "cust_x",
		Email: "victim@example.com", Product: "prod_monthly", Status: "active"}, 200)
	if got != "No such account" {
		t.Errorf("answer = %q", got)
	}
	if planOf(t, store, session).Plan != db.PlanFree {
		t.Error("an unsigned claim made the account Pro")
	}
	if _, err := store.Subscription(context.Background(), u.ID); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("an unsigned claim bound a subscription: %v", err)
	}
	if e, ok := eventRow(t, store, "evt_1"); !ok || e.UserID != "" {
		t.Errorf("the event is not in the queue with no account: %+v", e)
	}
	// A claim for an account that does not exist names nobody either.
	if got := a.send(t, h, ev{ID: "evt_2", Kind: "subscription.paid", Claim: "usr_gone", Sub: "sub_y", Product: "prod_monthly"}, 200); got != "No such account" {
		t.Errorf("claim for no account = %q", got)
	}
}

func TestPastDueDoesNotGrantFromFree(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	a.send(t, h, ev{ID: "evt_co", Kind: "checkout.completed", Claim: u.ID, Sub: "sub_1", Customer: "cust_1", Checkout: true}, 200)
	a.send(t, h, ev{ID: "evt_pd", Kind: "subscription.past_due", Sub: "sub_1", Product: "prod_monthly"}, 200)
	if planOf(t, store, session).Plan != db.PlanFree || subOf(t, store, u.ID).Status != "" {
		t.Error("past due made a free account Pro")
	}
	a.send(t, h, ev{ID: "evt_upd", Kind: "subscription.update", Sub: "sub_1", Product: "prod_monthly", Status: "past_due"}, 200)
	if planOf(t, store, session).Plan != db.PlanFree {
		t.Error("an update to past due made a free account Pro")
	}
	// On a paying plan, past due keeps Pro while Creem retries.
	a.paid(t, h, u, 0, time.Time{})
	a.send(t, h, ev{ID: "evt_pd2", Kind: "subscription.past_due", Sub: "sub_1", Product: "prod_monthly"}, 200)
	if p := planOf(t, store, session); p.Plan != db.PlanPro || subOf(t, store, u.ID).Status != db.SubPastDue {
		t.Errorf("past due on a paid plan: plan %s", p.Plan)
	}
	// The retries give up, and Pro lapses.
	a.send(t, h, ev{ID: "evt_unpaid", Kind: "subscription.unpaid", Sub: "sub_1"}, 200)
	if p := planOf(t, store, session); p.Plan != db.PlanFree || !p.Lapsed {
		t.Errorf("unpaid: plan %s lapsed %v", p.Plan, p.Lapsed)
	}
}

func TestUnknownProductGrantsNothing(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	a.send(t, h, ev{ID: "evt_1", Kind: "subscription.paid", Claim: u.ID, Sub: "sub_other", Customer: "cust_1", Product: "prod_someone_elses"}, 200)
	if planOf(t, store, session).Plan != db.PlanFree {
		t.Fatal("a product this install does not sell made the account Pro")
	}
	// The subscription already bound, moved to a new price at Creem, keeps
	// its renewals and keeps its known product.
	end := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	a.paid(t, h, u, 0, time.Time{})
	a.send(t, h, ev{ID: "evt_2", Kind: "subscription.paid", Sub: "sub_1", Product: "prod_new_price", PeriodEnd: end}, 200)
	if s := subOf(t, store, u.ID); s.Status != db.SubActive || !s.PeriodEnd.Equal(end) || s.ProductID != "prod_monthly" {
		t.Errorf("renewal on an unknown product: %+v", s)
	}
	// An end is acted on whatever the product.
	a.send(t, h, ev{ID: "evt_3", Kind: "subscription.expired", Sub: "sub_1", Product: "prod_new_price"}, 200)
	if s := subOf(t, store, u.ID); s.Status != db.SubPaused {
		t.Errorf("expiry on an unknown product: %+v", s)
	}
}

func TestClosingNeedsTheBoundSubscription(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	a.paid(t, h, u, 0, time.Time{})
	// The same customer's other subscription ends.
	a.send(t, h, ev{ID: "evt_1", Kind: "subscription.canceled", Sub: "sub_2", Customer: "cust_1"}, 200)
	if planOf(t, store, session).Plan != db.PlanPro || subOf(t, store, u.ID).Status != db.SubActive {
		t.Error("another subscription's cancel ended the plan")
	}
	a.send(t, h, ev{ID: "evt_2", Kind: "subscription.canceled", Sub: "sub_1", Customer: "cust_1"}, 200)
	if planOf(t, store, session).Plan != db.PlanFree {
		t.Error("the bound subscription's cancel did not end the plan")
	}
}

func TestHealthyPlanIsNotRebound(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	a.paid(t, h, u, 0, time.Time{})
	// A signed claim for a different customer and subscription.
	a.send(t, h, ev{ID: "evt_1", Kind: "subscription.paid", Claim: u.ID, Sub: "sub_9", Customer: "cust_9", Product: "prod_yearly"}, 200)
	if s := subOf(t, store, u.ID); s.SubscriptionID != "sub_1" || s.CustomerID != "cust_1" || s.ProductID != "prod_monthly" {
		t.Errorf("a healthy plan was rebound: %+v", s)
	}
	// Once it has lapsed, a new subscription binds, and its time restarts
	// the mark.
	a.send(t, h, ev{ID: "evt_2", Kind: "subscription.canceled", Sub: "sub_1", At: 100}, 200)
	a.send(t, h, ev{ID: "evt_3", Kind: "subscription.paid", Claim: u.ID, Sub: "sub_9", Customer: "cust_9", Product: "prod_yearly"}, 200)
	if s := subOf(t, store, u.ID); s.SubscriptionID != "sub_9" || s.CustomerID != "cust_9" || s.Status != db.SubActive || s.Mark != 0 {
		t.Errorf("a lapsed plan did not take the new subscription: %+v", s)
	}
	if planOf(t, store, session).Plan != db.PlanPro {
		t.Error("the new subscription did not make the account Pro")
	}
}

func TestRunningPeriodEndIsKept(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, _, _ := newUser(t, store, "a@example.com")
	end := a.store.Now().Add(20 * 24 * time.Hour).UTC().Truncate(time.Second)
	a.paid(t, h, u, 0, end)
	// subscription.active can arrive with no dates, after the payment.
	a.send(t, h, ev{ID: "evt_act", Kind: "subscription.active", Sub: "sub_1", Product: "prod_monthly"}, 200)
	if s := subOf(t, store, u.ID); !s.PeriodEnd.Equal(end) {
		t.Errorf("period end = %s, want %s kept", s.PeriodEnd, end)
	}
	// An end that has passed is let go.
	if err := store.PutSubscription(context.Background(), db.Subscription{UserID: u.ID, CustomerID: "cust_1", SubscriptionID: "sub_1",
		Status: db.SubActive, ProductID: "prod_monthly", PeriodEnd: a.store.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	a.send(t, h, ev{ID: "evt_act2", Kind: "subscription.active", Sub: "sub_1", Product: "prod_monthly"}, 200)
	if s := subOf(t, store, u.ID); !s.PeriodEnd.IsZero() {
		t.Errorf("an ended period end was kept: %s", s.PeriodEnd)
	}
}

func TestCompedAccountIsUntouchedByWebhooks(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, session, _ := newUser(t, store, "comped@example.com")
	pro(t, store, u)
	a.paid(t, h, u, 0, time.Time{})
	a.send(t, h, ev{ID: "evt_c", Kind: "subscription.canceled", Sub: "sub_1"}, 200)
	p := planOf(t, store, session)
	if p.Plan != db.PlanPro || !p.Comped || p.Lapsed {
		t.Errorf("comped account after a cancel: %+v", p)
	}
	var plan string
	if err := store.DB.QueryRow(`SELECT plan FROM users WHERE id = ?`, u.ID).Scan(&plan); err != nil || plan != db.PlanPro {
		t.Errorf("users.plan = %q %v", plan, err)
	}
	// A comped account listed in ProEmails is still promoted at sign-in
	// while it holds a subscription.
	a2, store2, h2, _ := billingApp(t, func(c *Config) { c.ProEmails = []string{"x@example.com"} })
	ux, _, _ := newUser(t, store2, "x@example.com")
	a2.paid(t, h2, ux, 0, time.Time{})
	post(h2, "/signin", url.Values{"email": {"x@example.com"}}, "")
	post(h2, "/signin/verify", url.Values{"t": {mailer(a2).lastLink(t)}}, "")
	a2.send(t, h2, ev{ID: "evt_c2", Kind: "subscription.canceled", Sub: "sub_1"}, 200)
	if p := planOf(t, store2, mustSession(t, store2, "x@example.com")); !p.Comped || p.Plan != db.PlanPro {
		t.Errorf("a subscribed ProEmails account was not comped: %+v", p)
	}
}

func TestFailedApplyAsksForTheEventAgain(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, _, _ := newUser(t, store, "a@example.com")
	if _, err := store.DB.Exec(`ALTER TABLE subscriptions RENAME TO subscriptions_away`); err != nil {
		t.Fatal(err)
	}
	pay := ev{ID: "evt_pay", Kind: "subscription.paid", Claim: u.ID, Sub: "sub_1", Customer: "cust_1", Product: "prod_monthly"}
	a.send(t, h, pay, 500)
	if _, ok := eventRow(t, store, "evt_pay"); ok {
		t.Fatal("an event that was not applied stayed recorded")
	}
	if _, err := store.DB.Exec(`ALTER TABLE subscriptions_away RENAME TO subscriptions`); err != nil {
		t.Fatal(err)
	}
	// Creem's retry is then applied.
	a.send(t, h, pay, 200)
	if s := subOf(t, store, u.ID); s.Status != db.SubActive {
		t.Errorf("the retry was not applied: %+v", s)
	}
}

func TestCheckoutGrantsNothingAndRedirectsToCreem(t *testing.T) {
	a, store, h, fake := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")

	w := serve(h, request("GET", "/account", nil, "", session))
	body := w.Body.String()
	for _, want := range []string{"Upgrade to Pro", "Pay $9 a month", "Pay $90 a year", `action="/account/billing/checkout"`, `name="csrf"`} {
		if !strings.Contains(body, want) {
			t.Errorf("account page is missing %q", want)
		}
	}
	if strings.Contains(body, "Manage billing") {
		t.Error("a free account with no customer is offered the billing page")
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' "+billing.CreemHosts) {
		t.Errorf("account CSP = %q", csp)
	}

	// Without the CSRF token, nothing reaches Creem.
	req := request("POST", "/account/billing/checkout", strings.NewReader("period=monthly"), "application/x-www-form-urlencoded", session)
	if w := serve(h, req); w.Code != 403 || fake.count() != 0 {
		t.Errorf("checkout without CSRF = %d, %d requests", w.Code, fake.count())
	}

	w = post(h, "/account/billing/checkout", url.Values{"period": {"yearly"}}, session)
	if w.Code != 303 || w.Header().Get("Location") != "https://checkout.creem.io/ch_1" {
		t.Fatalf("checkout = %d %s", w.Code, w.Header().Get("Location"))
	}
	r := fake.last()
	meta, _ := r.Body["metadata"].(map[string]any)
	sig, _ := meta["sig"].(string)
	if r.Body["product_id"] != "prod_yearly" || meta["userId"] != u.ID || !a.cfg.Billing.ClaimHolds(u.ID, sig) ||
		r.Body["success_url"] != "http://test/account?checkout=done#plan" {
		t.Errorf("checkout request %v", r.Body)
	}
	// The return grants nothing: only the webhook does.
	if planOf(t, store, session).Plan != db.PlanFree {
		t.Fatal("opening a checkout made the account Pro")
	}
	w = serve(h, request("GET", "/account?checkout=done", nil, "", session))
	if !strings.Contains(w.Body.String(), "turns on as soon as Creem confirms the payment") {
		t.Errorf("return page:\n%s", w.Body)
	}
	a.paid(t, h, u, 0, time.Date(2027, 10, 29, 0, 0, 0, 0, time.UTC))
	w = serve(h, request("GET", "/account?checkout=done", nil, "", session))
	if b := w.Body.String(); !strings.Contains(b, "Pro is on.") || !strings.Contains(b, "billed monthly") ||
		!strings.Contains(b, "paid through 29 Oct 2027") || !strings.Contains(b, "Manage billing") || strings.Contains(b, "Pay $9") {
		t.Errorf("Pro account page:\n%s", b)
	}
	// Already Pro, there is nothing to buy.
	n := fake.count()
	if w := post(h, "/account/billing/checkout", url.Values{"period": {"monthly"}}, session); w.Code != 409 || fake.count() != n {
		t.Errorf("checkout while Pro = %d", w.Code)
	}
	// A period not on offer is refused.
	_, s2, _ := newUser(t, store, "b@example.com")
	if w := post(h, "/account/billing/checkout", url.Values{"period": {"weekly"}}, s2); w.Code != 400 || fake.count() != n {
		t.Errorf("checkout for a weekly plan = %d", w.Code)
	}
}

func TestCheckoutReusesTheCustomer(t *testing.T) {
	a, store, h, fake := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	a.paid(t, h, u, 0, time.Time{})
	a.send(t, h, ev{ID: "evt_c", Kind: "subscription.canceled", Sub: "sub_1"}, 200)
	w := serve(h, request("GET", "/account", nil, "", session))
	if b := w.Body.String(); !strings.Contains(b, "Pro ended for this account") || !strings.Contains(b, "Pay $9 a month") || !strings.Contains(b, "Manage billing") {
		t.Errorf("lapsed account page:\n%s", b)
	}
	if w := post(h, "/account/billing/checkout", url.Values{"period": {"monthly"}}, session); w.Code != 303 {
		t.Fatalf("checkout = %d", w.Code)
	}
	if cust, _ := fake.last().Body["customer"].(map[string]any); cust["id"] != "cust_1" {
		t.Errorf("checkout customer = %v, want cust_1", cust)
	}
}

func TestCreemFailureChangesNothing(t *testing.T) {
	_, store, h, fake := billingApp(t)
	_, session, _ := newUser(t, store, "a@example.com")
	fake.fail = true
	w := post(h, "/account/billing/checkout", url.Values{"period": {"monthly"}}, session)
	if w.Code != 502 || !strings.Contains(w.Body.String(), "Nothing changed, and nothing was charged.") {
		t.Errorf("failed checkout = %d:\n%s", w.Code, w.Body)
	}
	if planOf(t, store, session).Plan != db.PlanFree {
		t.Error("a failed checkout changed the plan")
	}
}

func TestBillingPortal(t *testing.T) {
	a, store, h, fake := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	if w := post(h, "/account/billing/portal", nil, session); w.Code != 400 || fake.count() != 0 {
		t.Errorf("portal with no customer = %d", w.Code)
	}
	a.paid(t, h, u, 0, time.Time{})
	w := post(h, "/account/billing/portal", nil, session)
	if w.Code != 303 || w.Header().Get("Location") != "https://creem.io/portal/cust_1" || fake.last().Body["customer_id"] != "cust_1" {
		t.Errorf("portal = %d %s", w.Code, w.Header().Get("Location"))
	}
	fake.fail = true
	if w := post(h, "/account/billing/portal", nil, session); w.Code != 502 || !strings.Contains(w.Body.String(), "Nothing changed.") {
		t.Errorf("failed portal = %d", w.Code)
	}
	// Past due says so.
	fake.fail = false
	a.send(t, h, ev{ID: "evt_pd", Kind: "subscription.past_due", Sub: "sub_1"}, 200)
	if b := serve(h, request("GET", "/account", nil, "", session)).Body.String(); !strings.Contains(b, "did not go through, and Creem is retrying it") {
		t.Errorf("past due page:\n%s", b)
	}
}

func TestCompedAccountPageHasNoBilling(t *testing.T) {
	_, store, h, _ := billingApp(t)
	u, session, _ := newUser(t, store, "comped@example.com")
	pro(t, store, u)
	b := serve(h, request("GET", "/account", nil, "", session)).Body.String()
	if !strings.Contains(b, "granted by the operator") || strings.Contains(b, "Pay $9") || strings.Contains(b, "Manage billing") {
		t.Errorf("comped account page:\n%s", b)
	}
}

func TestBillingOffShowsNothing(t *testing.T) {
	_, store, h := newApp(t)
	_, session, _ := newUser(t, store, "a@example.com")
	w := serve(h, request("GET", "/account", nil, "", session))
	if b := w.Body.String(); strings.Contains(b, "Upgrade to Pro") || strings.Contains(b, `id="plan"`) {
		t.Errorf("account page without billing mentions a plan:\n%s", b)
	}
	if csp := w.Header().Get("Content-Security-Policy"); strings.Contains(csp, "creem") {
		t.Errorf("CSP without billing = %q", csp)
	}
	if w := post(h, "/account/billing/checkout", url.Values{"period": {"monthly"}}, session); w.Code == 303 {
		t.Error("checkout works without billing")
	}
	if w := webhook(h, []byte(`{}`), ""); w.Code != 404 && w.Code != 405 {
		t.Errorf("webhook without billing = %d", w.Code)
	}
	if b := serve(h, request("GET", "/newsletters", nil, "", session)).Body.String(); strings.Contains(b, "Upgrade to Pro") {
		t.Error("the newsletters page links to a plan without billing")
	}
}

func TestLapsedPlanKeepsNewslettersAndRefusesNewOnes(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	// Free, the page links to the plan.
	if b := serve(h, request("GET", "/newsletters", nil, "", session)).Body.String(); !strings.Contains(b, `href="/account#plan"`) {
		t.Errorf("free newsletters page has no link to the plan:\n%s", b)
	}
	a.paid(t, h, u, 0, time.Time{})
	id := addNewsletter(t, h, session, "Letter")
	a.send(t, h, ev{ID: "evt_c", Kind: "subscription.canceled", Sub: "sub_1"}, 200)

	w := serve(h, request("GET", "/newsletters", nil, "", session))
	b := w.Body.String()
	if !strings.Contains(b, "Pro plan has ended") || !strings.Contains(b, "/newsletters/"+id) || !strings.Contains(b, `href="/account#plan"`) {
		t.Errorf("lapsed newsletters page:\n%s", b)
	}
	w = post(h, "/newsletters", newsletterForm("Another"), session)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "Pro plan has ended") || !strings.Contains(w.Body.String(), `href="/account#plan"`) {
		t.Errorf("lapsed create = %d:\n%s", w.Code, w.Body)
	}
	if b := serve(h, request("GET", "/newsletters/"+id, nil, "", session)).Body.String(); !strings.Contains(b, "Pro has ended for this account") {
		t.Errorf("lapsed newsletter page:\n%s", b)
	}
	if pubs, _ := store.Publications(context.Background(), u.ID); len(pubs) != 1 {
		t.Errorf("%d newsletters after the lapse, want 1", len(pubs))
	}
}
