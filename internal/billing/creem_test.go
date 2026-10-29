package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const secret = "0123456789abcdef0123456789abcdef"

func testClient() *Client {
	return New(Config{APIKey: "creem_test_key", WebhookSecret: "whsec", ProductMonthly: "prod_m", ProductYearly: "prod_y", Secret: secret})
}

func sign(key string, body []byte) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func TestVerifyWebhook(t *testing.T) {
	c := testClient()
	body := []byte(`{"id":"evt_1"}`)
	good := sign("whsec", body)
	for _, tc := range []struct {
		name, sig string
		want      bool
	}{
		{"good", good, true},
		{"upper case and spaces", " " + strings.ToUpper(good) + " ", true},
		{"missing", "", false},
		{"wrong key", sign("other", body), false},
		{"wrong length", good[:len(good)-2], false},
		{"one byte off", good[:len(good)-1] + "0", good[len(good)-1] == '0'},
	} {
		if got := c.VerifyWebhook(body, tc.sig); got != tc.want {
			t.Errorf("%s: VerifyWebhook = %v, want %v", tc.name, got, tc.want)
		}
	}
	// Another body under the same signature fails.
	if c.VerifyWebhook([]byte(`{"id":"evt_2"}`), good) {
		t.Error("a signature verified a different body")
	}
	// No webhook secret refuses everything.
	if New(Config{APIKey: "k"}).VerifyWebhook(body, sign("", body)) {
		t.Error("verified with no webhook secret")
	}
}

func TestAccountClaim(t *testing.T) {
	c := testClient()
	sig, err := c.SignClaim("usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if !c.ClaimHolds("usr_1", sig) {
		t.Error("a signed claim does not hold")
	}
	other, _ := c.SignClaim("usr_2")
	for _, tc := range [][2]string{{"usr_2", sig}, {"usr_1", ""}, {"usr_1", other}, {"", sig}, {"usr_1", sig[:10]}} {
		if c.ClaimHolds(tc[0], tc[1]) {
			t.Errorf("claim %q with %q holds", tc[0], tc[1])
		}
	}
	// Without a secret, nothing is signed and nothing holds.
	none := New(Config{APIKey: "k"})
	if _, err := none.SignClaim("usr_1"); err == nil {
		t.Error("signed a claim with no secret")
	}
	if none.ClaimHolds("usr_1", sig) {
		t.Error("a claim holds with no secret")
	}
}

func TestEventTime(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int64
	}{
		{`1761900000`, 1761900000000},
		{`1761900000123`, 1761900000123},
		{`1761900000.5`, 1761900000500},
		{`0`, 0},
		{`-5`, 0},
		{`"soon"`, 0},
		{`null`, 0},
		{``, 0},
		{`1761900000000000`, 0}, // microseconds, believed by nothing
	} {
		if got := (Event{CreatedAt: json.RawMessage(tc.raw)}).Time(); got != tc.want {
			t.Errorf("created_at %s: Time = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestModeFollowsTheKey(t *testing.T) {
	if c := New(Config{APIKey: "creem_test_abc"}); c.Mode() != "test" || c.base() != "https://test-api.creem.io" {
		t.Errorf("test key: mode %s base %s", c.Mode(), c.base())
	}
	if c := New(Config{APIKey: "creem_abc"}); c.Mode() != "live" || c.base() != "https://api.creem.io" {
		t.Errorf("live key: mode %s base %s", c.Mode(), c.base())
	}
}

func TestReadSubscription(t *testing.T) {
	c := testClient()
	sig, _ := c.SignClaim("usr_1")
	sub := map[string]any{"id": "sub_1", "status": "active", "product": map[string]any{"id": "prod_m"},
		"customer": map[string]any{"id": "cust_1", "email": "a@example.com"}, "current_period_end_date": "2026-11-29T10:00:00.000Z",
		"metadata": map[string]any{"userId": "usr_1", "sig": sig}}
	obj, _ := json.Marshal(sub)
	got := c.ReadSubscription(Event{EventType: "subscription.paid", Object: obj})
	want := Sub{SubscriptionID: "sub_1", CustomerID: "cust_1", Email: "a@example.com", ProductID: "prod_m", UserID: "usr_1",
		Status: "active", PeriodEnd: time.Date(2026, 11, 29, 10, 0, 0, 0, time.UTC)}
	if got != want {
		t.Errorf("subscription event:\n got %+v\nwant %+v", got, want)
	}

	// A checkout carries the subscription nested, and the metadata on the
	// checkout itself; its own id is never a subscription's.
	checkout, _ := json.Marshal(map[string]any{"id": "ch_1", "customer": "cust_1", "product": "prod_m",
		"metadata":     map[string]any{"userId": "usr_1", "sig": sig},
		"subscription": map[string]any{"id": "sub_1", "status": "active"}})
	got = c.ReadSubscription(Event{EventType: "checkout.completed", Object: checkout})
	if got.SubscriptionID != "sub_1" || got.CustomerID != "cust_1" || got.ProductID != "prod_m" || got.UserID != "usr_1" {
		t.Errorf("checkout with a subscription: %+v", got)
	}
	bare, _ := json.Marshal(map[string]any{"id": "ch_1", "customer": map[string]any{"id": "cust_1"}})
	if got = c.ReadSubscription(Event{EventType: "checkout.completed", Object: bare}); got.SubscriptionID != "" || got.CustomerID != "cust_1" {
		t.Errorf("checkout with no subscription: %+v", got)
	}

	// Unsigned metadata names nobody.
	sub["metadata"] = map[string]any{"userId": "usr_1"}
	obj, _ = json.Marshal(sub)
	if got = c.ReadSubscription(Event{EventType: "subscription.paid", Object: obj}); got.UserID != "" {
		t.Errorf("unsigned metadata read as %q", got.UserID)
	}
}

// fakeCreem records requests and answers with the handler's status and body.
type fakeCreem struct {
	paths  []string
	bodies []map[string]any
	keys   []string
	status int
	answer string
}

func (f *fakeCreem) start(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		f.paths, f.bodies, f.keys = append(f.paths, r.Method+" "+r.URL.Path), append(f.bodies, m), append(f.keys, r.Header.Get("x-api-key"))
		w.WriteHeader(f.status)
		io.WriteString(w, f.answer)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestCreateCheckout(t *testing.T) {
	f := &fakeCreem{status: 200, answer: `{"id":"ch_1","checkout_url":"https://checkout.creem.io/ch_1"}`}
	c := testClient()
	c.Endpoint = f.start(t).URL
	ctx := context.Background()
	u, err := c.CreateCheckout(ctx, Checkout{UserID: "usr_1", Email: "a@example.com", Period: Yearly, SuccessURL: "https://app/account"})
	if err != nil || u != "https://checkout.creem.io/ch_1" {
		t.Fatalf("checkout = %q, %v", u, err)
	}
	b := f.bodies[0]
	meta, _ := b["metadata"].(map[string]any)
	cust, _ := b["customer"].(map[string]any)
	if f.paths[0] != "POST /v1/checkouts" || f.keys[0] != "creem_test_key" || b["product_id"] != "prod_y" ||
		cust["email"] != "a@example.com" || b["success_url"] != "https://app/account" || meta["userId"] != "usr_1" {
		t.Errorf("checkout request %s key %s body %v", f.paths[0], f.keys[0], b)
	}
	if sig, _ := meta["sig"].(string); !c.ClaimHolds("usr_1", sig) {
		t.Error("the checkout's claim is not signed")
	}
	// A known customer is named by id.
	if _, err := c.CreateCheckout(ctx, Checkout{UserID: "usr_1", Email: "a@example.com", CustomerID: "cust_1", Period: Monthly}); err != nil {
		t.Fatal(err)
	}
	if cust, _ := f.bodies[1]["customer"].(map[string]any); cust["id"] != "cust_1" || cust["email"] != nil || f.bodies[1]["product_id"] != "prod_m" {
		t.Errorf("second checkout body %v", f.bodies[1])
	}

	// A refusal, an answer with no url, and an answer pointing elsewhere are
	// all errors.
	for _, tc := range []struct {
		status int
		answer string
	}{{422, `{"message":"no"}`}, {200, `{"id":"ch_1"}`}, {200, `{"checkout_url":"https://evil.example/x"}`}, {200, `not json`}} {
		f.status, f.answer = tc.status, tc.answer
		if u, err := c.CreateCheckout(ctx, Checkout{UserID: "usr_1", Email: "a@example.com", Period: Monthly}); err == nil {
			t.Errorf("%d %s: checkout = %q, want an error", tc.status, tc.answer, u)
		}
	}
	// Without a secret, nothing is sent.
	n := len(f.paths)
	c.cfg.Secret = ""
	if _, err := c.CreateCheckout(ctx, Checkout{UserID: "usr_1", Email: "a@example.com", Period: Monthly}); err == nil || len(f.paths) != n {
		t.Errorf("checkout without a secret: err %v, %d requests", err, len(f.paths)-n)
	}
}

func TestPortalAndCancel(t *testing.T) {
	f := &fakeCreem{status: 200, answer: `{"customer_portal_link":"https://creem.io/my-orders/login/xyz"}`}
	c := testClient()
	c.Endpoint = f.start(t).URL
	ctx := context.Background()
	u, err := c.PortalLink(ctx, "cust_1")
	if err != nil || u != "https://creem.io/my-orders/login/xyz" || f.paths[0] != "POST /v1/customers/billing" || f.bodies[0]["customer_id"] != "cust_1" {
		t.Fatalf("portal = %q, %v, request %s %v", u, err, f.paths[0], f.bodies[0])
	}
	f.status, f.answer = 500, `{}`
	if _, err := c.PortalLink(ctx, "cust_1"); err == nil {
		t.Error("a refused portal is not an error")
	}

	f.status, f.answer = 200, `{"id":"sub_1","status":"canceled"}`
	if already, err := c.CancelSubscription(ctx, "sub_1"); err != nil || already || f.paths[2] != "POST /v1/subscriptions/sub_1/cancel" {
		t.Errorf("cancel = %v, %v, %s", already, err, f.paths[2])
	}
	f.status = 404
	if already, err := c.CancelSubscription(ctx, "sub_1"); err != nil || !already {
		t.Errorf("cancel of a gone subscription = %v, %v", already, err)
	}
	f.status = 500
	if _, err := c.CancelSubscription(ctx, "sub_1"); err == nil {
		t.Error("a refused cancel is not an error")
	}
}
