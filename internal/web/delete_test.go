package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
)

func confirmDelete(email string) url.Values { return url.Values{"email": {email}} }

func userExists(t *testing.T, store *db.Store, id string) bool {
	t.Helper()
	ok, err := store.UserIDExists(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestDeleteAccountPages(t *testing.T) {
	_, store, h := newApp(t)
	u, session, _ := newUser(t, store, "a@example.com")

	w := serve(h, request("GET", "/account", nil, "", session))
	if !strings.Contains(w.Body.String(), `href="/account/delete"`) {
		t.Error("the account page does not link to deleting the account")
	}
	w = serve(h, request("GET", "/account/delete", nil, "", session))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `action="/account/delete"`) ||
		!strings.Contains(w.Body.String(), `name="csrf" value="`+testCSRF+`"`) || !strings.Contains(w.Body.String(), "cannot be undone") {
		t.Fatalf("delete page = %d %s", w.Code, w.Body)
	}

	// Signed out, both go to sign in.
	if w := serve(h, request("GET", "/account/delete", nil, "", "")); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/signin") {
		t.Errorf("signed-out page = %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := post(h, "/account/delete", confirmDelete(u.Email), ""); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/signin") {
		t.Errorf("signed-out post = %d %s", w.Code, w.Header().Get("Location"))
	}

	// No CSRF token, or another site's form, deletes nothing.
	form := "application/x-www-form-urlencoded"
	noToken := request("POST", "/account/delete", strings.NewReader(confirmDelete(u.Email).Encode()), form, session)
	if w := serve(h, noToken); w.Code != http.StatusForbidden {
		t.Errorf("no CSRF token = %d", w.Code)
	}
	vals := confirmDelete(u.Email)
	vals.Set("csrf", testCSRF)
	foreign := request("POST", "/account/delete", strings.NewReader(vals.Encode()), form, session)
	foreign.Header.Set("Origin", "https://evil.example")
	if w := serve(h, foreign); w.Code != http.StatusForbidden {
		t.Errorf("another site = %d", w.Code)
	}

	// The wrong address deletes nothing.
	for _, typed := range []string{"", "b@example.com", "a@example.co"} {
		w := post(h, "/account/delete", confirmDelete(typed), session)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "nothing was deleted") {
			t.Errorf("confirming with %q = %d", typed, w.Code)
		}
	}
	if !userExists(t, store, u.ID) {
		t.Fatal("a refused delete deleted the account")
	}
}

func TestDeleteAccount(t *testing.T) {
	_, store, h := newApp(t)
	u, session, token := newUser(t, store, "a@example.com")
	other, otherSession, _ := newUser(t, store, "b@example.com")
	ctx := context.Background()
	addr, err := store.CreateAddressFor(ctx, time.Hour, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	m := saveMessage(t, store, addr.Token, "smtp")

	// The address is compared as typed at sign-in: case and spaces aside.
	w := post(h, "/account/delete", confirmDelete("  A@Example.com "), session)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/?deleted=1" {
		t.Fatalf("delete = %d %s %s", w.Code, w.Header().Get("Location"), w.Body)
	}
	if c := cookieNamed(w, sessionCookie); c == nil || c.MaxAge >= 0 {
		t.Error("the session cookie was not cleared")
	}
	if userExists(t, store, u.ID) {
		t.Fatal("the account is still there")
	}
	if _, err := store.RawByID(ctx, m.ID); err == nil {
		t.Error("the account's raw message is still there")
	}
	if w := serve(h, request("GET", "/account", nil, "", session)); w.Code != http.StatusSeeOther {
		t.Errorf("old session still opens the account: %d", w.Code)
	}
	if w := apiDo(h, "POST", "/api/v1/test-addresses", token); w.Code != http.StatusUnauthorized {
		t.Errorf("old API token = %d", w.Code)
	}
	if w := do(h, "GET", "/?deleted=1", nil, ""); !strings.Contains(w.Body.String(), "were deleted") {
		t.Error("the home page does not say the account was deleted")
	}
	if !userExists(t, store, other.ID) || serve(h, request("GET", "/account", nil, "", otherSession)).Code != 200 {
		t.Error("another account was touched")
	}
}

func TestDeleteAccountCancelsTheSubscriptionFirst(t *testing.T) {
	a, store, h, fake := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	a.paid(t, h, u, 1000, time.Now().Add(30*24*time.Hour))
	existedAtCancel := false
	fake.onCancel = func() { existedAtCancel, _ = store.UserIDExists(context.Background(), u.ID) }

	w := post(h, "/account/delete", confirmDelete(u.Email), session)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	if fake.last().Path != "/v1/subscriptions/sub_1/cancel" {
		t.Fatalf("last Creem call = %s, want the cancel", fake.last().Path)
	}
	if !existedAtCancel {
		t.Error("the account was deleted before the subscription was cancelled")
	}
	if userExists(t, store, u.ID) {
		t.Error("the account is still there")
	}
	if e, ok := eventRow(t, store, "evt_paid_"+u.ID); !ok || e.UserID != "" {
		t.Errorf("payment event = %+v %v, want kept with no account", e, ok)
	}
}

func TestDeleteAccountCancelFailureDeletesNothing(t *testing.T) {
	a, store, h, fake := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	a.paid(t, h, u, 1000, time.Now().Add(30*24*time.Hour))
	fake.cancelStatus = http.StatusBadGateway

	w := post(h, "/account/delete", confirmDelete(u.Email), session)
	body := w.Body.String()
	if w.Code != http.StatusConflict || !strings.Contains(body, "nothing was changed") ||
		!strings.Contains(body, `action="/account/billing/portal"`) || strings.Contains(body, `action="/account/delete"`) {
		t.Fatalf("failed cancel = %d %s", w.Code, body)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "creem.io") {
		t.Error("the billing form cannot redirect to Creem under this page's CSP")
	}
	if !userExists(t, store, u.ID) || subOf(t, store, u.ID).Status != db.SubActive {
		t.Error("a failed cancel still changed the account")
	}
	if w := serve(h, request("GET", "/account", nil, "", session)); w.Code != 200 {
		t.Errorf("session ended on a failed cancel: %d", w.Code)
	}
}

func TestDeleteAccountCancelNotFoundCountsAsCancelled(t *testing.T) {
	a, store, h, fake := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	a.paid(t, h, u, 1000, time.Now().Add(30*24*time.Hour))
	fake.cancelStatus = http.StatusNotFound
	if w := post(h, "/account/delete", confirmDelete(u.Email), session); w.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	if userExists(t, store, u.ID) {
		t.Error("a subscription Creem no longer has blocked the delete")
	}
}

func TestDeleteAccountSkipsACancelledSubscription(t *testing.T) {
	a, store, h, fake := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	a.paid(t, h, u, 1000, time.Now().Add(30*24*time.Hour))
	a.send(t, h, ev{ID: "evt_cancel", Kind: "subscription.canceled", Claim: u.ID, Sub: "sub_1", Customer: "cust_1", At: 2000}, 200)
	calls := fake.count()
	if w := post(h, "/account/delete", confirmDelete(u.Email), session); w.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	if fake.count() != calls {
		t.Error("cancelled a subscription that had already ended")
	}
}

func TestDeleteAccountRefusesWhenBillingIsOff(t *testing.T) {
	_, store, h := newApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	if err := store.PutSubscription(context.Background(), db.Subscription{UserID: u.ID, CustomerID: "cust_1",
		SubscriptionID: "sub_1", Status: db.SubActive}); err != nil {
		t.Fatal(err)
	}
	w := post(h, "/account/delete", confirmDelete(u.Email), session)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "nothing was deleted") {
		t.Fatalf("delete with billing off = %d %s", w.Code, w.Body)
	}
	if !userExists(t, store, u.ID) {
		t.Error("an account still paying at Creem was deleted")
	}
}

func TestLateWebhookAfterDeletionRecreatesNothing(t *testing.T) {
	a, store, h, _ := billingApp(t)
	u, session, _ := newUser(t, store, "a@example.com")
	a.paid(t, h, u, 1000, time.Now().Add(30*24*time.Hour))
	if w := post(h, "/account/delete", confirmDelete(u.Email), session); w.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	// Creem's own events for the cancel, and a stray renewal, all naming
	// the deleted account by its signed claim and its ids.
	for _, e := range []ev{
		{ID: "evt_late_cancel", Kind: "subscription.canceled", Claim: u.ID, Sub: "sub_1", Customer: "cust_1", At: 2000},
		{ID: "evt_late_paid", Kind: "subscription.paid", Claim: u.ID, Sub: "sub_1", Customer: "cust_1",
			Product: "prod_monthly", Status: "active", At: 3000},
		{ID: "evt_late_checkout", Kind: "checkout.completed", Claim: u.ID, Sub: "sub_1", Customer: "cust_1", Checkout: true, At: 4000},
	} {
		if got := a.send(t, h, e, 200); got != "No such account" {
			t.Errorf("%s answered %q", e.Kind, got)
		}
		if row, ok := eventRow(t, store, e.ID); !ok || row.UserID != "" {
			t.Errorf("%s recorded as %+v %v, want with no account", e.Kind, row, ok)
		}
	}
	if userExists(t, store, u.ID) {
		t.Error("a late event brought the account back")
	}
	var n int
	if err := store.DB.QueryRow(`SELECT COUNT(*) FROM subscriptions`).Scan(&n); err != nil || n != 0 {
		t.Errorf("subscriptions = %d %v, want none", n, err)
	}
}
