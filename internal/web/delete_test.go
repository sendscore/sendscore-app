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
	var n int
	if err := store.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
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
