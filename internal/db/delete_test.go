package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sendscore/sendscore/verdict"
)

// fillAccount signs up email and gives it a row in every table that can
// hold one: sessions, sign-in links, a known browser, an API token, a test
// address with a message, an upload, a publication with messages and an
// alert, an OAuth grant, counters, a subscription, and a Creem event.
func fillAccount(t *testing.T, s *Store, email string) User {
	t.Helper()
	ctx := context.Background()
	link, err := s.CreateLoginToken(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := s.ConsumeLoginToken(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = s.CreateLoginToken(ctx, email) // unused
	must(err)
	must(s.RememberBrowser(ctx, NewToken(32), email, time.Hour))
	_, _, err = s.CreateAPIToken(ctx, u.ID, "test", 25)
	must(err)

	now := s.Now()
	msg := func(m Message) {
		t.Helper()
		m.Source, m.ReceivedAt, m.ExpiresAt, m.Raw, m.Verdict = "smtp", now, now.Add(time.Hour), []byte("raw body"), &verdict.Verdict{}
		must(s.SaveMessage(ctx, &m))
	}
	addr, err := s.CreateAddressFor(ctx, time.Hour, u.ID)
	must(err)
	msg(Message{Token: addr.Token})
	msg(Message{UserID: u.ID}) // an upload
	p := &Publication{UserID: u.ID, Name: "News", TimeZone: "UTC", AlertEmail: email}
	must(s.CreatePublication(ctx, p, 5))
	msg(Message{PublicationID: p.ID, UserID: u.ID, Kind: KindIssue})
	msg(Message{PublicationID: p.ID, Kind: KindIssue})
	_, err = s.AddAlert(ctx, &Alert{PublicationID: p.ID, Kind: "worse", Key: "k", To: email})
	must(err)

	c, err := s.CreateOAuthClient(ctx, "App", []string{"https://a.test/cb"})
	must(err)
	code, err := s.CreateOAuthCode(ctx, OAuthCode{ClientID: c.ID, UserID: u.ID, RedirectURI: "https://a.test/cb"})
	must(err)
	_, err = s.ExchangeOAuthCode(ctx, code, func(OAuthCode) error { return nil })
	must(err)
	_, err = s.CreateOAuthCode(ctx, OAuthCode{ClientID: c.ID, UserID: u.ID, RedirectURI: "https://a.test/cb"}) // unused
	must(err)

	for _, name := range []string{"tests:user:", "billing:user:", "messages:user:"} {
		_, err = s.Take(ctx, name+u.ID, Day(now), 100, time.Hour)
		must(err)
	}
	must(s.PutSubscription(ctx, Subscription{UserID: u.ID, CustomerID: "cust_" + u.ID, SubscriptionID: "sub_" + u.ID, Status: SubActive}))
	_, err = s.RecordCreemEvent(ctx, CreemEvent{ID: "evt_" + u.ID, Kind: "subscription.paid", UserID: u.ID, Body: `{"customer":{"email":"gone@example.com"}}`})
	must(err)
	return u
}

// tableCounts counts the rows of every table in the database.
func tableCounts(t *testing.T, s *Store) map[string]int {
	t.Helper()
	rows, err := s.DB.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	rows.Close()
	out := map[string]int{}
	for _, n := range names {
		var c int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM ` + n).Scan(&c); err != nil {
			t.Fatal(err)
		}
		out[n] = c
	}
	return out
}

func TestDeleteUserRemovesEveryRow(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	other := fillAccount(t, s, "other@example.com")
	anon, _ := s.CreateAddress(ctx, time.Hour)
	save(t, s, anon.Token)
	before := tableCounts(t, s)

	u := fillAccount(t, s, "gone@example.com")
	filled := tableCounts(t, s)
	for table, n := range before {
		// Opt-outs hold no address and belong to no account.
		if table == "alert_recipients" {
			continue
		}
		if filled[table] <= n {
			t.Errorf("the fill left %s empty for the account, so the test does not cover it", table)
		}
	}

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	after := tableCounts(t, s)
	for table, n := range before {
		want := n
		switch table {
		case "creem_events", "oauth_clients":
			// The payment record and the shared registration are kept.
			want = n + 1
		}
		if after[table] != want {
			t.Errorf("%s has %d rows after the delete, want %d", table, after[table], want)
		}
	}
	e, err := s.CreemEventByID(ctx, "evt_"+u.ID)
	if err != nil || e.UserID != "" || strings.Contains(e.Body, "@") {
		t.Errorf("creem event = %+v %v, want kept with no account", e, err)
	}
	if ok, _ := s.UserIDExists(ctx, u.ID); ok {
		t.Error("the user row is still there")
	}
	if _, err := s.UserForSubscription(ctx, "sub_"+u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("subscription still resolves: %v", err)
	}

	// The other account is whole.
	if ok, _ := s.UserIDExists(ctx, other.ID); !ok {
		t.Fatal("the other account went too")
	}
	if sub, err := s.Subscription(ctx, other.ID); err != nil || sub.Status != SubActive {
		t.Errorf("other subscription = %+v %v", sub, err)
	}
	if e, _ := s.CreemEventByID(ctx, "evt_"+other.ID); e.UserID != other.ID {
		t.Errorf("other account's event lost its account: %+v", e)
	}
	if err := s.DeleteUser(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice: err = %v, want ErrNotFound", err)
	}
}
