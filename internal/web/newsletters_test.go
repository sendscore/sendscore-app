package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore/engine"
)

func newsletterForm(name string) url.Values {
	return url.Values{"name": {name}, "day": {"1", "4"}, "at": {"09:00"}, "time_zone": {"America/Toronto"}, "grace_minutes": {"45"}}
}

// addNewsletter adds a newsletter through the form and returns its ID.
func addNewsletter(t *testing.T, h http.Handler, session, name string) string {
	t.Helper()
	w := post(h, "/newsletters", newsletterForm(name), session)
	loc := w.Header().Get("Location")
	if w.Code != 303 || !strings.HasPrefix(loc, "/newsletters/pub_") {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	return strings.TrimPrefix(loc, "/newsletters/")
}

func pro(t *testing.T, store *db.Store, u db.User) {
	t.Helper()
	if err := store.SetPlan(context.Background(), u.ID, db.PlanPro); err != nil {
		t.Fatal(err)
	}
}

// saveIssue stores the sample as a received issue of the publication.
func saveIssue(t *testing.T, store *db.Store, pubID string) *db.Message {
	t.Helper()
	ctx := context.Background()
	p, err := store.PublicationByID(ctx, pubID)
	if err != nil {
		t.Fatal(err)
	}
	raw := sample(t)
	v, err := engine.Analyze(ctx, raw, engine.Options{Resolver: engine.OfflineResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	now := store.Now()
	m := &db.Message{PublicationID: p.ID, UserID: p.UserID, Kind: db.KindIssue, Source: "smtp", ReceivedAt: now,
		ExpiresAt: now.Add(time.Hour), Raw: raw, Verdict: v}
	if err := store.SaveMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNewslettersNeedPro(t *testing.T) {
	_, store, h := newApp(t, func(c *Config) { c.ProPublications = 2 })
	u, session, _ := newUser(t, store, "free@example.com")

	w := serve(h, request("GET", "/newsletters", nil, "", session))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "part of the Pro plan") || strings.Contains(w.Body.String(), `href="/newsletters/new"`) {
		t.Errorf("free list page = %d:\n%s", w.Code, w.Body)
	}
	if w := serve(h, request("GET", "/newsletters/new", nil, "", session)); w.Code != 403 {
		t.Errorf("free new page = %d", w.Code)
	}
	if w := post(h, "/newsletters", newsletterForm("Letter"), session); w.Code != 403 {
		t.Errorf("free create = %d", w.Code)
	}

	pro(t, store, u)
	if w := serve(h, request("GET", "/newsletters/new", nil, "", session)); w.Code != 200 || !strings.Contains(w.Body.String(), `value="free@example.com"`) {
		t.Errorf("pro new page = %d, or the alert address is not the account's", w.Code)
	}
	addNewsletter(t, h, session, "One")
	addNewsletter(t, h, session, "Two")
	if w := post(h, "/newsletters", newsletterForm("Three"), session); w.Code != 403 || !strings.Contains(w.Body.String(), "can monitor 2 newsletters") {
		t.Errorf("past the pro limit = %d", w.Code)
	}
	// Signed out, the pages ask to sign in.
	if w := serve(h, request("GET", "/newsletters", nil, "", "")); w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/signin") {
		t.Errorf("signed out = %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestProEmailsArePromotedAtSignin(t *testing.T) {
	a, store, h := newApp(t, func(c *Config) { c.ProEmails = []string{"jon@example.com"} })
	for _, email := range []string{"jon@example.com", "other@example.com"} {
		post(h, "/signin", url.Values{"email": {email}}, "")
		if w := post(h, "/signin/verify", url.Values{"t": {mailer(a).lastLink(t)}}, ""); w.Code != 303 {
			t.Fatalf("verify = %d", w.Code)
		}
	}
	for email, want := range map[string]string{"jon@example.com": db.PlanPro, "other@example.com": db.PlanFree} {
		var plan string
		if err := store.DB.QueryRow(`SELECT plan FROM users WHERE email = ?`, email).Scan(&plan); err != nil || plan != want {
			t.Errorf("%s plan = %q %v, want %s", email, plan, err, want)
		}
	}
	// At startup, the listed accounts that exist are moved.
	if n, err := store.PromoteEmails(context.Background(), []string{"OTHER@example.com "}); err != nil || n != 1 {
		t.Errorf("PromoteEmails = %d %v", n, err)
	}
}

func TestNewsletterFormValidates(t *testing.T) {
	_, store, h := newApp(t)
	u, session, _ := newUser(t, store, "pro@example.com")
	pro(t, store, u)
	cases := []struct {
		change func(url.Values)
		want   string
	}{
		{func(v url.Values) { v.Set("name", "") }, "Give the newsletter a name"},
		{func(v url.Values) { v.Set("time_zone", "Mars/Olympus") }, "time zone is not one"},
		{func(v url.Values) { v.Set("time_zone", "Local") }, "time zone is not one"},
		{func(v url.Values) { v.Set("at", "") }, "Choose the time"},
		{func(v url.Values) { v.Set("at", "25:00") }, "hours and minutes"},
		{func(v url.Values) { v.Set("grace_minutes", "9999") }, "grace period"},
		{func(v url.Values) { v.Set("alert_email", "nope") }, "full email address"},
	}
	for _, c := range cases {
		v := newsletterForm("Letter")
		c.change(v)
		w := post(h, "/newsletters", v, session)
		if w.Code != 400 || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%v = %d, want 400 with %q", v, w.Code, c.want)
		}
	}
	// No days is a newsletter without a schedule.
	v := newsletterForm("Unscheduled")
	v.Del("day")
	if w := post(h, "/newsletters", v, session); w.Code != 303 {
		t.Errorf("no schedule = %d %s", w.Code, w.Body)
	}
}

func TestNewsletterPagesEditAndDelete(t *testing.T) {
	_, store, h := newApp(t)
	u, session, _ := newUser(t, store, "pro@example.com")
	pro(t, store, u)
	id := addNewsletter(t, h, session, "The Friday Letter")
	ctx := context.Background()
	p, err := store.PublicationForUser(ctx, id, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p.Days != 1<<1|1<<4 || p.At != "09:00" || p.TimeZone != "America/Toronto" || p.GraceMinutes != 45 || p.AlertEmail != "pro@example.com" {
		t.Errorf("stored %+v", p)
	}
	m := saveIssue(t, store, id)

	w := serve(h, request("GET", "/newsletters/"+id, nil, "", session))
	body := w.Body.String()
	for _, want := range []string{"m-" + p.Token + "@in.test", "Every Monday and Thursday at 09:00 in America/Toronto, with 45 minutes of grace.",
		"/r/" + m.ID, "/newsletters/" + id + "/messages/" + m.ID, "No alert has been sent yet."} {
		if !strings.Contains(body, want) {
			t.Errorf("publication page is missing %q", want)
		}
	}
	if w := serve(h, request("GET", "/newsletters", nil, "", session)); !strings.Contains(w.Body.String(), "The Friday Letter") || !strings.Contains(w.Body.String(), "/r/"+m.ID) {
		t.Errorf("list page does not show the newsletter and its latest issue")
	}
	// The report links back for the owner.
	if w := serve(h, request("GET", "/r/"+m.ID, nil, "", session)); !strings.Contains(w.Body.String(), `href="/newsletters/`+id+`"`) {
		t.Errorf("report does not link back to the newsletter")
	}

	// The safe view shows the text and the links, and no HTML from the message.
	w = serve(h, request("GET", "/newsletters/"+id+"/messages/"+m.ID, nil, "", session))
	body = w.Body.String()
	if w.Code != 200 || !strings.Contains(body, `href="http://example.com/posts/sun"`) || !strings.Contains(body, "Read the full tip") || strings.Contains(body, "cdn.example.com/sun.jpg\"") {
		t.Errorf("message view = %d:\n%s", w.Code, body)
	}

	edit := newsletterForm("Renamed")
	edit.Set("paused", "on")
	edit.Del("day")
	if w := post(h, "/newsletters/"+id, edit, session); w.Code != 303 {
		t.Fatalf("edit = %d %s", w.Code, w.Body)
	}
	p, _ = store.PublicationForUser(ctx, id, u.ID)
	if p.Name != "Renamed" || !p.Paused || p.Scheduled() {
		t.Errorf("after edit %+v", p)
	}

	// Delete asks first, on a page of its own.
	if w := serve(h, request("GET", "/newsletters/"+id+"/delete", nil, "", session)); w.Code != 200 || !strings.Contains(w.Body.String(), "cannot be undone") {
		t.Errorf("delete page = %d", w.Code)
	}
	if w := post(h, "/newsletters/"+id+"/delete", nil, session); w.Code != 303 || w.Header().Get("Location") != "/newsletters/"+id+"/delete" {
		t.Errorf("delete without confirming = %d %s", w.Code, w.Header().Get("Location"))
	}
	if _, err := store.PublicationForUser(ctx, id, u.ID); err != nil {
		t.Fatal("deleted without confirming")
	}
	if w := post(h, "/newsletters/"+id+"/delete", url.Values{"confirm": {"delete"}}, session); w.Code != 303 {
		t.Errorf("delete = %d", w.Code)
	}
	if _, err := store.PublicationForUser(ctx, id, u.ID); err == nil {
		t.Error("not deleted")
	}
	if _, err := store.MessageByID(ctx, m.ID); err == nil {
		t.Error("the history was not deleted")
	}
}

func TestNewslettersBelongToTheirOwner(t *testing.T) {
	_, store, h := newApp(t)
	alice, aliceSession, aliceToken := newUser(t, store, "alice@example.com")
	bob, bobSession, bobToken := newUser(t, store, "bob@example.com")
	pro(t, store, alice)
	pro(t, store, bob)
	id := addNewsletter(t, h, aliceSession, "Alice's Letter")
	m := saveIssue(t, store, id)

	for _, path := range []string{"/newsletters/" + id, "/newsletters/" + id + "/edit", "/newsletters/" + id + "/delete",
		"/newsletters/" + id + "/messages/" + m.ID} {
		if w := serve(h, request("GET", path, nil, "", bobSession)); w.Code != 404 {
			t.Errorf("bob GET %s = %d", path, w.Code)
		}
	}
	if w := post(h, "/newsletters/"+id, newsletterForm("Taken"), bobSession); w.Code != 404 {
		t.Errorf("bob edit = %d", w.Code)
	}
	if w := post(h, "/newsletters/"+id+"/delete", url.Values{"confirm": {"delete"}}, bobSession); w.Code != 404 {
		t.Errorf("bob delete = %d", w.Code)
	}
	if w := serve(h, request("GET", "/newsletters", nil, "", bobSession)); strings.Contains(w.Body.String(), "Alice") {
		t.Error("bob's list shows alice's newsletter")
	}
	// A message of another publication is not shown under this one.
	bobID := addNewsletter(t, h, bobSession, "Bob's Letter")
	if w := serve(h, request("GET", "/newsletters/"+bobID+"/messages/"+m.ID, nil, "", bobSession)); w.Code != 404 {
		t.Errorf("alice's message under bob's newsletter = %d", w.Code)
	}

	// The API answers for the owner only.
	w := apiDo(h, "GET", "/api/v1/publications", aliceToken)
	var list struct {
		Publications []APIPublication `json:"publications"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != 200 || len(list.Publications) != 1 {
		t.Fatalf("alice's list = %d %s", w.Code, w.Body)
	}
	got := list.Publications[0]
	if got.ID != id || got.Latest == nil || got.Latest.ReportID != m.ID || got.Schedule == nil ||
		strings.Join(got.Schedule.Days, ",") != "monday,thursday" || !strings.HasPrefix(got.Address, "m-") {
		t.Errorf("alice's publication = %+v", got)
	}
	w = apiDo(h, "GET", "/api/v1/publications/"+id, aliceToken)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"reports"`) || !strings.Contains(w.Body.String(), m.ID) {
		t.Errorf("alice's publication = %d %s", w.Code, w.Body)
	}
	if w := apiDo(h, "GET", "/api/v1/publications/"+id, bobToken); w.Code != 404 {
		t.Errorf("bob reads alice's publication = %d", w.Code)
	}
	if w := apiDo(h, "GET", "/api/v1/publications", bobToken); strings.Contains(w.Body.String(), id) {
		t.Error("bob's list has alice's publication")
	}
	if w := apiDo(h, "GET", "/api/v1/publications", ""); w.Code != 401 {
		t.Errorf("no token = %d", w.Code)
	}
	if w := apiDo(h, "GET", "/api/v1/reports/"+m.ID, bobToken); w.Code != 404 {
		t.Errorf("bob reads alice's issue report = %d", w.Code)
	}
	if w := apiDo(h, "GET", "/api/v1/reports/"+m.ID, aliceToken); w.Code != 200 {
		t.Errorf("alice reads her issue report = %d", w.Code)
	}

	// So does list_publications on the MCP connector.
	srv := httptest.NewServer(h)
	defer srv.Close()
	for token, want := range map[string]bool{aliceToken: true, bobToken: false} {
		cs, err := connectMCP(t, srv.URL, token)
		if err != nil {
			t.Fatal(err)
		}
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_publications", Arguments: map[string]any{}})
		if err != nil || res.IsError {
			t.Fatalf("list_publications: %v %+v", err, res)
		}
		b, _ := json.Marshal(res.StructuredContent)
		if strings.Contains(string(b), id) != want {
			t.Errorf("list_publications for %s: %s", token[:12], b)
		}
		cs.Close()
	}
}

func TestBillingOffGivesProWithoutWritingIt(t *testing.T) {
	a, store, _ := newApp(t)
	ctx := context.Background()
	u, _, _ := newUser(t, store, "self@example.com")
	store.AllPro = true
	plan, err := store.PlanOf(ctx, u.ID)
	if err != nil || plan != db.PlanPro {
		t.Fatalf("plan with billing off = %q %v", plan, err)
	}
	if got := a.publicationLimit(&db.User{Plan: plan}); got != DefaultProPublications {
		t.Errorf("limit with billing off = %d", got)
	}
	// Billing coming back takes it away again, since nothing was stored.
	store.AllPro = false
	if p, _ := store.PlanOf(ctx, u.ID); p != db.PlanFree {
		t.Errorf("plan after billing returned = %q", p)
	}
	var stored string
	if err := store.DB.QueryRow(`SELECT plan FROM users WHERE id = ?`, u.ID).Scan(&stored); err != nil || stored != db.PlanFree {
		t.Errorf("users.plan = %q %v", stored, err)
	}
}
