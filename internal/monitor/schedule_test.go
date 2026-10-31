package monitor

import (
	"testing"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
)

func toronto(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("America/Toronto")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func utc(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

const everyDay = 0x7f

// A 09:00 slot in Toronto stays at 09:00 local across both changes, so its
// UTC time moves by an hour.
func TestScheduleKeepsLocalTimeAcrossDST(t *testing.T) {
	s := Schedule{Days: everyDay, Hour: 9, Minute: 0, Loc: toronto(t), Grace: 30 * time.Minute}
	cases := []struct{ after, want string }{
		// Summer time ends on Sunday 1 November 2026.
		{"2026-10-31T00:00:00Z", "2026-10-31T13:00:00Z"},
		{"2026-10-31T13:00:00Z", "2026-11-01T14:00:00Z"},
		{"2026-11-01T14:00:00Z", "2026-11-02T14:00:00Z"},
		// It starts again on Sunday 8 March 2026.
		{"2026-03-07T00:00:00Z", "2026-03-07T14:00:00Z"},
		{"2026-03-07T14:00:00Z", "2026-03-08T13:00:00Z"},
	}
	for _, c := range cases {
		if got := s.Next(utc(c.after)); !got.Equal(utc(c.want)) {
			t.Errorf("Next(%s) = %s, want %s", c.after, got.UTC().Format(time.RFC3339), c.want)
		}
	}
	// The missed deadline for Sunday 1 November is 09:30 EST, 14:30 UTC.
	if got := s.LastDue(utc("2026-11-01T14:29:00Z")); !got.Equal(utc("2026-10-31T13:00:00Z")) {
		t.Errorf("LastDue before the deadline = %s", got.UTC())
	}
	if got := s.LastDue(utc("2026-11-01T14:30:00Z")); !got.Equal(utc("2026-11-01T14:00:00Z")) {
		t.Errorf("LastDue at the deadline = %s", got.UTC())
	}
	// On the 23 hour day in spring the window is still split at the midpoint.
	slot := utc("2026-03-08T13:00:00Z")
	start, end := s.Window(slot)
	if !start.Equal(utc("2026-03-08T01:30:00Z")) || !end.Equal(utc("2026-03-09T01:00:00Z")) {
		t.Errorf("window = %s to %s", start.UTC(), end.UTC())
	}
}

func TestSchedulePlace(t *testing.T) {
	// Mondays and Thursdays at 07:30 UTC, with an hour of grace.
	s := Schedule{Days: 1<<1 | 1<<4, Hour: 7, Minute: 30, Loc: time.UTC, Grace: time.Hour}
	cases := []struct {
		at, slot string
		late     bool
	}{
		{"2026-10-26T07:00:00Z", "2026-10-26T07:30:00Z", false}, // early Monday
		{"2026-10-26T08:30:00Z", "2026-10-26T07:30:00Z", false}, // at the deadline
		{"2026-10-26T09:00:00Z", "2026-10-26T07:30:00Z", true},  // late
		{"2026-10-27T20:00:00Z", "2026-10-29T07:30:00Z", false}, // past the midpoint to Thursday
		{"2026-10-25T12:00:00Z", "2026-10-26T07:30:00Z", false}, // Sunday, nearer Monday
	}
	for _, c := range cases {
		slot, late := s.Place(utc(c.at))
		if !slot.Equal(utc(c.slot)) || late != c.late {
			t.Errorf("Place(%s) = %s late %v, want %s late %v", c.at, slot.UTC(), late, c.slot, c.late)
		}
	}
}

func TestDescribe(t *testing.T) {
	cases := []struct {
		p    db.Publication
		want string
	}{
		{db.Publication{Days: everyDay, At: "09:00", TimeZone: "America/Toronto", GraceMinutes: 30},
			"Every day at 09:00 in America/Toronto, with 30 minutes of grace."},
		{db.Publication{Days: 1<<1 | 1<<3 | 1<<5, At: "06:15", TimeZone: "UTC", GraceMinutes: 1},
			"Every Monday, Wednesday, and Friday at 06:15 in UTC, with 1 minute of grace."},
		{db.Publication{Days: 1<<0 | 1<<6, At: "10:00", TimeZone: "UTC", GraceMinutes: 60},
			"Every Saturday and Sunday at 10:00 in UTC, with 60 minutes of grace."},
	}
	for _, c := range cases {
		if got := Describe(c.p); got != c.want {
			t.Errorf("Describe = %q, want %q", got, c.want)
		}
	}
}

func TestIsSignup(t *testing.T) {
	for _, s := range []string{"Please confirm your subscription", "You’re subscribed!", "Verify your email"} {
		if !IsSignup(s, false) {
			t.Errorf("IsSignup(%q) = false", s)
		}
	}
	for _, s := range []string{"Shooting into the sun", "Issue 42: what we shipped", "How to verify your sending domain",
		"Welcome back: our fall issue", "Confirmed: rates hold steady", "Reactivate lapsed subscribers"} {
		if IsSignup(s, false) {
			t.Errorf("IsSignup(%q) = true for a publication with issues", s)
		}
	}
	// A looser match holds only before the first issue.
	if !IsSignup("Welcome to The Friday Letter", true) || IsSignup("Issue 1", true) {
		t.Error("first message of a publication")
	}
}
