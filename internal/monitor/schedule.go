// Package monitor watches published newsletters: it places each issue in
// its expected slot, decides when an alert is due, sends alerts once, and
// runs the heartbeat that notices a missed issue.
package monitor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // time zones work on a server without a zoneinfo database

	"github.com/sendscore/sendscore-app/internal/db"
)

// MaxGrace is the longest grace period. Slots are at least a day apart
// (23 hours across a change to summer time), and a deadline must fall
// before the midpoint to the next slot.
const MaxGrace = 10 * time.Hour

// Schedule is when a publication's issues are expected: on some weekdays at
// a local time in a time zone, with a grace period after it.
type Schedule struct {
	Days         int // bit set of time.Weekday
	Hour, Minute int
	Loc          *time.Location
	Grace        time.Duration
}

// ParseAt reads a local time as HH:MM.
func ParseAt(s string) (hour, minute int, err error) {
	h, m, ok := strings.Cut(s, ":")
	if !ok || len(h) != 2 || len(m) != 2 {
		return 0, 0, errors.New("time must be HH:MM")
	}
	hour, err1 := strconv.Atoi(h)
	minute, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, errors.New("time must be HH:MM")
	}
	return hour, minute, nil
}

// ScheduleOf returns the publication's schedule, or ok false when it has
// none or it cannot be read.
func ScheduleOf(p db.Publication) (Schedule, bool) {
	if !p.Scheduled() {
		return Schedule{}, false
	}
	h, m, err := ParseAt(p.At)
	if err != nil {
		return Schedule{}, false
	}
	loc, err := time.LoadLocation(p.TimeZone)
	if err != nil {
		return Schedule{}, false
	}
	return Schedule{Days: p.Days & 0x7f, Hour: h, Minute: m, Loc: loc, Grace: time.Duration(p.GraceMinutes) * time.Minute}, p.Days&0x7f != 0
}

// slots lists the scheduled times in [from, to], in order. Each is built
// from the local date, so a slot keeps its local time across a change
// between winter and summer time.
func (s Schedule) slots(from, to time.Time) []time.Time {
	var out []time.Time
	start := from.In(s.Loc)
	for i := -1; ; i++ {
		// Noon is never skipped or repeated by a time change.
		day := time.Date(start.Year(), start.Month(), start.Day()+i, 12, 0, 0, 0, s.Loc)
		slot := s.at(day)
		if slot.After(to) && day.After(to) {
			return out
		}
		if s.Days&(1<<day.Weekday()) != 0 && !slot.Before(from) && !slot.After(to) {
			out = append(out, slot)
		}
	}
}

// week is long enough to hold a slot of any schedule with a day set.
const week = 8 * 24 * time.Hour

// Prev returns the latest slot at or before t.
func (s Schedule) Prev(t time.Time) time.Time {
	ss := s.slots(t.Add(-week), t)
	return ss[len(ss)-1]
}

// Next returns the earliest slot after t.
func (s Schedule) Next(t time.Time) time.Time {
	for _, slot := range s.slots(t, t.Add(week)) {
		if slot.After(t) {
			return slot
		}
	}
	panic("monitor: schedule without a slot in a week")
}

// Window returns the span of time whose issues count for a slot: from the
// midpoint after the previous slot to the midpoint before the next one.
func (s Schedule) Window(slot time.Time) (start, end time.Time) {
	prev := s.Prev(slot.Add(-time.Second))
	next := s.Next(slot)
	return prev.Add(slot.Sub(prev) / 2), slot.Add(next.Sub(slot) / 2)
}

// Deadline is when an issue for the slot is late.
func (s Schedule) Deadline(slot time.Time) time.Time { return slot.Add(s.Grace) }

// Place returns the slot an issue received at t counts for, and whether it
// arrived after that slot's deadline.
func (s Schedule) Place(t time.Time) (slot time.Time, late bool) {
	prev, next := s.Prev(t), s.Next(t)
	slot = next
	if t.Before(prev.Add(next.Sub(prev) / 2)) {
		slot = prev
	}
	return slot, t.After(s.Deadline(slot))
}

// LastDue returns the latest slot whose deadline is at or before now.
func (s Schedule) LastDue(now time.Time) time.Time { return s.Prev(now.Add(-s.Grace)) }

var dayNames = []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}

// DayName is a weekday's name.
func DayName(d int) string { return dayNames[d%7] }

// Describe says the schedule in a sentence, such as "Every Monday and
// Thursday at 09:00 in America/Toronto, with 30 minutes of grace."
func Describe(p db.Publication) string {
	if !p.Scheduled() {
		return "No schedule is set, so SendScore compares each issue with the last one but does not expect issues at a set time."
	}
	var days string
	switch p.Days & 0x7f {
	case 0x7f:
		days = "Every day"
	case 0x3e:
		days = "Every weekday"
	default:
		var names []string
		// Monday first, as most calendars show a week.
		for _, d := range []int{1, 2, 3, 4, 5, 6, 0} {
			if p.Days&(1<<d) != 0 {
				names = append(names, dayNames[d])
			}
		}
		days = "Every " + list(names)
	}
	return fmt.Sprintf("%s at %s in %s, with %s of grace.", days, p.At, p.TimeZone, minutes(p.GraceMinutes))
}

func minutes(n int) string {
	if n == 1 {
		return "1 minute"
	}
	return strconv.Itoa(n) + " minutes"
}

// list joins words with commas and "and", with the serial comma.
func list(words []string) string {
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	case 2:
		return words[0] + " and " + words[1]
	}
	return strings.Join(words[:len(words)-1], ", ") + ", and " + words[len(words)-1]
}

// at is the schedule's local time on day's date. A time skipped by a change
// to summer time becomes the first moment after the gap, so the slot never
// comes before the send it stands for.
func (s Schedule) at(day time.Time) time.Time {
	t := time.Date(day.Year(), day.Month(), day.Day(), s.Hour, s.Minute, 0, 0, s.Loc)
	if t.Hour() == s.Hour && t.Minute() == s.Minute {
		return t
	}
	start, end := t.ZoneBounds()
	// Go resolves a skipped time with one of the two offsets, so t is on
	// one side of the gap or the other.
	wall := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)
	if wall.Before(time.Date(day.Year(), day.Month(), day.Day(), s.Hour, s.Minute, 0, 0, time.UTC)) {
		return end
	}
	return start
}
