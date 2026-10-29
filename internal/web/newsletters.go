package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore-app/internal/monitor"
	"github.com/sendscore/sendscore-app/internal/safeview"
	"github.com/sendscore/sendscore/verdict"
)

// Monitored newsletters (publications): pages, the API, and the
// list_publications MCP tool.

// Defaults for the publication settings in Config.
const (
	DefaultProPublications = 5
	DefaultGraceMinutes    = 30
	// timelineLength is how many messages a publication page shows.
	timelineLength = 100
	// apiReports is how many recent reports the publication API returns.
	apiReports = 50
)

// timeZones are offered in the form; any IANA name is accepted.
var timeZones = []string{
	"UTC", "America/New_York", "America/Toronto", "America/Chicago", "America/Denver", "America/Phoenix",
	"America/Los_Angeles", "America/Vancouver", "America/Anchorage", "America/Halifax", "America/Mexico_City",
	"America/Sao_Paulo", "America/Buenos_Aires", "Europe/London", "Europe/Dublin", "Europe/Lisbon", "Europe/Paris",
	"Europe/Berlin", "Europe/Amsterdam", "Europe/Madrid", "Europe/Rome", "Europe/Stockholm", "Europe/Warsaw",
	"Europe/Athens", "Europe/Helsinki", "Europe/Istanbul", "Africa/Lagos", "Africa/Johannesburg", "Africa/Nairobi",
	"Asia/Dubai", "Asia/Kolkata", "Asia/Singapore", "Asia/Hong_Kong", "Asia/Shanghai", "Asia/Tokyo", "Asia/Seoul",
	"Australia/Perth", "Australia/Sydney", "Australia/Melbourne", "Pacific/Auckland", "Pacific/Honolulu",
}

// weekdays lists the days in the form, Monday first.
var weekdays = []int{1, 2, 3, 4, 5, 6, 0}

// publicationLimit is how many publications the user's plan allows.
func (a *App) publicationLimit(u *db.User) int {
	if u.Plan == db.PlanPro {
		return a.cfg.ProPublications
	}
	return a.cfg.FreePublications
}

func (a *App) monitorAddress(p db.Publication) string { return "m-" + p.Token + "@" + a.cfg.MailDomain }

// signedIn returns the user, or sends a signed-out visitor to sign in and
// returns nil.
func (a *App) signedIn(w http.ResponseWriter, r *http.Request) *db.User {
	u := userFrom(r.Context())
	if u == nil {
		localRedirect(w, "/signin?next="+url.QueryEscape(r.URL.Path))
	}
	return u
}

// ownPublication loads the signed-in user's publication named in the path,
// answering 404 for anyone else's.
func (a *App) ownPublication(w http.ResponseWriter, r *http.Request) (*db.User, db.Publication, bool) {
	u := a.signedIn(w, r)
	if u == nil {
		return nil, db.Publication{}, false
	}
	p, err := a.store.PublicationForUser(r.Context(), r.PathValue("id"), u.ID)
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			a.log.Error("publication", "err", err)
		}
		a.fail(w, r, http.StatusNotFound, "This newsletter does not exist, or it belongs to another account.")
		return nil, p, false
	}
	return u, p, true
}

// planMessage explains why the user cannot add a publication, or is empty.
func (a *App) planMessage(u *db.User, count int) string {
	limit := a.publicationLimit(u)
	switch {
	case count < limit:
		return ""
	case limit == 0:
		return "Monitoring newsletters is part of the Pro plan. This account is on the free plan, so it cannot add a newsletter yet. Test addresses and uploads work as before."
	case limit == 1:
		return "This account can monitor 1 newsletter, and it already does. Delete it to add another."
	}
	return fmt.Sprintf("This account can monitor %d newsletters, and it already does. Delete one to add another.", limit)
}

type publicationRow struct {
	P        db.Publication
	Address  string
	Schedule string
	Latest   *db.Message
}

func (a *App) newsletters(w http.ResponseWriter, r *http.Request) {
	u := a.signedIn(w, r)
	if u == nil {
		return
	}
	ctx := r.Context()
	pubs, err := a.store.Publications(ctx, u.ID)
	if err != nil {
		a.log.Error("publications", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not load your newsletters.")
		return
	}
	rows := make([]publicationRow, 0, len(pubs))
	for _, p := range pubs {
		row := publicationRow{P: p, Address: a.monitorAddress(p), Schedule: monitor.Describe(p)}
		if m, err := a.store.LatestIssue(ctx, p.ID); err == nil {
			row.Latest = m
		}
		rows = append(rows, row)
	}
	a.render(w, r, http.StatusOK, "newsletters", map[string]any{"Title": "Newsletters", "Rows": rows,
		"PlanMessage": a.planMessage(u, len(pubs)), "Limit": a.publicationLimit(u)})
}

// formData is what the add and edit form shows.
func (a *App) formData(p db.Publication, title, action, errMsg string) map[string]any {
	days := map[int]bool{}
	for d := range 7 {
		days[d] = p.Days&(1<<d) != 0
	}
	type day struct {
		Value   int
		Name    string
		Checked bool
	}
	var ds []day
	for _, d := range weekdays {
		ds = append(ds, day{d, monitor.DayName(d), days[d]})
	}
	return map[string]any{"Title": title, "P": p, "Days": ds, "Zones": timeZones, "Action": action, "Error": errMsg,
		"MaxGrace": int(monitor.MaxGrace / time.Minute)}
}

func (a *App) newNewsletter(w http.ResponseWriter, r *http.Request) {
	u := a.signedIn(w, r)
	if u == nil {
		return
	}
	pubs, err := a.store.Publications(r.Context(), u.ID)
	if err != nil {
		a.log.Error("publications", "err", err)
	}
	if msg := a.planMessage(u, len(pubs)); msg != "" {
		a.render(w, r, http.StatusForbidden, "error", map[string]any{"Title": "Monitoring needs Pro", "Message": msg})
		return
	}
	p := db.Publication{TimeZone: "UTC", GraceMinutes: DefaultGraceMinutes, AlertEmail: u.Email}
	a.render(w, r, http.StatusOK, "newsletter_form", a.formData(p, "Add a newsletter", "/newsletters", ""))
}

// readPublication fills p from the form, returning a message for the first
// field that is not right.
func readPublication(r *http.Request, p *db.Publication, u *db.User) string {
	p.Name = strings.TrimSpace(r.PostFormValue("name"))
	p.At = strings.TrimSpace(r.PostFormValue("at"))
	p.TimeZone = strings.TrimSpace(r.PostFormValue("time_zone"))
	p.AlertEmail = db.NormalizeEmail(r.PostFormValue("alert_email"))
	p.Paused = r.PostFormValue("paused") == "on"
	p.Days = 0
	for _, v := range r.PostForm["day"] {
		if d, err := strconv.Atoi(v); err == nil && d >= 0 && d < 7 {
			p.Days |= 1 << d
		}
	}
	if p.TimeZone == "" {
		p.TimeZone = "UTC"
	}
	if p.AlertEmail == "" {
		p.AlertEmail = u.Email
	}
	grace := strings.TrimSpace(r.PostFormValue("grace_minutes"))
	p.GraceMinutes = DefaultGraceMinutes
	if grace != "" {
		n, err := strconv.Atoi(grace)
		if err != nil || n < 0 || time.Duration(n)*time.Minute > monitor.MaxGrace {
			return fmt.Sprintf("The grace period is a number of minutes from 0 to %d.", int(monitor.MaxGrace/time.Minute))
		}
		p.GraceMinutes = n
	}
	switch {
	case p.Name == "":
		return "Give the newsletter a name, such as the one readers see."
	case utf8.RuneCountInString(p.Name) > 100:
		return "Keep the name to 100 characters or fewer."
	case !validZone(p.TimeZone):
		return "The time zone is not one SendScore knows. Use an IANA name such as America/Toronto or Europe/London."
	case !validEmail(p.AlertEmail):
		return "Enter a full email address for alerts, such as you@example.com."
	}
	if p.At != "" {
		if _, _, err := monitor.ParseAt(p.At); err != nil {
			return "Enter the send time as hours and minutes, such as 09:00."
		}
	}
	if p.Days != 0 && p.At == "" {
		return "Choose the time the issue usually goes out, or clear the days to leave the schedule off."
	}
	return ""
}

func validZone(name string) bool {
	if name != "UTC" && !strings.Contains(name, "/") {
		return false
	}
	_, err := time.LoadLocation(name)
	return err == nil
}

func (a *App) createNewsletter(w http.ResponseWriter, r *http.Request) {
	u := a.signedIn(w, r)
	if u == nil {
		return
	}
	p := db.Publication{UserID: u.ID}
	if msg := readPublication(r, &p, u); msg != "" {
		a.render(w, r, http.StatusBadRequest, "newsletter_form", a.formData(p, "Add a newsletter", "/newsletters", msg))
		return
	}
	err := a.store.CreatePublication(r.Context(), &p, a.publicationLimit(u))
	if errors.Is(err, db.ErrLimit) {
		pubs, _ := a.store.Publications(r.Context(), u.ID)
		a.render(w, r, http.StatusForbidden, "error", map[string]any{"Title": "Monitoring needs Pro", "Message": a.planMessage(u, len(pubs))})
		return
	}
	if err != nil {
		a.log.Error("create publication", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not add the newsletter.")
		return
	}
	http.Redirect(w, r, "/newsletters/"+p.ID, http.StatusSeeOther)
}

func (a *App) newsletter(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.ownPublication(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	msgs, err := a.store.PublicationMessages(ctx, p.ID, timelineLength)
	if err != nil {
		a.log.Error("publication messages", "err", err)
	}
	data := map[string]any{"Title": p.Name, "P": p, "Address": a.monitorAddress(p), "Schedule": monitor.Describe(p),
		"Messages": msgs, "HistoryDays": a.cfg.HistoryDays}
	if al, err := a.store.LastSentAlert(ctx, p.ID); err == nil {
		data["LastAlert"] = al
	}
	if s, ok := monitor.ScheduleOf(p); ok && !p.Paused {
		data["Next"] = s.Next(a.store.Now())
	}
	a.render(w, r, http.StatusOK, "newsletter", data)
}

func (a *App) editNewsletter(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.ownPublication(w, r)
	if !ok {
		return
	}
	a.render(w, r, http.StatusOK, "newsletter_form", a.formData(p, "Edit "+p.Name, "/newsletters/"+p.ID, ""))
}

func (a *App) updateNewsletter(w http.ResponseWriter, r *http.Request) {
	u, p, ok := a.ownPublication(w, r)
	if !ok {
		return
	}
	if msg := readPublication(r, &p, u); msg != "" {
		a.render(w, r, http.StatusBadRequest, "newsletter_form", a.formData(p, "Edit "+p.Name, "/newsletters/"+p.ID, msg))
		return
	}
	if err := a.store.UpdatePublication(r.Context(), &p); err != nil {
		a.log.Error("update publication", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not save the newsletter.")
		return
	}
	http.Redirect(w, r, "/newsletters/"+p.ID, http.StatusSeeOther)
}

// deleteNewsletterForm asks before deleting, on its own page, so nothing is
// deleted by one click.
func (a *App) deleteNewsletterForm(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.ownPublication(w, r)
	if !ok {
		return
	}
	a.render(w, r, http.StatusOK, "newsletter_delete", map[string]any{"Title": "Delete " + p.Name, "P": p,
		"Address": a.monitorAddress(p)})
}

func (a *App) deleteNewsletter(w http.ResponseWriter, r *http.Request) {
	u, p, ok := a.ownPublication(w, r)
	if !ok {
		return
	}
	if r.PostFormValue("confirm") != "delete" {
		http.Redirect(w, r, "/newsletters/"+p.ID+"/delete", http.StatusSeeOther)
		return
	}
	if err := a.store.DeletePublication(r.Context(), p.ID, u.ID); err != nil {
		a.log.Error("delete publication", "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not delete the newsletter.")
		return
	}
	http.Redirect(w, r, "/newsletters", http.StatusSeeOther)
}

// messageView shows one of a publication's messages as text and a list of
// links, without its HTML or images, so the owner can find a confirmation
// link and open it themselves.
func (a *App) messageView(w http.ResponseWriter, r *http.Request) {
	_, p, ok := a.ownPublication(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	m, err := a.store.MessageByID(ctx, r.PathValue("mid"))
	if err != nil || m.PublicationID != p.ID {
		a.fail(w, r, http.StatusNotFound, "This message does not exist, or it has expired.")
		return
	}
	raw, err := a.store.RawByID(ctx, m.ID)
	if err != nil {
		a.fail(w, r, http.StatusNotFound, "This message does not exist, or it has expired.")
		return
	}
	v, err := safeview.Parse(raw)
	if err != nil {
		a.fail(w, r, http.StatusUnprocessableEntity, "This message could not be read.")
		return
	}
	a.render(w, r, http.StatusOK, "message", map[string]any{"Title": v.Subject, "P": p, "M": m, "View": v})
}

// API

type apiSchedule struct {
	Days         []string `json:"days"`
	Time         string   `json:"time"`
	TimeZone     string   `json:"time_zone"`
	GraceMinutes int      `json:"grace_minutes"`
	Description  string   `json:"description"`
}

type apiIssue struct {
	ReportID    string         `json:"report_id"`
	Kind        string         `json:"kind"`
	ReceivedAt  time.Time      `json:"received_at"`
	Subject     string         `json:"subject"`
	Verdict     verdict.Status `json:"verdict"`
	ReadyToSend bool           `json:"ready_to_send"`
	Changes     int            `json:"changes"`
	Worsened    bool           `json:"worsened"`
	Late        bool           `json:"late"`
	ReportURL   string         `json:"report_url"`
}

type apiAlert struct {
	Kind     string    `json:"kind"`
	SentAt   time.Time `json:"sent_at"`
	Subject  string    `json:"subject"`
	ReportID string    `json:"report_id,omitempty"`
}

// APIPublication is a publication as the API and MCP return it.
type APIPublication struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Address    string       `json:"address"`
	Schedule   *apiSchedule `json:"schedule"`
	AlertEmail string       `json:"alert_email"`
	Paused     bool         `json:"paused"`
	PageURL    string       `json:"page_url"`
	Latest     *apiIssue    `json:"latest"`
	LastAlert  *apiAlert    `json:"last_alert"`
	Reports    []apiIssue   `json:"reports,omitempty"`
}

func worsened(v *verdict.Verdict) bool {
	return slices.ContainsFunc(v.Changes, func(c verdict.Change) bool { return c.Worsened != "" })
}

func (a *App) apiIssue(m *db.Message) apiIssue {
	return apiIssue{ReportID: m.ID, Kind: m.Kind, ReceivedAt: m.ReceivedAt, Subject: m.Verdict.Message.Subject,
		Verdict: m.Verdict.Verdict, ReadyToSend: m.Verdict.ReadyToSend, Changes: len(m.Verdict.Changes),
		Worsened: worsened(m.Verdict), Late: m.Late, ReportURL: a.cfg.BaseURL + "/r/" + m.ID}
}

func (a *App) apiPublication(ctx context.Context, p db.Publication) APIPublication {
	out := APIPublication{ID: p.ID, Name: p.Name, Address: a.monitorAddress(p), AlertEmail: p.AlertEmail,
		Paused: p.Paused, PageURL: a.cfg.BaseURL + "/newsletters/" + p.ID}
	if p.Scheduled() {
		s := &apiSchedule{Time: p.At, TimeZone: p.TimeZone, GraceMinutes: p.GraceMinutes, Description: monitor.Describe(p), Days: []string{}}
		for _, d := range weekdays {
			if p.Days&(1<<d) != 0 {
				s.Days = append(s.Days, strings.ToLower(monitor.DayName(d)))
			}
		}
		out.Schedule = s
	}
	if m, err := a.store.LatestIssue(ctx, p.ID); err == nil {
		i := a.apiIssue(m)
		out.Latest = &i
	}
	if al, err := a.store.LastSentAlert(ctx, p.ID); err == nil {
		out.LastAlert = &apiAlert{Kind: al.Kind, SentAt: al.SentAt, Subject: al.Subject, ReportID: al.ReportID}
	}
	return out
}

func (a *App) listPublications(ctx context.Context, u *db.User) ([]APIPublication, error) {
	pubs, err := a.store.Publications(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	out := make([]APIPublication, 0, len(pubs))
	for _, p := range pubs {
		out = append(out, a.apiPublication(ctx, p))
	}
	return out, nil
}

func (a *App) apiPublications(w http.ResponseWriter, r *http.Request) {
	out, err := a.listPublications(r.Context(), userFrom(r.Context()))
	if err != nil {
		a.log.Error("publications", "err", err)
		apiError(w, http.StatusInternalServerError, "could not list publications")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publications": out})
}

func (a *App) apiPublicationByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := a.store.PublicationForUser(ctx, r.PathValue("id"), userFrom(ctx).ID)
	if err != nil {
		apiError(w, http.StatusNotFound, "no such publication")
		return
	}
	out := a.apiPublication(ctx, p)
	msgs, err := a.store.PublicationMessages(ctx, p.ID, apiReports)
	if err != nil {
		a.log.Error("publication messages", "err", err)
	}
	out.Reports = []apiIssue{}
	for _, m := range msgs {
		out.Reports = append(out.Reports, a.apiIssue(m))
	}
	writeJSON(w, http.StatusOK, out)
}

// MCP

type publicationsOut struct {
	Publications []APIPublication `json:"publications"`
}

type noInput struct{}

// addPublicationTools adds list_publications to the connector's tools.
func (a *App) addPublicationTools(s *mcp.Server, u *db.User) {
	closed := false
	mcp.AddTool(s, &mcp.Tool{
		Name:  "list_publications",
		Title: "List monitored newsletters",
		Description: "List the newsletters this account monitors, each with its monitoring address, expected schedule, alert address, " +
			"whether alerts are paused, its latest issue (verdict, ready_to_send, number of changes from the issue before, and whether anything got worse), and the last alert sent.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &closed},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, publicationsOut, error) {
		out, err := a.listPublications(ctx, u)
		return nil, publicationsOut{Publications: out}, err
	})
}
