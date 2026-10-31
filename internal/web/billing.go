package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sendscore/sendscore-app/internal/billing"
	"github.com/sendscore/sendscore-app/internal/db"
)

// Billing through Creem (see internal/billing): the plan section of the
// account page, the checkout and portal forms behind it, and the webhook
// that is the only thing that changes a subscription.

// maxWebhookBytes is the largest webhook body read.
const maxWebhookBytes = 1 << 20

// checkoutsPerHour caps the checkout and portal links one account opens.
const checkoutsPerHour = 20

const billingUnchanged = " Nothing changed, and nothing was charged. Try again in a minute."

// planView is the plan section of the account page.
type planView struct {
	// State is free, active, past_due, lapsed, or comped.
	State     string
	Period    string
	PeriodEnd time.Time
	// Manage is set when the account has a customer at Creem.
	Manage       bool
	Yearly       bool
	PriceMonthly string
	PriceYearly  string
	Publications int
	HistoryDays  int
	// Confirming is set on the return from a checkout, until Creem's
	// webhook says the payment went through.
	Confirming bool
	Confirmed  bool
}

// planFor builds the plan section, or nil when billing is off.
func (a *App) planFor(ctx context.Context, r *http.Request, u *db.User) *planView {
	b := a.cfg.Billing
	if b == nil {
		return nil
	}
	v := &planView{State: "free", Yearly: b.YearlyOffered(), PriceMonthly: billing.PriceMonthly, PriceYearly: billing.PriceYearly,
		Publications: a.cfg.ProPublications, HistoryDays: a.cfg.HistoryDays}
	sub, err := a.store.Subscription(ctx, u.ID)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		a.log.Error("subscription", "user", u.ID, "err", err)
	}
	v.Manage = sub.CustomerID != ""
	v.Period, v.PeriodEnd = b.PeriodOf(sub.ProductID), sub.PeriodEnd
	switch {
	case u.Comped:
		v.State = "comped"
	case sub.Status == db.SubActive:
		v.State = "active"
	case sub.Status == db.SubPastDue:
		v.State = "past_due"
	case u.Lapsed:
		v.State = "lapsed"
	}
	if r.URL.Query().Get("checkout") == "done" {
		v.Confirmed = u.Plan == db.PlanPro
		v.Confirming = !v.Confirmed
	}
	return v
}

// planLink is where a page sends someone to buy Pro, or empty.
func (a *App) planLink(u *db.User) string {
	if a.cfg.Billing == nil || u == nil || u.Plan == db.PlanPro {
		return ""
	}
	return "/account#plan"
}

// takeBillingLink counts one checkout or portal link against the account's
// hourly allowance, answering the account page when it is used up.
func (a *App) takeBillingLink(w http.ResponseWriter, r *http.Request, u *db.User) bool {
	_, err := a.store.Take(r.Context(), "billing:user:"+u.ID, db.Hour(a.store.Now()), checkoutsPerHour, 2*time.Hour)
	if err == nil {
		return true
	}
	if !errors.Is(err, db.ErrLimit) {
		a.log.Error("count billing link", "err", err)
		return true
	}
	a.renderAccount(w, r, http.StatusTooManyRequests, map[string]any{"BillingError": "This account has opened many billing pages in the last hour. Try again in an hour."})
	return false
}

// checkout opens a Creem checkout for Pro and sends the browser to it. It
// grants nothing: Pro turns on when Creem's webhook says it was paid.
func (a *App) checkout(w http.ResponseWriter, r *http.Request) {
	u := a.signedIn(w, r)
	if u == nil {
		return
	}
	b := a.cfg.Billing
	if b == nil {
		a.fail(w, r, http.StatusNotFound, "This SendScore does not sell plans.")
		return
	}
	period := r.PostFormValue("period")
	if b.Product(period) == "" {
		a.renderAccount(w, r, http.StatusBadRequest, map[string]any{"BillingError": "That plan is not offered here."})
		return
	}
	if u.Plan == db.PlanPro {
		a.renderAccount(w, r, http.StatusConflict, map[string]any{"BillingError": "This account is already on Pro, so there is nothing to buy."})
		return
	}
	if !a.takeBillingLink(w, r, u) {
		return
	}
	sub, err := a.store.Subscription(r.Context(), u.ID)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		a.log.Error("subscription", "user", u.ID, "err", err)
	}
	link, err := b.CreateCheckout(r.Context(), billing.Checkout{UserID: u.ID, Email: u.Email, CustomerID: sub.CustomerID,
		Period: period, SuccessURL: a.cfg.BaseURL + "/account?checkout=done#plan"})
	if err != nil {
		a.log.Error("creem checkout", "user", u.ID, "err", err)
		a.renderAccount(w, r, http.StatusBadGateway, map[string]any{"BillingError": "Creem could not open a checkout just now." + billingUnchanged})
		return
	}
	http.Redirect(w, r, link, http.StatusSeeOther)
}

// billingPortal sends the browser to Creem's page for the account's
// customer, where the card, the invoices, and cancelling live.
func (a *App) billingPortal(w http.ResponseWriter, r *http.Request) {
	u := a.signedIn(w, r)
	if u == nil {
		return
	}
	b := a.cfg.Billing
	if b == nil {
		a.fail(w, r, http.StatusNotFound, "This SendScore does not sell plans.")
		return
	}
	sub, err := a.store.Subscription(r.Context(), u.ID)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		a.log.Error("subscription", "user", u.ID, "err", err)
	}
	if sub.CustomerID == "" {
		a.renderAccount(w, r, http.StatusBadRequest, map[string]any{"BillingError": "This account has no billing at Creem yet."})
		return
	}
	if !a.takeBillingLink(w, r, u) {
		return
	}
	link, err := b.PortalLink(r.Context(), sub.CustomerID)
	if err != nil {
		a.log.Error("creem portal", "user", u.ID, "err", err)
		a.renderAccount(w, r, http.StatusBadGateway, map[string]any{"BillingError": "Creem could not open the billing page just now. Nothing changed. Try again in a minute."})
		return
	}
	http.Redirect(w, r, link, http.StatusSeeOther)
}

// creemWebhook applies what Creem says about a subscription, which is the
// only thing that changes one. It takes no session and no CSRF token: it is
// authenticated by its signature alone. How it answers decides whether
// Creem retries.
//
//   - A bad or missing signature is 401, and nothing is written.
//   - Anything understood, applied or deliberately ignored, is 200, since a
//     4xx would make Creem retry a decision already made, for hours.
//   - Only a failure here is 500, the one case where a retry is wanted.
func (a *App) creemWebhook(w http.ResponseWriter, r *http.Request) {
	b := a.cfg.Billing
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBytes))
	if err != nil {
		if tooLarge := (*http.MaxBytesError)(nil); errors.As(err, &tooLarge) {
			http.Error(w, "Request body is too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	// No detail: explaining why a signature failed helps someone guess one.
	if !b.VerifyWebhook(raw, r.Header.Get(billing.SignatureHeader)) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var ev billing.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	// An event with no id cannot be deduplicated, so it is never applied
	// blind: two deliveries of an idless cancel, the second after a new
	// payment, would end a paying account.
	if ev.ID == "" {
		a.log.Error("creem event with no id; refusing to apply it blind", "kind", ev.EventType)
		http.Error(w, "No event id", http.StatusInternalServerError)
		return
	}
	// Its own deadline, so Creem hanging up cannot stop an event halfway.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Second)
	defer cancel()
	// One event at a time, since applying one reads the subscription,
	// decides, and writes it back.
	a.billingMu.Lock()
	defer a.billingMu.Unlock()

	sub := b.ReadSubscription(ev)
	userID, err := a.accountFor(ctx, sub)
	if err != nil {
		a.log.Error("creem account lookup", "event", ev.ID, "err", err)
		http.Error(w, "Could not apply", http.StatusInternalServerError)
		return
	}
	at := ev.Time()
	// Seen before? Then this is a retry of something already applied. The
	// insert is the check, so two deliveries racing cannot both win.
	first, err := a.store.RecordCreemEvent(ctx, db.CreemEvent{ID: ev.ID, Kind: ev.EventType, UserID: userID, At: at, Body: string(raw)})
	if err != nil {
		a.log.Error("record creem event", "event", ev.ID, "err", err)
		http.Error(w, "Could not apply", http.StatusInternalServerError)
		return
	}
	if !first {
		io.WriteString(w, "Already seen")
		return
	}
	// From here a failure must give the record back, or Creem's retry would
	// be answered "already seen" for an event never applied.
	msg, err := a.applyEvent(ctx, ev.EventType, sub, userID, at)
	if err != nil {
		a.log.Error("could not apply creem event; asking for it again", "event", ev.ID, "kind", ev.EventType, "err", err)
		if uerr := a.store.ForgetCreemEvent(ctx, ev.ID); uerr != nil {
			a.log.Error("AND could not take the record back: this event is recorded but NOT applied, so fix the account by hand",
				"event", ev.ID, "user", userID, "err", uerr)
		}
		http.Error(w, "Could not apply", http.StatusInternalServerError)
		return
	}
	// A stop before this line leaves the event unapplied on record, so
	// Creem's retry applies it again, which the event mark makes harmless.
	if err := a.store.MarkCreemEventApplied(ctx, ev.ID); err != nil {
		a.log.Error("mark creem event applied", "event", ev.ID, "err", err)
	}
	io.WriteString(w, msg)
}

// accountFor is whose account an event is about, in the order the sources
// can be trusted: the signed claim this app put in the checkout, then the
// subscription and customer ids an earlier event bound. There is no email
// fallback: Creem does not prove the buyer owns the address they type, so
// matching on it would let a stranger bind a subscription to someone else's
// account. An event that names nobody is recorded with no account and
// linked by hand.
func (a *App) accountFor(ctx context.Context, sub billing.Sub) (string, error) {
	if sub.UserID != "" {
		ok, err := a.store.UserIDExists(ctx, sub.UserID)
		if err != nil {
			return "", err
		}
		if ok {
			return sub.UserID, nil
		}
	}
	for _, find := range []func() (string, error){
		func() (string, error) { return a.store.UserForSubscription(ctx, sub.SubscriptionID) },
		func() (string, error) { return a.store.UserForCustomer(ctx, sub.CustomerID) },
	} {
		uid, err := find()
		if err == nil {
			return uid, nil
		}
		if !errors.Is(err, db.ErrNotFound) {
			return "", err
		}
	}
	return "", nil
}

// applyEvent applies a genuine event seen for the first time, and returns
// the answer for Creem.
func (a *App) applyEvent(ctx context.Context, kind string, sub billing.Sub, userID string, at int64) (string, error) {
	if userID == "" {
		a.log.Warn("creem event names no account here; link it by hand if it is real", "kind", kind,
			"subscription", sub.SubscriptionID, "customer", sub.CustomerID)
		return "No such account", nil
	}
	// Too late to matter: an event older than the newest one applied to the
	// account is recorded and ignored, since a cancel whose first delivery
	// timed out must not end the subscription bought after it.
	if at != 0 {
		cur, err := a.store.Subscription(ctx, userID)
		if err != nil && !errors.Is(err, db.ErrNotFound) {
			return "", err
		}
		if cur.Mark > at {
			a.log.Warn("creem event is older than what was already applied; recorded, not applied", "kind", kind, "user", userID)
			return "Out of order", nil
		}
	}
	switch kind {
	case "subscription.trialing":
		// SendScore sells no trial, so this can only be a payment link used
		// outside its checkout. A later payment arrives as subscription.paid.
		a.log.Warn("creem trial started, which SendScore does not sell; granting nothing", "user", userID)
	case "subscription.active", "subscription.paid":
		return "ok", a.writeSubscription(ctx, userID, sub, change{Status: db.SubActive, SetPeriod: true, PeriodEnd: sub.PeriodEnd}, at)
	case "subscription.past_due":
		// A failed payment Creem is retrying. Pro stays on meanwhile.
		return "ok", a.writeSubscription(ctx, userID, sub, change{Status: db.SubPastDue}, at)
	case "subscription.unpaid", "subscription.expired", "subscription.paused":
		return "ok", a.writeSubscription(ctx, userID, sub, change{Status: db.SubPaused}, at)
	case "subscription.canceled":
		return "ok", a.writeSubscription(ctx, userID, sub, change{Status: db.SubCancelled}, at)
	case "subscription.scheduled_cancel":
		// Nothing changes until the period ends and subscription.canceled
		// arrives.
		a.log.Info("creem subscription will cancel at the end of the period", "user", userID)
	case "subscription.update":
		status := statusFrom(sub.Status)
		if status == "" {
			return "ok", nil
		}
		return "ok", a.writeSubscription(ctx, userID, sub, change{Status: status, SetPeriod: true, PeriodEnd: sub.PeriodEnd}, at)
	case "refund.created", "dispute.created":
		// Neither changes what someone may do today. A person decides.
		a.log.Warn("creem "+kind+": look at this one", "user", userID)
	case "checkout.completed":
		// Binds the ids at once, since Creem sends this and the
		// subscription's own events in no promised order.
		if sub.CustomerID != "" || sub.SubscriptionID != "" {
			return "ok", a.writeSubscription(ctx, userID, sub, change{}, at)
		}
	default:
		a.log.Info("creem event SendScore does not act on", "kind", kind)
	}
	return "ok", nil
}

// statusFrom maps Creem's status words to the stored ones, or empty.
func statusFrom(s string) string {
	switch s {
	case "active":
		return db.SubActive
	case "past_due":
		return db.SubPastDue
	case "paused", "unpaid", "expired":
		return db.SubPaused
	case "canceled":
		return db.SubCancelled
	}
	return ""
}

// change is what an event writes: a status (or none), and for the events
// that carry one, the period end.
type change struct {
	Status    string
	SetPeriod bool
	PeriodEnd time.Time
}

// writeSubscription applies an event to the account's subscription, under
// the rules that keep a stranger's or a stale event from changing it.
func (a *App) writeSubscription(ctx context.Context, userID string, sub billing.Sub, next change, at int64) error {
	cur, err := a.store.Subscription(ctx, userID)
	if errors.Is(err, db.ErrNotFound) {
		cur, err = db.Subscription{UserID: userID}, nil
	}
	if err != nil {
		return err
	}
	closes := next.Status == db.SubPaused || next.Status == db.SubCancelled
	period := a.cfg.Billing.PeriodOf(sub.ProductID)
	log := a.log.With("user", userID, "subscription", sub.SubscriptionID)

	// Past due is a paying subscription's grace, not a way in: applied only
	// to one already active or past due.
	if next.Status == db.SubPastDue && !db.GoodStanding(cur.Status) {
		log.Warn("creem says past due, but the account is not on a paid plan; not letting it in on that", "status", cur.Status)
		return nil
	}
	// A product this install does not sell grants nothing, unless it is the
	// subscription the account is already on (moved to a new price at
	// Creem), whose renewals must still be recorded. Taking access away is
	// worth acting on whatever the product.
	if period == "" && sub.ProductID != "" && !closes {
		if sub.SubscriptionID == "" || sub.SubscriptionID != cur.SubscriptionID {
			log.Error("creem product is not one this install sells; granting nothing", "product", sub.ProductID)
			return nil
		}
		log.Warn("account is on a product this install does not sell; taking the dates", "product", sub.ProductID)
	}
	// Taking access away needs the bound subscription, not merely the same
	// customer, who may hold more than one.
	if closes && cur.SubscriptionID != "" && sub.SubscriptionID != "" && sub.SubscriptionID != cur.SubscriptionID {
		log.Warn("a different subscription ended; leaving the plan alone", "bound", cur.SubscriptionID)
		return nil
	}
	// The ids are only written onto a subscription that is unbound or no
	// longer in good standing, so a subscription bought elsewhere cannot
	// rebind a healthy account to someone else's customer.
	same := (sub.CustomerID != "" && sub.CustomerID == cur.CustomerID) ||
		(sub.SubscriptionID != "" && sub.SubscriptionID == cur.SubscriptionID)
	if db.GoodStanding(cur.Status) && cur.Bound() && !same {
		log.Error("refusing to rebind a healthy plan to another subscription; link it by hand if it is real", "bound", cur.SubscriptionID)
		return nil
	}

	nxt := cur
	if next.Status != "" {
		nxt.Status = next.Status
	}
	// A running period end is never overwritten with nothing: Creem's
	// subscription.active can carry no dates and land after the paid event
	// that did. An ended one is let go.
	if next.SetPeriod {
		keep := next.PeriodEnd.IsZero() && cur.PeriodEnd.After(a.store.Now()) && !closes
		if !keep {
			nxt.PeriodEnd = next.PeriodEnd
		}
	}
	if period != "" {
		nxt.ProductID = sub.ProductID
	}
	if sub.CustomerID != "" {
		nxt.CustomerID = sub.CustomerID
	}
	if sub.SubscriptionID != "" {
		nxt.SubscriptionID = sub.SubscriptionID
	}
	// The ordering mark moves only when a status was written, and a status
	// that binds another subscription starts it again from that event.
	rebinds := sub.SubscriptionID != "" && sub.SubscriptionID != cur.SubscriptionID
	switch {
	case next.Status != "" && rebinds:
		nxt.Mark = at
	case next.Status != "" && at != 0:
		nxt.Mark = max(cur.Mark, at)
	}
	if err := a.store.PutSubscription(ctx, nxt); err != nil {
		return err
	}
	if next.Status != "" && next.Status != cur.Status {
		log.Info("subscription status changed", "from", cur.Status, "to", next.Status)
	}
	return nil
}

// accountCSP widens form-action on the account page to Creem, since its
// checkout and portal forms answer with a redirect there, which form-action
// also governs.
func (a *App) accountCSP(w http.ResponseWriter) {
	if a.cfg.Billing != nil {
		w.Header().Set("Content-Security-Policy", strings.Replace(csp, "form-action 'self'", "form-action 'self' "+billing.CreemHosts, 1))
	}
}
