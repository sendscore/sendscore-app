package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
)

// Deleting an account. A subscription at Creem is cancelled first, so no one
// is left paying for an account that is gone, and when that cannot be done
// nothing is deleted.

// deleteAccountForm asks before deleting, on its own page, so nothing is
// deleted by one click.
func (a *App) deleteAccountForm(w http.ResponseWriter, r *http.Request) {
	u := a.signedIn(w, r)
	if u == nil {
		return
	}
	a.renderDelete(w, r, http.StatusOK, u, nil)
}

func (a *App) renderDelete(w http.ResponseWriter, r *http.Request, status int, u *db.User, extra map[string]any) {
	data := map[string]any{"Title": "Delete your account"}
	sub, err := a.store.Subscription(r.Context(), u.ID)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		a.log.Error("subscription", "user", u.ID, "err", err)
	}
	data["Paying"] = liveSubscription(sub)
	data["Manage"] = a.cfg.Billing != nil && sub.CustomerID != ""
	for k, v := range extra {
		data[k] = v
	}
	// The billing form on a refusal answers with a redirect to Creem.
	a.accountCSP(w)
	a.render(w, r, status, "account_delete", data)
}

// liveSubscription reports whether a subscription may still charge: one in
// good standing, or any bound subscription Creem has not said is cancelled.
func liveSubscription(sub db.Subscription) bool {
	return db.GoodStanding(sub.Status) || (sub.SubscriptionID != "" && sub.Status != db.SubCancelled)
}

func (a *App) deleteAccount(w http.ResponseWriter, r *http.Request) {
	u := a.signedIn(w, r)
	if u == nil {
		return
	}
	typed := db.NormalizeEmail(r.PostFormValue("email"))
	if typed != db.NormalizeEmail(u.Email) {
		a.renderDelete(w, r, http.StatusBadRequest, u, map[string]any{
			"Error": "That is not the email address of this account, so nothing was deleted. Type it exactly as it appears above."})
		return
	}
	// Its own deadline, so a browser hanging up cannot stop it between the
	// cancel and the delete. The billing lock keeps a webhook from writing
	// the subscription back while the account is going.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
	defer cancel()
	a.billingMu.Lock()
	defer a.billingMu.Unlock()

	cancelled, refusal := a.endSubscription(ctx, u)
	if refusal != "" {
		a.renderDelete(w, r, http.StatusConflict, u, map[string]any{"Blocked": refusal})
		return
	}
	if err := a.store.DeleteUser(ctx, u.ID); err != nil {
		a.log.Error("delete account", "user", u.ID, "subscription_cancelled", cancelled, "err", err)
		msg := "Could not delete the account. Nothing was deleted. Try again in a minute."
		if cancelled {
			msg = "Your subscription at Creem was cancelled, but the account could not be deleted. Try again in a minute."
		}
		a.fail(w, r, http.StatusInternalServerError, msg)
		return
	}
	a.log.Info("account deleted", "user", u.ID, "subscription_cancelled", cancelled)
	a.setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/?deleted=1", http.StatusSeeOther)
}

// endSubscription cancels the account's subscription at Creem when it may
// still charge. It returns whether it cancelled one, or why the account
// cannot be deleted yet.
func (a *App) endSubscription(ctx context.Context, u *db.User) (cancelled bool, refusal string) {
	sub, err := a.store.Subscription(ctx, u.ID)
	if errors.Is(err, db.ErrNotFound) {
		return false, ""
	}
	if err != nil {
		a.log.Error("subscription", "user", u.ID, "err", err)
		return false, "Could not read this account's billing, so nothing was deleted. Try again in a minute."
	}
	if !liveSubscription(sub) {
		return false, ""
	}
	log := a.log.With("user", u.ID, "subscription", sub.SubscriptionID, "status", sub.Status)
	b := a.cfg.Billing
	if b == nil {
		log.Error("account with a live Creem subscription asked to be deleted, but billing is off here; refusing so they are not left paying")
		return false, "This account has a subscription at Creem, and this SendScore cannot cancel it right now, so nothing was deleted. Cancel the subscription with Creem first, then come back here to delete the account."
	}
	if sub.SubscriptionID == "" {
		log.Error("account in good standing has no Creem subscription id to cancel; refusing deletion")
		return false, "SendScore could not find the subscription to cancel at Creem, so nothing was changed. Cancel it on the billing page, then come back here to delete the account."
	}
	already, err := b.CancelSubscription(ctx, sub.SubscriptionID)
	if err != nil {
		log.Error("creem cancel before deleting the account", "err", err)
		return false, "Creem could not cancel your subscription just now, so nothing was changed and your account is still here. Cancel it on the billing page, then come back here to delete the account, or try again in a minute."
	}
	if already {
		log.Info("creem has no such subscription; treating it as cancelled")
	}
	return true, ""
}
