package web

import (
	"context"
	"net/http"
	"time"

	"github.com/sendscore/sendscore-app/internal/db"
)

// deleteAccountForm asks before deleting, on its own page, so nothing is
// deleted by one click.
func (a *App) deleteAccountForm(w http.ResponseWriter, r *http.Request) {
	u := a.signedIn(w, r)
	if u == nil {
		return
	}
	a.renderDelete(w, r, http.StatusOK, nil)
}

func (a *App) renderDelete(w http.ResponseWriter, r *http.Request, status int, extra map[string]any) {
	data := map[string]any{"Title": "Delete your account"}
	for k, v := range extra {
		data[k] = v
	}
	a.render(w, r, status, "account_delete", data)
}

func (a *App) deleteAccount(w http.ResponseWriter, r *http.Request) {
	u := a.signedIn(w, r)
	if u == nil {
		return
	}
	typed := db.NormalizeEmail(r.PostFormValue("email"))
	if typed != db.NormalizeEmail(u.Email) {
		a.renderDelete(w, r, http.StatusBadRequest, map[string]any{
			"Error": "That is not the email address of this account, so nothing was deleted. Type it exactly as it appears above."})
		return
	}
	// Its own deadline, so a browser hanging up cannot stop it halfway.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
	defer cancel()
	if err := a.store.DeleteUser(ctx, u.ID); err != nil {
		a.log.Error("delete account", "user", u.ID, "err", err)
		a.fail(w, r, http.StatusInternalServerError, "Could not delete the account. Nothing was deleted. Try again in a minute.")
		return
	}
	a.log.Info("account deleted", "user", u.ID)
	a.setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/?deleted=1", http.StatusSeeOther)
}
