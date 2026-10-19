package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/TonnPcst/martgo-auth/internal/apperr"
	"github.com/TonnPcst/martgo-auth/internal/httpx"
	"github.com/TonnPcst/martgo-auth/internal/oauth"
	"github.com/TonnPcst/martgo-auth/internal/service"
	chimw "github.com/go-chi/chi/v5/middleware"
)

type GoogleLogin interface {
	Start(ctx context.Context) (state, authURL string, err error)
	Finish(ctx context.Context, state, code string) (oauth.Identity, error)
}

const (
	stateCookie     = "martgo_oauth_state"
	stateCookiePath = "/api/v1/auth/google"
)

type GoogleHandler struct {
	google      GoogleLogin
	auth        *service.AuthService
	frontendURL string
	secure      bool
}

type googleExchangeRequest struct {
	Code string `json:"code" validate:"required,max=64"`
}

// Login sends the browser to Google. GET /api/v1/auth/google/login (10 requests/min per IP)
//
// ENG: Also puts the state in an HttpOnly cookie. The callback must bring back the same
// state, which ties the login to this browser: an attacker cannot make a victim finish
// a login the attacker started (login CSRF).
// LAO: ສົ່ງ browser ໄປໜ້າ login ຂອງ Google ແລະ ເກັບ state ໃນ cookie ເພື່ອກັນ login CSRF.
//
// @param w - response writer
// @param r - browser request
// @returns writes 302 to Google
func (h *GoogleHandler) Login(w http.ResponseWriter, r *http.Request) {
	state, authURL, err := h.google.Start(r.Context())
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	h.setStateCookie(w, state, 600)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback is where Google sends the browser back. GET /api/v1/auth/google/callback (10 requests/min per IP)
//
// ENG: Always redirects to OAUTH_FRONTEND_URL: with ?code=<one-time code> on success, or
// with ?error=<reason>: access_denied (cancelled at Google), invalid_state, not_allowed
// (no active MartGo user for this Google account) or failed (details in the log).
// LAO: Google ສົ່ງ browser ກັບມາບ່ອນນີ້ — redirect ໄປ frontend ພ້ອມ ?code= ຫຼື ?error=.
//
// @param w - response writer
// @param r - browser request with ?state=&code= (or ?error=)
// @returns writes 302 to the frontend
func (h *GoogleHandler) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	h.setStateCookie(w, "", -1)

	if q.Get("error") != "" {
		h.fail(w, r, "access_denied", nil)
		return
	}
	state := q.Get("state")
	cookie, err := r.Cookie(stateCookie)
	if err != nil || state == "" || cookie.Value != state {
		h.fail(w, r, "invalid_state", nil)
		return
	}

	id, err := h.google.Finish(r.Context(), state, q.Get("code"))
	switch {
	case errors.Is(err, oauth.ErrInvalidState):
		h.fail(w, r, "invalid_state", nil)
		return
	case errors.Is(err, oauth.ErrWrongDomain):
		h.fail(w, r, "not_allowed", nil)
		return
	case err != nil:
		h.fail(w, r, "failed", err)
		return
	}

	code, err := h.auth.LoginWithIdentity(r.Context(), id)
	switch {
	case apperr.KindOf(err) == apperr.KindUnauthorized:
		h.fail(w, r, "not_allowed", nil)
		return
	case err != nil:
		h.fail(w, r, "failed", err)
		return
	}
	h.redirect(w, r, url.Values{"code": {code}})
}

// Exchange turns the one-time code into a login. POST /api/v1/auth/google/exchange (10 requests/min per IP)
//
// ENG: Called by the frontend with the code from the callback redirect. Answers like
// POST /auth/login: 200 with the token, or 202 with an SMS challenge.
// LAO: ແລກລະຫັດໃຊ້ຄັ້ງດຽວເປັນ token (200) ຫຼື OTP challenge (202).
//
// @param w - response writer
// @param r - request with {code}
// @returns writes 200 or 202; 401 if the code is unknown, used or expired
func (h *GoogleHandler) Exchange(w http.ResponseWriter, r *http.Request) {
	var req googleExchangeRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	res, err := h.auth.ExchangeHandoff(r.Context(), req.Code)
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	writeLoginResult(w, res)
}

// setStateCookie sets or clears the state cookie.
//
// ENG: HttpOnly so scripts cannot read it, SameSite=Lax so it is still sent when Google
// redirects the browser back, and limited to the /api/v1/auth/google paths.
// LAO: ຕັ້ງ ຫຼື ລຶບ cookie ຂອງ state (HttpOnly, SameSite=Lax).
//
// @param w - response writer
// @param value - state, or "" when clearing
// @param maxAge - seconds to keep it, -1 to delete it
func (h *GoogleHandler) setStateCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    value,
		Path:     stateCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// fail redirects to the frontend with an error reason.
//
// ENG: Unexpected errors are logged with the request ID; the browser only gets the reason.
// LAO: redirect ໄປ frontend ພ້ອມເຫດຜົນທີ່ຜິດພາດ — ຂໍ້ຜິດພາດພາຍໃນຈະ log ໄວ້.
//
// @param w - response writer
// @param r - browser request
// @param reason - short error code for the frontend
// @param err - error to log, or nil
func (h *GoogleHandler) fail(w http.ResponseWriter, r *http.Request, reason string, err error) {
	if err != nil {
		slog.ErrorContext(r.Context(), "google login failed", "err", err, "request_id", chimw.GetReqID(r.Context()))
	}
	h.redirect(w, r, url.Values{"error": {reason}})
}

// redirect sends the browser to OAUTH_FRONTEND_URL with the given query.
//
// ENG: The target is fixed by config, never taken from the request (no open redirect).
// LAO: redirect ໄປ frontend (URL ຄົງທີ່ຈາກ config).
//
// @param w - response writer
// @param r - browser request
// @param v - query values to add
func (h *GoogleHandler) redirect(w http.ResponseWriter, r *http.Request, v url.Values) {
	http.Redirect(w, r, h.frontendURL+"?"+v.Encode(), http.StatusFound)
}
