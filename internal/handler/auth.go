package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/TonnPcst/martgo-auth/internal/httpx"
	"github.com/TonnPcst/martgo-auth/internal/service"
)

type AuthHandler struct {
	auth  *service.AuthService
	users *service.UserService
}

type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,max=72"`
}

type loginResponse struct {
	AccessToken string       `json:"access_token"`
	TokenType   string       `json:"token_type"`
	ExpiresAt   time.Time    `json:"expires_at"`
	User        userResponse `json:"user"`
}

type otpChallengeResponse struct {
	OTPRequired bool      `json:"otp_required"`
	ChallengeID string    `json:"challenge_id"`
	PhoneHint   string    `json:"phone_hint,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	ResendAt    time.Time `json:"resend_at"`
}

type verifyOTPRequest struct {
	ChallengeID string `json:"challenge_id" validate:"required,max=64"`
	Code        string `json:"code" validate:"required,len=6,numeric"`
}

type resendOTPRequest struct {
	ChallengeID string `json:"challenge_id" validate:"required,max=64"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	res, err := h.auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	if res.Challenge != nil {
		httpx.JSON(w, http.StatusAccepted, otpChallengeResponse{
			OTPRequired: true,
			ChallengeID: res.Challenge.ID,
			PhoneHint:   maskPhone(*res.User.Phone),
			ExpiresAt:   res.Challenge.ExpiresAt,
			ResendAt:    res.Challenge.ResendAt,
		})
		return
	}
	writeLogin(w, res)
}

func (h *AuthHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req verifyOTPRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	res, err := h.auth.VerifyOTP(r.Context(), req.ChallengeID, req.Code)
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	writeLogin(w, res)
}

func (h *AuthHandler) ResendOTP(w http.ResponseWriter, r *http.Request) {
	var req resendOTPRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	ch, err := h.auth.ResendOTP(r.Context(), req.ChallengeID)
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, otpChallengeResponse{
		OTPRequired: true, ChallengeID: ch.ID, ExpiresAt: ch.ExpiresAt, ResendAt: ch.ResendAt,
	})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user, err := h.users.Get(r.Context(), actorFrom(r).UserID)
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, toUserResponse(user))
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.auth.Logout(r.Context(), actorFrom(r).UserID); err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeLogin(w http.ResponseWriter, res service.LoginResult) {
	httpx.JSON(w, http.StatusOK, loginResponse{
		AccessToken: res.Token,
		TokenType:   "Bearer",
		ExpiresAt:   res.ExpiresAt,
		User:        toUserResponse(res.User),
	})
}

// maskPhone shows only the last 4 digits: 2055551234 → ******1234.
func maskPhone(p string) string {
	if len(p) <= 4 {
		return p
	}
	return strings.Repeat("*", len(p)-4) + p[len(p)-4:]
}
