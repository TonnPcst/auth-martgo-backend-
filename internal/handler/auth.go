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

// Login checks email and password. POST /api/v1/auth/login (5 requests/min per IP)
//
// ENG: If the user has no phone, returns 200 with the access token. If the user has a
// phone, sends an SMS code and returns 202 with a challenge ID, a masked phone
// number and the expiry/resend times; the client then calls VerifyOTP.
// LAO: ເຂົ້າສູ່ລະບົບດ້ວຍ email/ລະຫັດຜ່ານ — ມີເບີໂທຈະສົ່ງ OTP (202), ບໍ່ມີຈະໄດ້ token ເລີຍ (200).
//
// @param w - response writer
// @param r - request with {email, password}
// @returns writes 200 with the token or 202 with the OTP challenge; 401 on wrong credentials, 429 when locked out
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
	writeLoginResult(w, res)
}

// VerifyOTP finishes an SMS login. POST /api/v1/auth/login/verify (10 requests/min per IP)
//
// ENG: Takes the challenge ID from Login and the 6-digit code from the SMS. On success
// returns the access token like a normal login.
// LAO: ຢືນຢັນລະຫັດ OTP 6 ຫຼັກ ແລ້ວອອກ token.
//
// @param w - response writer
// @param r - request with {challenge_id, code}
// @returns writes 200 with the token; 401 if the code is wrong or expired
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

// ResendOTP sends a new SMS code for an open challenge. POST /api/v1/auth/login/resend (5 requests/min per IP)
//
// ENG: The old code stops working. Limited by a cooldown and a maximum number of sends.
// LAO: ສົ່ງລະຫັດ OTP ໃໝ່ — ລະຫັດເກົ່າໃຊ້ບໍ່ໄດ້ອີກ, ມີເວລາລໍຖ້າ ແລະ ຈຳກັດຈຳນວນຄັ້ງ.
//
// @param w - response writer
// @param r - request with {challenge_id}
// @returns writes 202 with the new expiry/resend times; 401 if the challenge is gone, 429 if too soon or too many
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

// Me returns the logged-in user's profile. GET /api/v1/auth/me
//
// ENG: The user ID comes from the verified token.
// LAO: ດຶງຂໍ້ມູນຂອງຜູ້ໃຊ້ທີ່ເຂົ້າສູ່ລະບົບຢູ່.
//
// @param w - response writer
// @param r - authenticated request
// @returns writes 200 with the user
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user, err := h.users.Get(r.Context(), actorFrom(r).UserID)
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, toUserResponse(user))
}

// Logout signs the user out everywhere. POST /api/v1/auth/logout
//
// ENG: Revokes every token the user holds, on all devices.
// LAO: ອອກຈາກລະບົບທຸກອຸປະກອນ — token ທັງໝົດຈະໃຊ້ບໍ່ໄດ້.
//
// @param w - response writer
// @param r - authenticated request
// @returns writes 204
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.auth.Logout(r.Context(), actorFrom(r).UserID); err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeLoginResult writes the answer of a first login step.
//
// ENG: 202 with the SMS challenge when the user has a phone, otherwise 200 with the token.
// Shared by the password login and the Google exchange.
// LAO: ຕອບຜົນການເຂົ້າສູ່ລະບົບ — ມີເບີໂທຕອບ 202 ພ້ອມ OTP challenge, ບໍ່ມີຕອບ 200 ພ້ອມ token.
//
// @param w - response writer
// @param res - login result
func writeLoginResult(w http.ResponseWriter, res service.LoginResult) {
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

// writeLogin writes a successful login response.
//
// ENG: Body: access_token, token_type "Bearer", expires_at and the user.
// LAO: ຕອບກັບເມື່ອເຂົ້າສູ່ລະບົບສຳເລັດ ພ້ອມ token ແລະ ຂໍ້ມູນຜູ້ໃຊ້.
//
// @param w - response writer
// @param res - login result with the signed token
func writeLogin(w http.ResponseWriter, res service.LoginResult) {
	httpx.JSON(w, http.StatusOK, loginResponse{
		AccessToken: res.Token,
		TokenType:   "Bearer",
		ExpiresAt:   res.ExpiresAt,
		User:        toUserResponse(res.User),
	})
}

// maskPhone hides all but the last 4 digits of a phone number.
//
// ENG: Example: 2055551234 becomes ******1234. Numbers of 4 digits or fewer are returned as is.
// LAO: ປິດບັງເບີໂທ ສະແດງສະເພາະ 4 ຕົວສຸດທ້າຍ.
//
// @param p - normalized phone number
// @returns the masked number
func maskPhone(p string) string {
	if len(p) <= 4 {
		return p
	}
	return strings.Repeat("*", len(p)-4) + p[len(p)-4:]
}
