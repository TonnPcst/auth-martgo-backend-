package handler

import (
	"net/http"
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
	httpx.JSON(w, http.StatusOK, loginResponse{
		AccessToken: res.Token,
		TokenType:   "Bearer",
		ExpiresAt:   res.ExpiresAt,
		User:        toUserResponse(res.User),
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
