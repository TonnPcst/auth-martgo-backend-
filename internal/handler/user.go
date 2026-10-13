package handler

import (
	"net/http"
	"time"

	"github.com/TonnPcst/martgo-auth/internal/db"
	"github.com/TonnPcst/martgo-auth/internal/httpx"
	"github.com/TonnPcst/martgo-auth/internal/service"
)

type UserHandler struct{ svc *service.UserService }

type userResponse struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	FullName  string    `json:"full_name"`
	Role      string    `json:"role"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toUserResponse(u db.User) userResponse {
	return userResponse{
		ID: u.ID, Email: u.Email, FullName: u.FullName, Role: u.Role,
		IsActive: u.IsActive, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
}

type createUserRequest struct {
	Email    string `json:"email" validate:"required,email,max=254"`
	Password string `json:"password" validate:"required,min=8,max=72"`
	FullName string `json:"full_name" validate:"required,max=100"`
	Role     string `json:"role" validate:"required,oneof=admin manager cashier"`
}

type updateUserRequest struct {
	FullName *string `json:"full_name" validate:"omitempty,min=1,max=100"`
	Role     *string `json:"role" validate:"omitempty,oneof=admin manager cashier"`
	IsActive *bool   `json:"is_active"`
	Password *string `json:"password" validate:"omitempty,min=8,max=72"`
}

func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	user, err := h.svc.Create(r.Context(), service.CreateUserInput{
		Email: req.Email, Password: req.Password, FullName: req.FullName, Role: req.Role,
	})
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, toUserResponse(user))
}

func (h *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.IDParam(r, "id")
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	user, err := h.svc.Get(r.Context(), id)
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, toUserResponse(user))
}

func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := httpx.ParsePagination(r)
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	users, total, err := h.svc.List(r.Context(), limit, offset)
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	out := make([]userResponse, len(users))
	for i, u := range users {
		out[i] = toUserResponse(u)
	}
	httpx.WritePage(w, out, limit, offset, total)
}

func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.IDParam(r, "id")
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	var req updateUserRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	user, err := h.svc.Update(r.Context(), actorFrom(r), id, service.UpdateUserInput{
		FullName: req.FullName, Role: req.Role, IsActive: req.IsActive, Password: req.Password,
	})
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, toUserResponse(user))
}
