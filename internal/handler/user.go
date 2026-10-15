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
	Phone     *string   `json:"phone"`
	FullName  string    `json:"full_name"`
	Role      string    `json:"role"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// toUserResponse converts a user row into the public JSON shape.
//
// ENG: Leaves out the password hash and token version.
// LAO: ແປງຂໍ້ມູນຜູ້ໃຊ້ເປັນ JSON ສຳລັບຕອບກັບ (ບໍ່ລວມລະຫັດຜ່ານ).
//
// @param u - user row from the database
// @returns the response struct
func toUserResponse(u db.User) userResponse {
	return userResponse{
		ID: u.ID, Email: u.Email, Phone: u.Phone, FullName: u.FullName, Role: u.Role,
		IsActive: u.IsActive, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
}

type createUserRequest struct {
	Email    string `json:"email" validate:"required,email,max=254"`
	Password string `json:"password" validate:"required,min=8,max=72"`
	FullName string `json:"full_name" validate:"required,max=100"`
	Role     string `json:"role" validate:"required,oneof=admin manager cashier"`
	Phone    string `json:"phone" validate:"omitempty,max=20"`
}

type updateUserRequest struct {
	FullName *string `json:"full_name" validate:"omitempty,min=1,max=100"`
	Role     *string `json:"role" validate:"omitempty,oneof=admin manager cashier"`
	IsActive *bool   `json:"is_active"`
	Password *string `json:"password" validate:"omitempty,min=8,max=72"`
	// "" removes the phone, which turns SMS login codes off for the user.
	Phone *string `json:"phone" validate:"omitempty,max=20"`
}

// Create creates a user. POST /api/v1/users (admin)
//
// ENG: Body: email, password (8-72 chars), full_name, role and optional phone. Giving
// a phone turns on SMS login codes for that user.
// LAO: ສ້າງຜູ້ໃຊ້ໃໝ່ (ສະເພາະ admin).
//
// @param w - response writer
// @param r - request with the user JSON body
// @returns writes 201 with the user; 400 on bad input, 409 if the email or phone is taken
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	user, err := h.svc.Create(r.Context(), service.CreateUserInput{
		Email: req.Email, Password: req.Password, FullName: req.FullName, Role: req.Role, Phone: req.Phone,
	})
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, toUserResponse(user))
}

// Get returns one user. GET /api/v1/users/{id} (admin)
//
// ENG: Reads the ID from the path and loads the user.
// LAO: ດຶງຂໍ້ມູນຜູ້ໃຊ້ຕາມ ID.
//
// @param w - response writer
// @param r - request with the {id} path parameter
// @returns writes 200 with the user; 404 if it does not exist
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

// List returns a page of users. GET /api/v1/users (admin)
//
// ENG: Supports the limit and offset query parameters.
// LAO: ດຶງລາຍການຜູ້ໃຊ້ແບບແບ່ງໜ້າ.
//
// @param w - response writer
// @param r - request with optional limit/offset query
// @returns writes 200 with a paginated list
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

// Update changes some of a user's fields. PATCH /api/v1/users/{id} (admin)
//
// ENG: Only the fields sent are changed. An empty phone removes it, which turns SMS
// login codes off. Admins cannot deactivate themselves or change their own role.
// LAO: ແກ້ໄຂຂໍ້ມູນຜູ້ໃຊ້ບາງສ່ວນ — admin ປິດບັນຊີ ຫຼື ປ່ຽນ role ຂອງຕົນເອງບໍ່ໄດ້.
//
// @param w - response writer
// @param r - request with the {id} path parameter and the fields to change
// @returns writes 200 with the user; 400 on bad input, 404 if missing, 409 if the phone is taken
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
		FullName: req.FullName, Role: req.Role, IsActive: req.IsActive, Password: req.Password, Phone: req.Phone,
	})
	if err != nil {
		httpx.HandleError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, toUserResponse(user))
}
