package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/TonnPcst/martgo-auth/internal/apperr"
	"github.com/TonnPcst/martgo-auth/internal/db"
	"github.com/TonnPcst/martgo-auth/internal/domain"
	"github.com/TonnPcst/martgo-auth/internal/store"
	"github.com/TonnPcst/martgo-auth/internal/token"
)

type UserService struct {
	store    store.Store
	sessions SessionWriter
}

// NewUserService creates the user management service.
//
// ENG: Session changes are published so other services see role and status updates.
// LAO: ສ້າງ service ສຳລັບຈັດການຜູ້ໃຊ້.
//
// @param s - data store
// @param sessions - publishes session state to Redis
// @returns the service
func NewUserService(s store.Store, sessions SessionWriter) *UserService {
	return &UserService{store: s, sessions: sessions}
}

type CreateUserInput struct {
	Email    string
	Phone    string
	Password string
	FullName string
	Role     string
}

type UpdateUserInput struct {
	FullName *string
	Phone    *string
	Role     *string
	IsActive *bool
	Password *string
}

// Create creates a new user.
//
// ENG: Validates the role, normalizes the optional phone, hashes the password with
// bcrypt and saves the user with a lower-cased email.
// LAO: ສ້າງຜູ້ໃຊ້ໃໝ່ — ກວດ role, ປັບເບີໂທ, hash ລະຫັດຜ່ານດ້ວຍ bcrypt.
//
// @param ctx - request context
// @param in - email, phone, password, full name and role
// @returns the created user, a validation error, or Conflict if the email or phone is taken
func (s *UserService) Create(ctx context.Context, in CreateUserInput) (db.User, error) {
	if !domain.IsValidRole(in.Role) {
		return db.User{}, apperr.Validation("invalid role %q", in.Role)
	}

	phone, err := normalizePhone(in.Phone)
	if err != nil {
		return db.User{}, err
	}

	hash, err := token.HashPassword(in.Password)
	if err != nil {
		return db.User{}, err
	}
	user, err := s.store.CreateUser(ctx, db.CreateUserParams{
		Email:        normalizeEmail(in.Email),
		Phone:        nilIfEmpty(phone),
		PasswordHash: hash,
		FullName:     strings.TrimSpace(in.FullName),
		Role:         in.Role,
	})
	return user, userDBError(err)
}

// Get loads a user by ID.
//
// ENG: Returns NotFound when there is no such user.
// LAO: ດຶງຜູ້ໃຊ້ຕາມ ID.
//
// @param ctx - request context
// @param id - user ID
// @returns the user, or a NotFound error
func (s *UserService) Get(ctx context.Context, id int64) (db.User, error) {
	user, err := s.store.GetUserByID(ctx, id)
	return user, dbError(err, "user")
}

// List returns one page of users and the total count.
//
// ENG: Runs the page query and the count query separately.
// LAO: ດຶງລາຍການຜູ້ໃຊ້ແບບແບ່ງໜ້າ ພ້ອມຈຳນວນທັງໝົດ.
//
// @param ctx - request context
// @param limit - page size
// @param offset - number of rows to skip
// @returns the page items and the total number of users
func (s *UserService) List(ctx context.Context, limit, offset int32) ([]db.User, int64, error) {
	users, err := s.store.ListUsers(ctx, db.ListUsersParams{Limit: limit, Offset: offset})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.store.CountUsers(ctx)
	if err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

// Update changes the given fields of a user.
//
// ENG: nil fields are left as they are. Users cannot deactivate themselves or change
// their own role. A new password is hashed; an empty phone removes it. After saving,
// the session is republished so role, active and token version changes reach other
// services right away.
// LAO: ແກ້ໄຂຂໍ້ມູນຜູ້ໃຊ້ — ປິດບັນຊີ/ປ່ຽນ role ຕົນເອງບໍ່ໄດ້, ແລ້ວອັບເດດ session ໃນ Redis.
//
// @param ctx - request context
// @param actor - user making the change
// @param id - user to update
// @param in - fields to change (nil means unchanged)
// @returns the updated user, a validation error, NotFound, or Conflict if the phone is taken
func (s *UserService) Update(ctx context.Context, actor Actor, id int64, in UpdateUserInput) (db.User, error) {
	if in.Role != nil && !domain.IsValidRole(*in.Role) {
		return db.User{}, apperr.Validation("invalid role %q", *in.Role)
	}
	if actor.UserID == id {
		if in.IsActive != nil && !*in.IsActive {
			return db.User{}, apperr.Validation("you cannot deactivate your own account")
		}
		if in.Role != nil && *in.Role != actor.Role {
			return db.User{}, apperr.Validation("you cannot change your own role")
		}
	}

	params := db.UpdateUserParams{ID: id, FullName: in.FullName, Role: in.Role, IsActive: in.IsActive}
	if in.Phone != nil {
		phone, err := normalizePhone(*in.Phone)
		if err != nil {
			return db.User{}, err
		}
		params.Phone = &phone
	}
	if in.Password != nil {
		hash, err := token.HashPassword(*in.Password)
		if err != nil {
			return db.User{}, err
		}
		params.PasswordHash = &hash
	}
	user, err := s.store.UpdateUser(ctx, params)
	if err != nil {
		return db.User{}, userDBError(err)
	}
	// Role, is_active or token_version may have changed: other services must see it.
	if err := s.sessions.Put(ctx, user.ID, sessionOf(user)); err != nil {
		return db.User{}, fmt.Errorf("publish session: %w", err)
	}
	return user, nil
}

// userDBError tells a duplicate phone apart from a duplicate email.
//
// ENG: Checks the violated constraint name; anything else falls back to dbError.
// LAO: ແຍກຂໍ້ຜິດພາດເບີໂທຊ້ຳ ອອກຈາກ email ຊ້ຳ.
//
// @param err - error from the store, may be nil
// @returns the converted error, or nil
func userDBError(err error) error {
	if store.IsUniqueViolation(err) && store.ConstraintName(err) == "users_phone_key" {
		return apperr.Conflict("phone is already used by another user")
	}
	return dbError(err, "user")
}

// normalizePhone normalizes an optional phone number.
//
// ENG: A blank value is allowed and returns "" (no phone). Anything else must be a
// valid Lao mobile number.
// LAO: ປັບເບີໂທ (ບໍ່ບັງຄັບ) — ວ່າງໄດ້, ຖ້າມີຕ້ອງເປັນເບີລາວທີ່ຖືກຕ້ອງ.
//
// @param s - phone as typed
// @returns the normalized phone or "", or a validation error
func normalizePhone(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	p, err := domain.NormalizePhone(s)
	if err != nil {
		return "", apperr.Validation("%v", err)
	}
	return p, nil
}

// nilIfEmpty returns nil for an empty string, otherwise a pointer to it.
//
// ENG: Used to store "no phone" as NULL.
// LAO: ຖ້າ string ວ່າງຈະສົ່ງຄືນ nil (ບັນທຶກເປັນ NULL).
//
// @param s - value
// @returns pointer to s, or nil
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
