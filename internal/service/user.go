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

func (s *UserService) Get(ctx context.Context, id int64) (db.User, error) {
	user, err := s.store.GetUserByID(ctx, id)
	return user, dbError(err, "user")
}

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
func userDBError(err error) error {
	if store.IsUniqueViolation(err) && store.ConstraintName(err) == "users_phone_key" {
		return apperr.Conflict("phone is already used by another user")
	}
	return dbError(err, "user")
}

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

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
