package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/TonnPcst/martgo-auth/internal/apperr"
	"github.com/TonnPcst/martgo-auth/internal/db"
	"github.com/TonnPcst/martgo-auth/internal/session"
	"github.com/TonnPcst/martgo-auth/internal/store"
	"github.com/TonnPcst/martgo-auth/internal/token"
)

// SessionWriter publishes a user's current token state for other services to check.
type SessionWriter interface {
	Put(ctx context.Context, userID int64, s session.State) error
}

type AuthService struct {
	store    store.Store
	tokens   *token.Manager
	sessions SessionWriter
	guard    *loginGuard
}

func NewAuthService(s store.Store, tokens *token.Manager, sessions SessionWriter) *AuthService {
	return &AuthService{store: s, tokens: tokens, sessions: sessions, guard: newLoginGuard(5, 15*time.Minute)}
}

type LoginResult struct {
	Token     string
	ExpiresAt time.Time
	User      db.User
}

var (
	errInvalidCredentials = apperr.Unauthorized("invalid email or password")
	errTooManyAttempts    = apperr.TooManyRequests("too many failed login attempts, please try again later")
)

var dummyHash = sync.OnceValue(func() string {
	hash, _ := token.HashPassword("martgo-timing-dummy")
	return hash
})

func (s *AuthService) Login(ctx context.Context, email string, password string) (LoginResult, error) {
	key := normalizeEmail(email)
	now := time.Now()
	if s.guard.locked(key, now) {
		return LoginResult{}, errTooManyAttempts
	}

	user, err := s.store.GetUserByEmail(ctx, key)
	if err != nil {
		if store.IsNotFound(err) {
			token.CheckPassword(dummyHash(), password)
			s.guard.fail(key, now)
			return LoginResult{}, errInvalidCredentials
		}
		return LoginResult{}, err
	}
	if !token.CheckPassword(user.PasswordHash, password) || !user.IsActive {
		s.guard.fail(key, now)
		return LoginResult{}, errInvalidCredentials
	}
	s.guard.reset(key)

	signed, expiresAt, err := s.tokens.Generate(user.ID, user.Role, user.TokenVersion)
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.sessions.Put(ctx, user.ID, sessionOf(user)); err != nil {
		return LoginResult{}, fmt.Errorf("publish session: %w", err)
	}
	return LoginResult{Token: signed, ExpiresAt: expiresAt, User: user}, nil
}

// Logout revokes every token the user currently holds, on all devices.
func (s *AuthService) Logout(ctx context.Context, userID int64) error {
	user, err := s.store.BumpTokenVersion(ctx, userID)
	if err != nil {
		return err
	}
	return s.sessions.Put(ctx, user.ID, sessionOf(user))
}

func sessionOf(u db.User) session.State {
	return session.State{TokenVersion: u.TokenVersion, Role: u.Role, Active: u.IsActive}
}
