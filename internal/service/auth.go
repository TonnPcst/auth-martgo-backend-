package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TonnPcst/martgo-auth/internal/apperr"
	"github.com/TonnPcst/martgo-auth/internal/db"
	"github.com/TonnPcst/martgo-auth/internal/otp"
	"github.com/TonnPcst/martgo-auth/internal/session"
	"github.com/TonnPcst/martgo-auth/internal/store"
	"github.com/TonnPcst/martgo-auth/internal/token"
)

// SessionWriter publishes a user's current token state for other services to check.
type SessionWriter interface {
	Put(ctx context.Context, userID int64, s session.State) error
}

type OTPManager interface {
	Start(ctx context.Context, sub otp.Subject, phone string) (otp.Challenge, error)
	Resend(ctx context.Context, id string) (otp.Challenge, error)
	Verify(ctx context.Context, id, code string) (otp.Subject, error)
}

type AuthService struct {
	store    store.Store
	tokens   *token.Manager
	sessions SessionWriter
	otp      OTPManager
	guard    *loginGuard
}

func NewAuthService(s store.Store, tokens *token.Manager, sessions SessionWriter, otps OTPManager) *AuthService {
	return &AuthService{store: s, tokens: tokens, sessions: sessions, otp: otps, guard: newLoginGuard(5, 15*time.Minute)}
}

type LoginResult struct {
	Token     string
	ExpiresAt time.Time
	User      db.User
	Challenge *otp.Challenge
}

var (
	errInvalidCredentials = apperr.Unauthorized("invalid email or password")
	errTooManyAttempts    = apperr.TooManyRequests("too many failed login attempts, please try again later")
	errInvalidOTP         = apperr.Unauthorized("invalid or expired code")
	errOTPExhausted       = apperr.Unauthorized("too many wrong codes, please log in again")
	errOTPGone            = apperr.Unauthorized("code expired, please log in again")
	errResendTooSoon      = apperr.TooManyRequests("please wait before requesting another code")
	errTooManySends       = apperr.TooManyRequests("no more codes can be sent, please log in again")
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

	if user.Phone != nil {
		ch, err := s.otp.Start(ctx, otp.Subject{UserID: user.ID, Email: key}, *user.Phone)
		if err != nil {
			return LoginResult{}, err
		}
		return LoginResult{User: user, Challenge: &ch}, nil
	}
	s.guard.reset(key)
	return s.issue(ctx, user)
}

func (s *AuthService) VerifyOTP(ctx context.Context, challengeID, code string) (LoginResult, error) {
	now := time.Now()
	sub, err := s.otp.Verify(ctx, challengeID, code)
	switch {
	case errors.Is(err, otp.ErrNotFound):
		return LoginResult{}, errInvalidOTP
	case errors.Is(err, otp.ErrInvalidCode):
		s.guard.fail(sub.Email, now)
		return LoginResult{}, errInvalidOTP
	case errors.Is(err, otp.ErrTooManyAttempts):
		s.guard.fail(sub.Email, now)
		return LoginResult{}, errOTPExhausted
	case err != nil:
		return LoginResult{}, err
	}
	if s.guard.locked(sub.Email, now) {
		return LoginResult{}, errTooManyAttempts
	}
	s.guard.reset(sub.Email)

	user, err := s.store.GetUserByID(ctx, sub.UserID)
	if store.IsNotFound(err) || (err == nil && !user.IsActive) {
		return LoginResult{}, errInvalidCredentials
	}
	if err != nil {
		return LoginResult{}, err
	}
	return s.issue(ctx, user)
}

func (s *AuthService) ResendOTP(ctx context.Context, challengeID string) (otp.Challenge, error) {
	ch, err := s.otp.Resend(ctx, challengeID)
	switch {
	case errors.Is(err, otp.ErrNotFound):
		return otp.Challenge{}, errOTPGone
	case errors.Is(err, otp.ErrResendTooSoon):
		return otp.Challenge{}, errResendTooSoon
	case errors.Is(err, otp.ErrTooManySends):
		return otp.Challenge{}, errTooManySends
	}
	return ch, err
}

func (s *AuthService) issue(ctx context.Context, user db.User) (LoginResult, error) {
	signed, expiredAt, err := s.tokens.Generate(user.ID, user.Role, user.TokenVersion)
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.sessions.Put(ctx, user.ID, sessionOf(user)); err != nil {
		return LoginResult{}, fmt.Errorf("publish session: %w", err)
	}
	return LoginResult{Token: signed, ExpiresAt: expiredAt, User: user}, nil
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
