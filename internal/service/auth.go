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

// NewAuthService creates the authentication service.
//
// ENG: Also creates the login guard: 5 failures lock an email for 15 minutes.
// LAO: ສ້າງ service ສຳລັບການເຂົ້າສູ່ລະບົບ — ຜິດ 5 ຄັ້ງຈະລັອກ 15 ນາທີ.
//
// @param s - data store
// @param tokens - signs access tokens
// @param sessions - publishes session state to Redis
// @param otps - handles SMS login codes
// @returns the service
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

// Login checks a user's email and password.
//
// ENG: Refuses locked-out emails. When the email is unknown a dummy password check
// still runs so response time does not reveal which emails exist. Wrong passwords
// and disabled accounts count as failures. A user with a phone gets an OTP
// challenge instead of a token; the lockout is only reset after the code is
// verified. Otherwise the token is issued right away.
// LAO: ກວດ email/ລະຫັດຜ່ານ — ກວດການລັອກ, ປ້ອງກັນ timing attack, ມີເບີໂທຈະເລີ່ມ OTP, ບໍ່ມີຈະອອກ token.
//
// @param ctx - request context
// @param email - email as typed (normalized here)
// @param password - plain password
// @returns a token result, an OTP challenge result, or an Unauthorized/TooManyRequests error
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

// VerifyOTP finishes an SMS login and issues the token.
//
// ENG: Wrong codes count as login failures for the user's email. After a correct code
// it still checks the lockout, resets it, reloads the user and refuses accounts that
// were deleted or disabled in the meantime.
// LAO: ຢືນຢັນ OTP — ຜິດຈະນັບເປັນການເຂົ້າສູ່ລະບົບລົ້ມເຫຼວ, ຖືກຈະກວດຜູ້ໃຊ້ອີກຄັ້ງແລ້ວອອກ token.
//
// @param ctx - request context
// @param challengeID - ID returned by Login
// @param code - 6-digit code from the SMS
// @returns the login result with the token, or an Unauthorized/TooManyRequests error
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

// ResendOTP sends a new code for an open challenge.
//
// ENG: Maps OTP errors to client errors: gone (401), too soon (429) and too many sends (429).
// LAO: ສົ່ງ OTP ໃໝ່ ແລະ ແປງຂໍ້ຜິດພາດໃຫ້ເປັນ 401/429.
//
// @param ctx - request context
// @param challengeID - ID returned by Login
// @returns the updated challenge, or an error
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

// issue signs an access token and publishes the user's session.
//
// ENG: The session in Redis is what other services check, so it is written on every login.
// LAO: ອອກ token ແລະ ບັນທຶກ session ລົງ Redis ໃຫ້ service ອື່ນກວດໄດ້.
//
// @param ctx - request context
// @param user - user that logged in
// @returns the login result with the token and its expiry, or an error
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
//
// ENG: Bumps the user's token version in the database and publishes it, so tokens with
// the old version are rejected everywhere.
// LAO: ອອກຈາກລະບົບທຸກອຸປະກອນ — ເພີ່ມເວີຊັນ token ເພື່ອໃຫ້ token ເກົ່າໃຊ້ບໍ່ໄດ້.
//
// @param ctx - request context
// @param userID - user to log out
// @returns nil, or an error if the DB or Redis fails
func (s *AuthService) Logout(ctx context.Context, userID int64) error {
	user, err := s.store.BumpTokenVersion(ctx, userID)
	if err != nil {
		return err
	}
	return s.sessions.Put(ctx, user.ID, sessionOf(user))
}

// sessionOf builds the session state to publish for a user.
//
// ENG: Copies the token version, role and active flag.
// LAO: ສ້າງ session state (ເວີຊັນ token, role, active) ຈາກຂໍ້ມູນຜູ້ໃຊ້.
//
// @param u - user row
// @returns the session state
func sessionOf(u db.User) session.State {
	return session.State{TokenVersion: u.TokenVersion, Role: u.Role, Active: u.IsActive}
}
