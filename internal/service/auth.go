package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TonnPcst/martgo-auth/internal/apperr"
	"github.com/TonnPcst/martgo-auth/internal/db"
	"github.com/TonnPcst/martgo-auth/internal/oauth"
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

type HandoffStore interface {
	Create(ctx context.Context, userID int64, clientChallenge string) (string, error)
	Redeem(ctx context.Context, code string, verifier string) (int64, error)
}

type AuthService struct {
	store    store.Store
	tokens   *token.Manager
	sessions SessionWriter
	otp      OTPManager
	handoffs HandoffStore
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
// @param handoffs - one-time codes for the Google login redirect
// @returns the service
func NewAuthService(s store.Store, tokens *token.Manager, sessions SessionWriter, otps OTPManager, handoffs HandoffStore) *AuthService {
	return &AuthService{store: s, tokens: tokens, sessions: sessions, otp: otps, handoffs: handoffs, guard: newLoginGuard(5, 15*time.Minute)}
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
	errIdentityNotAllowed = apperr.Unauthorized("this Google account cannot sign in to MartGo")
	errHandoffInvalid     = apperr.Unauthorized("login link expired, please sign in again")
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

	if user.Phone == nil {
		s.guard.reset(key)
	}
	return s.complete(ctx, user)
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

// LoginWithIdentity starts a session for someone Google has vouched for.
//
// ENG: Only staff that an admin already created may log in; nobody is signed up
// automatically. The Google account is found by its stable subject. The first time,
// it is linked to the user with the same email, but only if Google says the email is
// verified. Disabled users are refused. Returns a one-time code for the frontend
// instead of a token.
// LAO: ເຂົ້າສູ່ລະບົບດ້ວຍບັນຊີ Google — ສະເພາະພະນັກງານທີ່ admin ສ້າງໄວ້, ຜູກບັນຊີຄັ້ງທຳອິດດ້ວຍ email ທີ່ຢືນຢັນແລ້ວ.
//
// @param ctx - request context
// @param id - identity verified by the oauth package
// @returns the one-time code, or an Unauthorized error
func (s *AuthService) LoginWithIdentity(ctx context.Context, id oauth.Identity) (string, error) {
	user, err := s.store.GetUserByIdentity(ctx, db.GetUserByIdentityParams{Provider: id.Provider, Subject: id.Subject})
	if store.IsNotFound(err) {
		user, err = s.linkIdentity(ctx, id)
	}
	if err != nil {
		return "", err
	}
	if !user.IsActive {
		return "", errIdentityNotAllowed
	}
	return s.handoffs.Create(ctx, user.ID, id.ClientChallenge)
}

// linkIdentity links a Google account to the existing user with the same email.
//
// ENG: Refused when the email is not verified by Google, when no user has that email,
// or when the user already has a different Google account linked (unique violation).
// LAO: ຜູກບັນຊີ Google ກັບຜູ້ໃຊ້ທີ່ມີ email ດຽວກັນ — ຕ້ອງເປັນ email ທີ່ Google ຢືນຢັນແລ້ວ.
//
// @param ctx - request context
// @param id - identity verified by the oauth package
// @returns the linked user, or an Unauthorized error
func (s *AuthService) linkIdentity(ctx context.Context, id oauth.Identity) (db.User, error) {
	if !id.EmailVerified {
		return db.User{}, errIdentityNotAllowed
	}
	user, err := s.store.GetUserByEmail(ctx, normalizeEmail(id.Email))
	if store.IsNotFound(err) {
		return db.User{}, errIdentityNotAllowed
	}
	if err != nil {
		return db.User{}, err
	}
	err = s.store.CreateUserIdentity(ctx, db.CreateUserIdentityParams{Provider: id.Provider, Subject: id.Subject, UserID: user.ID})
	if store.IsUniqueViolation(err) {
		return db.User{}, errIdentityNotAllowed
	}
	if err != nil {
		return db.User{}, err
	}
	return user, nil
}

// ExchangeHandoff turns the one-time code from LoginWithIdentity into a login.
//
// ENG: Reloads the user, because they may have been disabled since the redirect, then
// finishes exactly like a password login: an SMS challenge for users with a phone,
// otherwise the token.
// LAO: ແລກລະຫັດໃຊ້ຄັ້ງດຽວເປັນການເຂົ້າສູ່ລະບົບ — ມີເບີໂທຈະສົ່ງ OTP, ບໍ່ມີຈະອອກ token.
//
// @param ctx - request context
// @param code - one-time code from the frontend
// @returns the login result, or an Unauthorized error
func (s *AuthService) ExchangeHandoff(ctx context.Context, code string, verifier string) (LoginResult, error) {
	userID, err := s.handoffs.Redeem(ctx, code, verifier)
	if errors.Is(err, oauth.ErrHandoffNotFound) || errors.Is(err, oauth.ErrHandoffMismatch) {
		return LoginResult{}, errHandoffInvalid
	}
	if err != nil {
		return LoginResult{}, err
	}
	user, err := s.store.GetUserByID(ctx, userID)
	if store.IsNotFound(err) || (err == nil && !user.IsActive) {
		return LoginResult{}, errIdentityNotAllowed
	}
	if err != nil {
		return LoginResult{}, err
	}
	return s.complete(ctx, user)
}

// complete finishes a login once the first factor (password or Google) has passed.
//
// ENG: A user with a phone gets an SMS challenge; anyone else gets the token right away.
// LAO: ຈົບການເຂົ້າສູ່ລະບົບ — ມີເບີໂທຈະເລີ່ມ OTP, ບໍ່ມີຈະອອກ token.
//
// @param ctx - request context
// @param user - user who passed the first factor
// @returns a token result or an OTP challenge result, or an error
func (s *AuthService) complete(ctx context.Context, user db.User) (LoginResult, error) {
	if user.Phone != nil {
		ch, err := s.otp.Start(ctx, otp.Subject{UserID: user.ID, Email: user.Email}, *user.Phone)
		if err != nil {
			return LoginResult{}, err
		}
		return LoginResult{User: user, Challenge: &ch}, nil
	}
	return s.issue(ctx, user)
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
