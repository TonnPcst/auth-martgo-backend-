package service

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TonnPcst/martgo-auth/internal/db"
	"github.com/TonnPcst/martgo-auth/internal/oauth"
	"github.com/TonnPcst/martgo-auth/internal/otp"
	"github.com/TonnPcst/martgo-auth/internal/session"
	"github.com/TonnPcst/martgo-auth/internal/store"
	"github.com/TonnPcst/martgo-auth/internal/token"
)

type fakeStore struct {
	store.Store
	users      map[int64]db.User
	identities map[string]int64
	linkErr    error
}

func (f *fakeStore) GetUserByID(_ context.Context, id int64) (db.User, error) {
	u, ok := f.users[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (f *fakeStore) GetUserByEmail(_ context.Context, email string) (db.User, error) {
	for _, u := range f.users {
		if u.Email == email {
			return u, nil
		}
	}
	return db.User{}, pgx.ErrNoRows
}

func (f *fakeStore) GetUserByIdentity(ctx context.Context, arg db.GetUserByIdentityParams) (db.User, error) {
	id, ok := f.identities[arg.Subject]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return f.GetUserByID(ctx, id)
}

func (f *fakeStore) CreateUserIdentity(_ context.Context, arg db.CreateUserIdentityParams) error {
	if f.linkErr != nil {
		return f.linkErr
	}
	f.identities[arg.Subject] = arg.UserID
	return nil
}

type fakeSessions struct{}

func (fakeSessions) Put(context.Context, int64, session.State) error { return nil }

type fakeOTP struct{ started bool }

func (f *fakeOTP) Start(context.Context, otp.Subject, string) (otp.Challenge, error) {
	f.started = true
	return otp.Challenge{ID: "CH1"}, nil
}
func (f *fakeOTP) Resend(context.Context, string) (otp.Challenge, error) { return otp.Challenge{}, nil }
func (f *fakeOTP) Verify(context.Context, string, string) (otp.Subject, error) {
	return otp.Subject{}, nil
}

type fakeHandoff struct {
	userID    int64
	challenge string
}

// fakeHandoffs skips the SHA-256: the verifier must equal the challenge.
type fakeHandoffs map[string]fakeHandoff

func (f fakeHandoffs) Create(_ context.Context, userID int64, clientChallenge string) (string, error) {
	code := fmt.Sprintf("CODE%d", len(f)+1)
	f[code] = fakeHandoff{userID: userID, challenge: clientChallenge}
	return code, nil
}

func (f fakeHandoffs) Redeem(_ context.Context, code, verifier string) (int64, error) {
	h, ok := f[code]
	if !ok {
		return 0, oauth.ErrHandoffNotFound
	}
	delete(f, code)
	if verifier != h.challenge {
		return 0, oauth.ErrHandoffMismatch
	}
	return h.userID, nil
}

var (
	phone   = "2055551234"
	alice   = db.User{ID: 1, Email: "alice@martgo.local", Role: "cashier", IsActive: true, TokenVersion: 1}
	bob     = db.User{ID: 2, Email: "bob@martgo.local", Role: "cashier", IsActive: false, TokenVersion: 1}
	carol   = db.User{ID: 3, Email: "carol@martgo.local", Role: "manager", IsActive: true, TokenVersion: 1, Phone: &phone}
	googleA = oauth.Identity{Provider: oauth.ProviderGoogle, Subject: "sub-alice", Email: "Alice@MartGo.local", EmailVerified: true, ClientChallenge: "CHAL"}
)

type googleTest struct {
	svc      *AuthService
	store    *fakeStore
	otp      *fakeOTP
	handoffs fakeHandoffs
}

func newGoogleTest(t *testing.T) googleTest {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	st := &fakeStore{
		users:      map[int64]db.User{alice.ID: alice, bob.ID: bob, carol.ID: carol},
		identities: map[string]int64{},
	}
	otps := &fakeOTP{}
	handoffs := fakeHandoffs{}
	svc := NewAuthService(st, token.NewManagerFromKey(priv, time.Hour), fakeSessions{}, otps, handoffs)
	return googleTest{svc: svc, store: st, otp: otps, handoffs: handoffs}
}

func TestLoginWithIdentityLinksByVerifiedEmail(t *testing.T) {
	tt := newGoogleTest(t)

	code, err := tt.svc.LoginWithIdentity(context.Background(), googleA)
	require.NoError(t, err)
	assert.Equal(t, fakeHandoff{userID: alice.ID, challenge: "CHAL"}, tt.handoffs[code])
	assert.Equal(t, alice.ID, tt.store.identities["sub-alice"], "first login links the account")
}

func TestLoginWithIdentityUsesSubjectAfterLinking(t *testing.T) {
	tt := newGoogleTest(t)
	tt.store.identities["sub-alice"] = alice.ID

	moved := googleA
	moved.Email = "someone-else@gmail.com"
	code, err := tt.svc.LoginWithIdentity(context.Background(), moved)
	require.NoError(t, err)
	assert.Equal(t, alice.ID, tt.handoffs[code].userID)
}

func TestLoginWithIdentityRefusals(t *testing.T) {
	tests := []struct {
		name    string
		id      oauth.Identity
		linkErr error
	}{
		{"email not verified", oauth.Identity{Provider: "google", Subject: "s1", Email: alice.Email, EmailVerified: false}, nil},
		{"no user with that email", oauth.Identity{Provider: "google", Subject: "s2", Email: "stranger@gmail.com", EmailVerified: true}, nil},
		{"user disabled", oauth.Identity{Provider: "google", Subject: "s3", Email: bob.Email, EmailVerified: true}, nil},
		{"user linked to another Google account", googleA, &pgconn.PgError{Code: "23505", ConstraintName: "user_identities_user_provider_key"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tt := newGoogleTest(t)
			tt.store.linkErr = tc.linkErr

			_, err := tt.svc.LoginWithIdentity(context.Background(), tc.id)
			assert.ErrorIs(t, err, errIdentityNotAllowed)
			assert.Empty(t, tt.handoffs, "no handoff code may be created")
		})
	}
}

func TestExchangeHandoffIssuesToken(t *testing.T) {
	tt := newGoogleTest(t)
	code, err := tt.svc.LoginWithIdentity(context.Background(), googleA)
	require.NoError(t, err)

	res, err := tt.svc.ExchangeHandoff(context.Background(), code, "CHAL")
	require.NoError(t, err)
	assert.NotEmpty(t, res.Token)
	assert.Nil(t, res.Challenge)
	assert.Equal(t, alice.ID, res.User.ID)

	_, err = tt.svc.ExchangeHandoff(context.Background(), code, "CHAL")
	assert.ErrorIs(t, err, errHandoffInvalid, "a code works once")
}

func TestExchangeHandoffRefusesOtherBrowser(t *testing.T) {
	tt := newGoogleTest(t)
	code, err := tt.svc.LoginWithIdentity(context.Background(), googleA)
	require.NoError(t, err)

	_, err = tt.svc.ExchangeHandoff(context.Background(), code, "SOMEONE-ELSES-VERIFIER")
	assert.ErrorIs(t, err, errHandoffInvalid)
}

func TestExchangeHandoffStartsOTPForPhoneUsers(t *testing.T) {
	tt := newGoogleTest(t)
	tt.handoffs["C"] = fakeHandoff{userID: carol.ID, challenge: "CHAL"}

	res, err := tt.svc.ExchangeHandoff(context.Background(), "C", "CHAL")
	require.NoError(t, err)
	assert.Empty(t, res.Token, "no token before the SMS code")
	require.NotNil(t, res.Challenge)
	assert.True(t, tt.otp.started)
}

func TestExchangeHandoffRefusesUserDisabledMeanwhile(t *testing.T) {
	tt := newGoogleTest(t)
	code, err := tt.svc.LoginWithIdentity(context.Background(), googleA)
	require.NoError(t, err)

	disabled := alice
	disabled.IsActive = false
	tt.store.users[alice.ID] = disabled

	_, err = tt.svc.ExchangeHandoff(context.Background(), code, "CHAL")
	assert.ErrorIs(t, err, errIdentityNotAllowed)
}

func TestExchangeHandoffUnknownCode(t *testing.T) {
	tt := newGoogleTest(t)

	_, err := tt.svc.ExchangeHandoff(context.Background(), "NOPE", "CHAL")
	assert.ErrorIs(t, err, errHandoffInvalid)
}
