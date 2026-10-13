package handler

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TonnPcst/martgo-auth/internal/db"
	"github.com/TonnPcst/martgo-auth/internal/domain"
	"github.com/TonnPcst/martgo-auth/internal/token"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

type fakeUsers map[int64]db.User

func (f fakeUsers) GetUserByID(_ context.Context, id int64) (db.User, error) {
	u, ok := f[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func newTestRouter(t *testing.T, users fakeUsers, pinger Pinger) (http.Handler, *token.Manager) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	tokens := token.NewManagerFromKey(priv, time.Hour)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewRouter(logger, tokens, users, pinger, Services{}, RouterOptions{}), tokens
}

func send(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mustToken(t *testing.T, tokens *token.Manager, userID int64, role string, version int32) string {
	t.Helper()
	signed, _, err := tokens.Generate(userID, role, version)
	require.NoError(t, err)
	return signed
}

func TestHealthz(t *testing.T) {
	h, _ := newTestRouter(t, nil, fakePinger{})
	assert.Equal(t, http.StatusOK, send(h, http.MethodGet, "/healthz", "").Code)

	h, _ = newTestRouter(t, nil, fakePinger{err: errors.New("db down")})
	assert.Equal(t, http.StatusServiceUnavailable, send(h, http.MethodGet, "/healthz", "").Code)
}

func TestAuthenticate(t *testing.T) {
	users := fakeUsers{
		1: {ID: 1, Role: domain.RoleCashier, IsActive: true, TokenVersion: 1},
		2: {ID: 2, Role: domain.RoleCashier, IsActive: false, TokenVersion: 1},
		3: {ID: 3, Role: domain.RoleCashier, IsActive: true, TokenVersion: 2},
	}
	h, tokens := newTestRouter(t, users, fakePinger{})

	_, otherKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	foreign := token.NewManagerFromKey(otherKey, time.Hour)

	tests := []struct {
		name  string
		token string
		want  int
	}{
		{"missing token", "", http.StatusUnauthorized},
		{"garbage token", "not-a-jwt", http.StatusUnauthorized},
		{"signed by another key", mustToken(t, foreign, 1, domain.RoleCashier, 1), http.StatusUnauthorized},
		{"disabled user", mustToken(t, tokens, 2, domain.RoleCashier, 1), http.StatusUnauthorized},
		{"deleted user", mustToken(t, tokens, 99, domain.RoleCashier, 1), http.StatusUnauthorized},
		{"revoked token", mustToken(t, tokens, 3, domain.RoleCashier, 1), http.StatusUnauthorized},
		// Passes authentication, then RequireRole rejects a cashier on /users.
		{"active cashier", mustToken(t, tokens, 1, domain.RoleCashier, 1), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, send(h, http.MethodGet, "/api/v1/users", tt.token).Code)
		})
	}
}

func TestRoleComesFromDatabase(t *testing.T) {
	// The token still says admin, but the user was demoted to cashier.
	users := fakeUsers{1: {ID: 1, Role: domain.RoleCashier, IsActive: true, TokenVersion: 1}}
	h, tokens := newTestRouter(t, users, fakePinger{})

	rec := send(h, http.MethodGet, "/api/v1/users", mustToken(t, tokens, 1, domain.RoleAdmin, 1))
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestLoginRateLimit(t *testing.T) {
	h, _ := newTestRouter(t, nil, fakePinger{})

	// An empty body fails validation (400) before reaching the auth service.
	for range 5 {
		assert.Equal(t, http.StatusBadRequest, send(h, http.MethodPost, "/api/v1/auth/login", "").Code)
	}
	rec := send(h, http.MethodPost, "/api/v1/auth/login", "")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
}

func TestDocs(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewRouter(logger, token.NewManagerFromKey(priv, time.Hour), fakeUsers{}, fakePinger{}, Services{}, RouterOptions{EnableDocs: true})

	assert.Equal(t, http.StatusOK, send(h, http.MethodGet, "/docs", "").Code)
	rec := send(h, http.MethodGet, "/docs/openapi.yaml", "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "/auth/login")

	h, _ = newTestRouter(t, nil, fakePinger{})
	assert.Equal(t, http.StatusNotFound, send(h, http.MethodGet, "/docs", "").Code)
}
