package handler

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TonnPcst/martgo-auth/internal/db"
	"github.com/TonnPcst/martgo-auth/internal/oauth"
	"github.com/TonnPcst/martgo-auth/internal/otp"
	"github.com/TonnPcst/martgo-auth/internal/service"
	"github.com/TonnPcst/martgo-auth/internal/token"
)

const (
	testFrontend  = "http://frontend.test/done"
	testChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

type fakeGoogle struct {
	finishErr error
}

func (f *fakeGoogle) Start(context.Context, string) (string, string, error) {
	return "STATE123", "https://accounts.google.com/o/oauth2/auth?state=STATE123", nil
}

func (f *fakeGoogle) Finish(context.Context, string, string) (oauth.Identity, error) {
	return oauth.Identity{}, f.finishErr
}

func newGoogleRouter(t *testing.T, g GoogleLogin) http.Handler {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewRouter(logger, token.NewManagerFromKey(priv, time.Hour), fakeUsers{}, nil,
		Services{Google: g}, RouterOptions{OAuthFrontendURL: testFrontend})
}

func callback(h http.Handler, query, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/callback?"+query, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: stateCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func redirectError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, testFrontend, loc.Scheme+"://"+loc.Host+loc.Path)
	return loc.Query().Get("error")
}

func TestGoogleRoutesOffWithoutConfig(t *testing.T) {
	h, _ := newTestRouter(t, nil, fakePinger{})
	assert.Equal(t, http.StatusNotFound, send(h, http.MethodGet, "/api/v1/auth/google/login", "").Code)
}

func TestGoogleLoginSetsStateCookie(t *testing.T) {
	h := newGoogleRouter(t, &fakeGoogle{})

	rec := send(h, http.MethodGet, "/api/v1/auth/google/login?code_challenge="+testChallenge, "")
	require.Equal(t, http.StatusFound, rec.Code)
	assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), "https://accounts.google.com/"))

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, stateCookie, c.Name)
	assert.Equal(t, "STATE123", c.Value)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.Equal(t, stateCookiePath, c.Path)
}

func TestGoogleLoginNeedsCodeChallenge(t *testing.T) {
	h := newGoogleRouter(t, &fakeGoogle{})

	for _, q := range []string{"", "?code_challenge=short", "?code_challenge=" + testChallenge[:42] + "="} {
		rec := send(h, http.MethodGet, "/api/v1/auth/google/login"+q, "")
		assert.Equal(t, http.StatusBadRequest, rec.Code, "query %q", q)
		assert.Empty(t, rec.Result().Cookies(), "no state cookie without a challenge")
	}
}

func TestGoogleCallbackErrors(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		cookie    string
		finishErr error
		want      string
	}{
		{"user cancelled at Google", "error=access_denied", "", nil, "access_denied"},
		{"no state cookie", "state=STATE123&code=c", "", nil, "invalid_state"},
		{"cookie does not match", "state=STATE123&code=c", "OTHER", nil, "invalid_state"},
		{"no state in URL", "code=c", "STATE123", nil, "invalid_state"},
		{"state unknown to Redis", "state=STATE123&code=c", "STATE123", oauth.ErrInvalidState, "invalid_state"},
		{"outside allowed domain", "state=STATE123&code=c", "STATE123", oauth.ErrWrongDomain, "not_allowed"},
		{"google exchange fails", "state=STATE123&code=c", "STATE123", errors.New("invalid_grant"), "failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newGoogleRouter(t, &fakeGoogle{finishErr: tt.finishErr})
			assert.Equal(t, tt.want, redirectError(t, callback(h, tt.query, tt.cookie)))
		})
	}
}

func TestGoogleCallbackClearsCookie(t *testing.T) {
	h := newGoogleRouter(t, &fakeGoogle{})

	rec := callback(h, "error=access_denied", "STATE123")
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, stateCookie, cookies[0].Name)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

func TestGoogleExchangeValidation(t *testing.T) {
	h := newGoogleRouter(t, &fakeGoogle{})

	verifier := strings.Repeat("v", 43)
	for _, body := range []string{
		``,
		`{}`,
		`{"code":"x"}`,
		`{"code":"x","code_verifier":"too-short"}`,
		`{"code":"` + strings.Repeat("A", 65) + `","code_verifier":"` + verifier + `"}`,
		`{"code":"x","code_verifier":"` + verifier + `","extra":1}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/google/exchange", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "body %q", body)
	}
}

func TestWriteLoginResult(t *testing.T) {
	phone := "2055551234"

	rec := httptest.NewRecorder()
	writeLoginResult(rec, service.LoginResult{Token: "jwt-token", ExpiresAt: time.Now().Add(time.Hour)})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"access_token":"jwt-token"`)

	rec = httptest.NewRecorder()
	writeLoginResult(rec, service.LoginResult{User: db.User{Phone: &phone}, Challenge: &otp.Challenge{ID: "CH1"}})
	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Contains(t, rec.Body.String(), `"challenge_id":"CH1"`)
	assert.Contains(t, rec.Body.String(), `"phone_hint":"******1234"`)
	assert.NotContains(t, rec.Body.String(), "access_token")
}
