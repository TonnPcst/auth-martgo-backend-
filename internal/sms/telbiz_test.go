package sms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTelbiz issues tok-1, tok-2, ... and rejects SMS sent with a token in reject.
func fakeTelbiz(t *testing.T, tokenCalls, smsCalls *atomic.Int32, reject string, smsStatus int, smsBody string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/api/v1/connect/token":
			n := tokenCalls.Add(1)
			assert.Equal(t, "id", body["ClientID"])
			assert.Equal(t, "secret", body["Secret"])
			assert.Equal(t, "client_credentials", body["GrantType"])
			fmt.Fprintf(w, `{"success":true,"code":"SUCCESS","accessToken":"tok-%d"}`, n)
		case "/api/v1/smsservice/newtransaction":
			smsCalls.Add(1)
			if r.Header.Get("Authorization") == "Bearer "+reject {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "2055551234", body["Phone"])
			assert.Equal(t, "OTP", body["Title"])
			assert.Equal(t, "hello", body["Message"])
			w.WriteHeader(smsStatus)
			fmt.Fprint(w, smsBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const okBody = `{"response":{"success":true,"code":"SUCCESS"},"key":{"rangeKey":"abc"}}`

func TestTelbizReusesToken(t *testing.T) {
	var tokenCalls, smsCalls atomic.Int32
	srv := fakeTelbiz(t, &tokenCalls, &smsCalls, "", http.StatusOK, okBody)
	c := NewTelbiz(srv.URL, "id", "secret")

	require.NoError(t, c.Send(context.Background(), "2055551234", "hello"))
	require.NoError(t, c.Send(context.Background(), "2055551234", "hello"))
	assert.Equal(t, int32(1), tokenCalls.Load())
	assert.Equal(t, int32(2), smsCalls.Load())
}

func TestTelbizRefreshesTokenOn401(t *testing.T) {
	var tokenCalls, smsCalls atomic.Int32
	srv := fakeTelbiz(t, &tokenCalls, &smsCalls, "tok-1", http.StatusOK, okBody)
	c := NewTelbiz(srv.URL, "id", "secret")

	require.NoError(t, c.Send(context.Background(), "2055551234", "hello"))
	assert.Equal(t, int32(2), tokenCalls.Load())
	assert.Equal(t, int32(2), smsCalls.Load())
}

func TestTelbizError(t *testing.T) {
	var tokenCalls, smsCalls atomic.Int32
	srv := fakeTelbiz(t, &tokenCalls, &smsCalls, "", http.StatusBadRequest,
		`{"success":false,"code":"CREDIT_NOT_SUFFICIENT","message":"not enough credit"}`)
	c := NewTelbiz(srv.URL, "id", "secret")

	err := c.Send(context.Background(), "2055551234", "hello")
	var te *TelbizError
	require.True(t, errors.As(err, &te), "got %v", err)
	assert.Equal(t, "CREDIT_NOT_SUFFICIENT", te.Code)
	assert.Equal(t, http.StatusBadRequest, te.HTTPStatus)
}
