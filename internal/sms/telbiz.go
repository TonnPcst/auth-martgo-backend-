package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const DefaultTelbizURL = "https://api.telbiz.la"

const telbizTitle = "OTP"

type Telbiz struct {
	baseURL  string
	clientID string
	secret   string
	hc       *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewTelbiz creates a Telbiz SMS client.
//
// ENG: Requests time out after 10 seconds. The access token is fetched on first use.
// LAO: ສ້າງ client ສຳລັບສົ່ງ SMS ຜ່ານ Telbiz.
//
// @param baseURL - API base URL, e.g. https://api.telbiz.la
// @param clientID - Telbiz client ID
// @param secret - Telbiz client secret
// @returns the client
func NewTelbiz(baseURL, clientID, secret string) *Telbiz {
	return &Telbiz{
		baseURL:  strings.TrimRight(baseURL, "/"),
		clientID: clientID,
		secret:   secret,
		hc:       &http.Client{Timeout: 10 * time.Second},
	}
}

type TelbizError struct {
	HTTPStatus int
	Code       string
	Message    string
}

// Error implements the error interface.
//
// ENG: Includes the HTTP status, the Telbiz error code and its message.
// LAO: ສົ່ງຄືນຂໍ້ຄວາມຂໍ້ຜິດພາດຈາກ Telbiz.
//
// @returns the error message
func (e *TelbizError) Error() string {
	return fmt.Sprintf("telbiz: status %d, code %q: %s", e.HTTPStatus, e.Code, e.Message)
}

type telbizStatus struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

var errUnauthorized = errors.New("telbiz: unauthorized")

// Send sends an SMS through Telbiz.
//
// ENG: If Telbiz rejects the cached access token, it is dropped and the send is
// retried once with a fresh token.
// LAO: ສົ່ງ SMS ຜ່ານ Telbiz — ຖ້າ token ໃຊ້ບໍ່ໄດ້ ຈະຂໍ token ໃໝ່ແລ້ວລອງອີກຄັ້ງ.
//
// @param ctx - request context
// @param phone - destination phone number
// @param message - SMS text
// @returns nil, or a *TelbizError / network error
func (t *Telbiz) Send(ctx context.Context, phone, message string) error {
	body := map[string]string{"Phone": phone, "Title": telbizTitle, "Message": message}
	err := t.send(ctx, body)
	if errors.Is(err, errUnauthorized) {
		t.dropToken()
		err = t.send(ctx, body)
	}
	return err
}

// send makes one SMS request with the current access token.
//
// ENG: Telbiz may answer 200 with success=false, which is also treated as an error.
// LAO: ສົ່ງ SMS 1 ຄັ້ງດ້ວຍ token ປັດຈຸບັນ.
//
// @param ctx - request context
// @param body - SMS request payload
// @returns nil, errUnauthorized, or another error
func (t *Telbiz) send(ctx context.Context, body any) error {
	tok, err := t.accessToken(ctx)
	if err != nil {
		return err
	}
	var out struct {
		Response telbizStatus `json:"response"`
	}
	if err := t.post(ctx, "/api/v1/smsservice/newtransaction", tok, body, &out); err != nil {
		return err
	}
	if !out.Response.Success {
		return &TelbizError{Code: out.Response.Code, Message: out.Response.Message}
	}
	return nil
}

// accessToken returns a cached access token or fetches a new one.
//
// ENG: Uses the client-credentials grant. The token is reused until shortly before
// its expiry. The mutex keeps concurrent sends from fetching several tokens at once.
// LAO: ດຶງ access token ຈາກ cache ຫຼື ຂໍໃໝ່ຈາກ Telbiz.
//
// @param ctx - request context
// @returns the token, or an error if Telbiz refuses the credentials
func (t *Telbiz) accessToken(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && time.Now().Before(t.expiresAt) {
		return t.token, nil
	}

	req := map[string]string{"ClientID": t.clientID, "Secret": t.secret, "GrantType": "client_credentials"}
	var out struct {
		telbizStatus
		AccessToken string `json:"accessToken"`
	}
	if err := t.post(ctx, "/api/v1/connect/token", "", req, &out); err != nil {
		return "", fmt.Errorf("telbiz token: %w", err)
	}
	if !out.Success || out.AccessToken == "" {
		return "", fmt.Errorf("telbiz token: %w", &TelbizError{Code: out.Code, Message: out.Message})
	}
	t.token = out.AccessToken
	t.expiresAt = tokenExpiry(out.AccessToken, time.Now())
	return t.token, nil
}

// dropToken forgets the cached access token.
//
// ENG: Called after a 401 so the next send fetches a new one.
// LAO: ລຶບ token ທີ່ cache ໄວ້ ເພື່ອໃຫ້ຂໍໃໝ່.
func (t *Telbiz) dropToken() {
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
}

// tokenExpiry works out when to stop reusing a Telbiz token.
//
// ENG: Reads the exp claim without verifying the signature (Telbiz checks it, not us)
// and subtracts 1 minute as a safety margin. Falls back to 30 minutes when the token
// has no readable expiry.
// LAO: ຄິດໄລ່ເວລາໝົດອາຍຸຂອງ token Telbiz (ລົບ 1 ນາທີເພື່ອຄວາມປອດໄພ).
//
// @param tok - access token (a JWT)
// @param now - current time
// @returns the time after which the token should be refreshed
func tokenExpiry(tok string, now time.Time) time.Time {
	var claims jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tok, &claims); err == nil && claims.ExpiresAt != nil {
		return claims.ExpiresAt.Add(-time.Minute)
	}
	return now.Add(30 * time.Minute)
}

// post sends a JSON POST request to Telbiz and decodes the response.
//
// ENG: Reads at most 1 MB of the response. A 401 on an authenticated call returns
// errUnauthorized so the caller can refresh the token. Any status of 300 or above
// becomes a *TelbizError.
// LAO: ສົ່ງ POST JSON ໄປ Telbiz ແລະ ອ່ານຜົນຕອບກັບ.
//
// @param ctx - request context
// @param path - API path, e.g. /api/v1/connect/token
// @param bearer - access token, or "" for the token request itself
// @param in - request payload
// @param out - pointer to decode the response into
// @returns nil, errUnauthorized, a *TelbizError or a network/decoding error
func (t *Telbiz) post(ctx context.Context, path, bearer string, in, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := t.hc.Do(req)
	if err != nil {
		return fmt.Errorf("telbiz: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("telbiz: read body: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized && bearer != "" {
		return errUnauthorized
	}
	if resp.StatusCode >= 300 {
		var st telbizStatus
		_ = json.Unmarshal(data, &st)
		return &TelbizError{HTTPStatus: resp.StatusCode, Code: st.Code, Message: st.Message}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("telbiz: decode response: %w", err)
	}
	return nil
}
