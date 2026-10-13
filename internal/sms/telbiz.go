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

func (e *TelbizError) Error() string {
	return fmt.Sprintf("telbiz: status %d, code %q: %s", e.HTTPStatus, e.Code, e.Message)
}

type telbizStatus struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

var errUnauthorized = errors.New("telbiz: unauthorized")

func (t *Telbiz) Send(ctx context.Context, phone, message string) error {
	body := map[string]string{"Phone": phone, "Title": telbizTitle, "Message": message}
	err := t.send(ctx, body)
	if errors.Is(err, errUnauthorized) {
		t.dropToken()
		err = t.send(ctx, body)
	}
	return err
}

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

func (t *Telbiz) dropToken() {
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
}

func tokenExpiry(tok string, now time.Time) time.Time {
	var claims jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tok, &claims); err == nil && claims.ExpiresAt != nil {
		return claims.ExpiresAt.Add(-time.Minute)
	}
	return now.Add(30 * time.Minute)
}

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
