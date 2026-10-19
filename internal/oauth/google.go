package oauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	ProviderGoogle = "google"
	googleIssuer   = "https://accounts.google.com"
	stateTTL       = 10 * time.Minute
)

var (
	ErrInvalidState = errors.New("oauth: unknown or expired state")
	ErrWrongDomain  = errors.New("oauth: account is not in the allowed domain")
)

type Identity struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
}

type GoogleConfig struct {
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	AllowedDomain string
}

type Google struct {
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	rdb      *redis.Client
	domain   string
}

// NewGoogle creates the Google login client.
//
// ENG: Downloads Google's OpenID configuration (signing keys, endpoints) once, so it
// needs network access at startup. Asks for the "openid email profile" scopes.
// LAO: ສ້າງ client ສຳລັບ login ດ້ວຍ Google — ດາວໂຫຼດການຕັ້ງຄ່າ OpenID ຂອງ Google ຕອນເລີ່ມ.
//
// @param ctx - startup context (limits the discovery request)
// @param rdb - Redis client that holds the state of logins in progress
// @param cfg - client ID/secret, redirect URL and optional Workspace domain
// @returns the client, or an error if discovery fails
func NewGoogle(ctx context.Context, rdb *redis.Client, cfg GoogleConfig) (*Google, error) {
	provider, err := oidc.NewProvider(ctx, googleIssuer)
	if err != nil {
		return nil, fmt.Errorf("google openid discovery: %w", err)
	}
	return &Google{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     google.Endpoint,
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		rdb:      rdb,
		domain:   strings.ToLower(cfg.AllowedDomain),
	}, nil
}

// stateKey returns the Redis key of a login in progress.
//
// ENG: Format: "oauth:state:<state>". The value is "<pkce verifier>:<nonce>".
// LAO: ສ້າງ key ຂອງ Redis ສຳລັບ login ທີ່ກຳລັງດຳເນີນຢູ່.
//
// @param state - random state sent to Google
// @returns the Redis key
func stateKey(state string) string { return "oauth:state:" + state }

// Start begins a Google login.
//
// ENG: Creates three random values and keeps the last two in Redis for 10 minutes:
// state (sent back by Google, proves the callback belongs to a login we started),
// the PKCE verifier (only its hash goes to Google, so a stolen code is useless) and
// the nonce (copied by Google into the ID token, so an old token cannot be replayed).
// LAO: ເລີ່ມ login ດ້ວຍ Google — ສ້າງ state, PKCE verifier ແລະ nonce ເກັບໄວ້ໃນ Redis 10 ນາທີ.
//
// @param ctx - request context
// @returns the state (the caller also puts it in a cookie) and the Google URL to redirect to
func (g *Google) Start(ctx context.Context) (state, authURL string, err error) {
	state = rand.Text()
	verifier := oauth2.GenerateVerifier()
	nonce := rand.Text()
	if err := g.rdb.Set(ctx, stateKey(state), verifier+":"+nonce, stateTTL).Err(); err != nil {
		return "", "", fmt.Errorf("store oauth state: %w", err)
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)}
	if g.domain != "" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", g.domain))
	}
	return state, g.oauth.AuthCodeURL(state, opts...), nil
}

type googleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	HostedDomain  string `json:"hd"`
}

// Finish completes a Google login from the callback.
//
// ENG: Takes the state out of Redis (GETDEL, so it works once), exchanges the code for
// tokens together with the PKCE verifier, then verifies the ID token: Google's
// signature, issuer, audience (our client ID), expiry and our nonce. When an allowed
// domain is set, the account must belong to that Google Workspace domain.
// LAO: ຈົບການ login ດ້ວຍ Google — ກວດ state, ແລກ code ເປັນ token, ກວດ ID token ແລະ nonce.
//
// @param ctx - request context
// @param state - state from the callback URL
// @param code - authorization code from the callback URL
// @returns the verified identity, or ErrInvalidState, ErrWrongDomain or an exchange/verify error
func (g *Google) Finish(ctx context.Context, state, code string) (Identity, error) {
	saved, err := g.rdb.GetDel(ctx, stateKey(state)).Result()
	if errors.Is(err, redis.Nil) {
		return Identity{}, ErrInvalidState
	}
	if err != nil {
		return Identity{}, fmt.Errorf("load oauth state: %w", err)
	}
	verifier, nonce, _ := strings.Cut(saved, ":")

	tok, err := g.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchange google code: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return Identity{}, errors.New("google response has no id_token")
	}
	idToken, err := g.verifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, fmt.Errorf("verify google id_token: %w", err)
	}
	if idToken.Nonce != nonce {
		return Identity{}, errors.New("google id_token nonce mismatch")
	}

	var c googleClaims
	if err := idToken.Claims(&c); err != nil {
		return Identity{}, fmt.Errorf("read google claims: %w", err)
	}
	if g.domain != "" && strings.ToLower(c.HostedDomain) != g.domain {
		return Identity{}, ErrWrongDomain
	}
	return Identity{Provider: ProviderGoogle, Subject: idToken.Subject, Email: c.Email, EmailVerified: c.EmailVerified}, nil
}
