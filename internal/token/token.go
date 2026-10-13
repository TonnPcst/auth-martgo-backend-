package token

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Issuer must match what mart-api checks.
const Issuer = "martgo-auth"

// Claims is the contract with mart-api: keep the JSON tags identical on both sides.
type Claims struct {
	UserID       int64  `json:"uid"`
	Role         string `json:"role"`
	TokenVersion int32  `json:"ver"`
	jwt.RegisteredClaims
}

// Manager signs tokens with the Ed25519 private key and verifies them with its public half.
type Manager struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	ttl  time.Duration
}

func NewManager(privPEM []byte, ttl time.Duration) (*Manager, error) {
	key, err := jwt.ParseEdPrivateKeyFromPEM(privPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ed25519")
	}
	return NewManagerFromKey(priv, ttl), nil
}

func NewManagerFromKey(priv ed25519.PrivateKey, ttl time.Duration) *Manager {
	return &Manager{priv: priv, pub: priv.Public().(ed25519.PublicKey), ttl: ttl}
}

func (m *Manager) TTL() time.Duration { return m.ttl }

func (m *Manager) Generate(userID int64, role string, version int32) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(m.ttl)
	claims := Claims{
		UserID:       userID,
		Role:         role,
		TokenVersion: version,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(userID, 10),
			Issuer:    Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(m.priv)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

func (m *Manager) Parse(token string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims,
		func(t *jwt.Token) (any, error) { return m.pub, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

type claimsKey struct{}

func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, c)
}

func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*Claims)
	return c, ok
}
