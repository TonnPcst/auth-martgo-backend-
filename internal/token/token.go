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

// NewManager creates a token manager from a PEM-encoded Ed25519 private key.
//
// ENG: The public half is derived from the private key and used for verification.
// LAO: ສ້າງຕົວຈັດການ token ຈາກ private key (Ed25519).
//
// @param privPEM - contents of the private key PEM file
// @param ttl - lifetime of issued tokens
// @returns the manager, or an error if the key cannot be parsed or is not Ed25519
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

// NewManagerFromKey creates a token manager from an already parsed private key.
//
// ENG: Mainly used by tests that generate a key pair in memory.
// LAO: ສ້າງຕົວຈັດການ token ຈາກ private key ທີ່ parse ແລ້ວ (ໃຊ້ໃນ test).
//
// @param priv - Ed25519 private key
// @param ttl - lifetime of issued tokens
// @returns the manager
func NewManagerFromKey(priv ed25519.PrivateKey, ttl time.Duration) *Manager {
	return &Manager{priv: priv, pub: priv.Public().(ed25519.PublicKey), ttl: ttl}
}

// TTL returns the lifetime of issued tokens.
//
// ENG: Also used as the TTL of the Redis session entries.
// LAO: ສົ່ງຄືນອາຍຸຂອງ token.
//
// @returns the token TTL
func (m *Manager) TTL() time.Duration { return m.ttl }

// Generate signs a new access token for a user.
//
// ENG: The token holds the user ID, role and token version, plus subject, issuer
// "martgo-auth", issued-at and expiry. Signed with EdDSA.
// LAO: ສ້າງ ແລະ ເຊັນ access token ໃໝ່ສຳລັບຜູ້ໃຊ້ (EdDSA).
//
// @param userID - user ID
// @param role - user role
// @param version - current token version, used for revocation
// @returns the signed token and its expiry time, or an error
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

// Parse verifies a JWT and returns its claims.
//
// ENG: Only accepts EdDSA-signed tokens issued by "martgo-auth" that have an expiry
// and have not expired.
// LAO: ກວດສອບ JWT (ລາຍເຊັນ, ຜູ້ອອກ, ວັນໝົດອາຍຸ) ແລ້ວສົ່ງຄືນ claims.
//
// @param token - raw JWT string without the "Bearer " prefix
// @returns the claims, or an error if the token is invalid or expired
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

// WithClaims stores the token claims in the context.
//
// ENG: Called by the Authenticate middleware after the token is verified.
// LAO: ເກັບ claims ຂອງ token ໄວ້ໃນ context.
//
// @param ctx - parent context
// @param c - verified claims
// @returns a new context holding the claims
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, c)
}

// ClaimsFromContext reads the token claims stored by WithClaims.
//
// ENG: ok is false for requests that did not go through Authenticate.
// LAO: ດຶງ claims ຂອງ token ອອກຈາກ context.
//
// @param ctx - request context
// @returns the claims and true, or nil and false
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*Claims)
	return c, ok
}
