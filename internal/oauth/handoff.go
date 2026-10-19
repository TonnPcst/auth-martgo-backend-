package oauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

const handoffTTL = time.Minute

var (
	ErrHandoffNotFound = errors.New("oauth: handoff code not found or expired")
	ErrHandoffMismatch = errors.New("oauth: code_verifier does not match the handoff code")
)

type Handoffs struct {
	rdb *redis.Client
}

// NewHandoffs creates the store of one-time login codes.
//
// ENG: After Google login the browser is redirected to the frontend with a short-lived
// code instead of the access token, so the token never appears in a URL, browser
// history or server logs.
// LAO: ສ້າງບ່ອນເກັບລະຫັດໃຊ້ຄັ້ງດຽວ — ສົ່ງລະຫັດໃຫ້ frontend ແທນ token ເພື່ອບໍ່ໃຫ້ token ຢູ່ໃນ URL.
//
// @param rdb - Redis client
// @returns the store
func NewHandoffs(rdb *redis.Client) *Handoffs { return &Handoffs{rdb: rdb} }

// handoffKey returns the Redis key of a one-time login code.
//
// ENGENG: Format: "oauth:handoff:<code>". The value is "<user ID>:<client challenge>".
// LAO: ສ້າງ key ຂອງ Redis ສຳລັບລະຫັດໃຊ້ຄັ້ງດຽວ.
//
// @param code - one-time code
// @returns the Redis key
func handoffKey(code string) string { return "oauth:handoff:" + code }

// Create stores a new one-time code for a user.
//
// ENG: The code is random (crypto/rand) and lives 1 minute. It is bound to the
// frontend's code_challenge: only the browser that started the login holds the
// matching code_verifier, so a code sent to someone else is useless.
// LAO: ສ້າງລະຫັດໃຊ້ຄັ້ງດຽວໃຫ້ຜູ້ໃຊ້ — ອາຍຸ 1 ນາທີ, ຜູກກັບ code_challenge ຂອງ frontend.
//
// @param ctx - request context
// @param userID - user who passed the Google login
// @param clientChallenge - code_challenge the frontend sent when the login started
// @returns the code, or an error if Redis fails
func (h *Handoffs) Create(ctx context.Context, userID int64, clientChallenge string) (string, error) {
	code := rand.Text()
	value := strconv.FormatInt(userID, 10) + ":" + clientChallenge
	if err := h.rdb.Set(ctx, handoffKey(code), value, handoffTTL).Err(); err != nil {
		return "", fmt.Errorf("store oauth handoff: %w", err)
	}
	return code, nil
}

// Redeem uses up a one-time code.
//
// ENG: GETDEL reads and deletes in one step, so a code works only once even when two
// requests race. The SHA-256 of the verifier must equal the stored challenge; a wrong
// verifier still uses up the code, so it cannot be guessed.
// LAO: ໃຊ້ລະຫັດ — ອ່ານແລ້ວລຶບທັນທີ (GETDEL) ແລະ ກວດ code_verifier ກັບ challenge.
//
// @param ctx - request context
// @param code - code from the frontend
// @param verifier - code_verifier the frontend kept since the login started
// @returns the user ID, ErrHandoffNotFound, ErrHandoffMismatch, or a Redis error
func (h *Handoffs) Redeem(ctx context.Context, code string, verifier string) (int64, error) {
	saved, err := h.rdb.GetDel(ctx, handoffKey(code)).Result()
	if errors.Is(err, redis.Nil) {
		return 0, ErrHandoffNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("redeem oauth handoff: %w", err)
	}
	id, challenge, _ := strings.Cut(saved, ":")
	want := oauth2.S256ChallengeFromVerifier(verifier)
	if subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) != 1 {
		return 0, ErrHandoffMismatch
	}
	return strconv.ParseInt(id, 10, 64)
}
