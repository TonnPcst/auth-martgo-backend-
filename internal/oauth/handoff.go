package oauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const handoffTTL = time.Minute

var ErrHandoffNotFound = errors.New("oauth: handoff code not found or expired")

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
// ENG: Format: "oauth:handoff:<code>". The value is the user ID.
// LAO: ສ້າງ key ຂອງ Redis ສຳລັບລະຫັດໃຊ້ຄັ້ງດຽວ.
//
// @param code - one-time code
// @returns the Redis key
func handoffKey(code string) string { return "oauth:handoff:" + code }

// Create stores a new one-time code for a user.
//
// ENG: The code is random (crypto/rand) and lives 1 minute.
// LAO: ສ້າງລະຫັດໃຊ້ຄັ້ງດຽວໃຫ້ຜູ້ໃຊ້ — ອາຍຸ 1 ນາທີ.
//
// @param ctx - request context
// @param userID - user who passed the Google login
// @returns the code, or an error if Redis fails
func (h *Handoffs) Create(ctx context.Context, userID int64) (string, error) {
	code := rand.Text()
	if err := h.rdb.Set(ctx, handoffKey(code), userID, handoffTTL).Err(); err != nil {
		return "", fmt.Errorf("store oauth handoff: %w", err)
	}
	return code, nil
}

// Redeem uses up a one-time code.
//
// ENG: GETDEL reads and deletes in one step, so a code works only once even when two
// requests race.
// LAO: ໃຊ້ລະຫັດ — ອ່ານແລ້ວລຶບທັນທີ (GETDEL) ຈຶ່ງໃຊ້ໄດ້ຄັ້ງດຽວ.
//
// @param ctx - request context
// @param code - code from the frontend
// @returns the user ID, ErrHandoffNotFound, or a Redis error
func (h *Handoffs) Redeem(ctx context.Context, code string) (int64, error) {
	userID, err := h.rdb.GetDel(ctx, handoffKey(code)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, ErrHandoffNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("redeem oauth handoff: %w", err)
	}
	return userID, nil
}
