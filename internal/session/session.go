// Package session publishes each user's current token state to Redis so that
// other services can check revocation without calling the auth service.
package session

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type State struct {
	TokenVersion int32
	Role         string
	Active       bool
}

// Key returns the Redis key holding a user's session state.
//
// ENG: This is the contract with mart-api: keep it and the field names identical on both sides.
// LAO: ສ້າງ key ຂອງ Redis ສຳລັບ session — ຕ້ອງກົງກັບ mart-api.
//
// @param userID - user ID
// @returns the key, e.g. "session:user:42"
func Key(userID int64) string { return "session:user:" + strconv.FormatInt(userID, 10) }

type Writer struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewWriter creates a session writer on top of a Redis client.
//
// ENG: ttl should equal the JWT TTL: once the newest token has expired the entry is useless.
// LAO: ສ້າງຕົວຂຽນ session ລົງ Redis — TTL ຄວນເທົ່າກັບອາຍຸຂອງ JWT.
//
// @param rdb - Redis client
// @param ttl - how long each entry lives
// @returns the writer
func NewWriter(rdb *redis.Client, ttl time.Duration) *Writer {
	return &Writer{rdb: rdb, ttl: ttl}
}

// Put publishes a user's current token state to Redis.
//
// ENG: Writes the "ver", "role" and "active" fields and resets the TTL in one transaction.
// LAO: ບັນທຶກສະຖານະ session (ເວີຊັນ token, role, active) ລົງ Redis.
//
// @param ctx - request context
// @param userID - user ID
// @param s - state to publish
// @returns error if Redis fails
func (w *Writer) Put(ctx context.Context, userID int64, s State) error {
	k := Key(userID)
	_, err := w.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, k, "ver", s.TokenVersion, "role", s.Role, "active", s.Active)
		p.Expire(ctx, k, w.ttl)
		return nil
	})
	return err
}
