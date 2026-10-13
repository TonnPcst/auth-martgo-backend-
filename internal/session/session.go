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

// Key is the contract with mart-api: keep it and the field names identical on both sides.
func Key(userID int64) string { return "session:user:" + strconv.FormatInt(userID, 10) }

type Writer struct {
	rdb *redis.Client
	ttl time.Duration
}

// ttl should equal the JWT TTL: once the newest token has expired the entry is useless.
func NewWriter(rdb *redis.Client, ttl time.Duration) *Writer {
	return &Writer{rdb: rdb, ttl: ttl}
}

func (w *Writer) Put(ctx context.Context, userID int64, s State) error {
	k := Key(userID)
	_, err := w.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, k, "ver", s.TokenVersion, "role", s.Role, "active", s.Active)
		p.Expire(ctx, k, w.ttl)
		return nil
	})
	return err
}
