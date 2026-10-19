package oauth

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

var testChallenge = oauth2.S256ChallengeFromVerifier(testVerifier)

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		url = "redis://localhost:6380/15"
	}
	opt, err := redis.ParseURL(url)
	require.NoError(t, err)
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { rdb.Close() })
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis not available at %s: %v", url, err)
	}
	return rdb
}

func TestHandoffIsSingleUse(t *testing.T) {
	ctx := context.Background()
	h := NewHandoffs(newTestRedis(t))

	code, err := h.Create(ctx, 42, testChallenge)
	require.NoError(t, err)

	userID, err := h.Redeem(ctx, code, testVerifier)
	require.NoError(t, err)
	assert.Equal(t, int64(42), userID)

	_, err = h.Redeem(ctx, code, testVerifier)
	assert.ErrorIs(t, err, ErrHandoffNotFound)
}

func TestHandoffUnknownCode(t *testing.T) {
	h := NewHandoffs(newTestRedis(t))

	_, err := h.Redeem(context.Background(), "NOT-A-CODE", testVerifier)
	assert.ErrorIs(t, err, ErrHandoffNotFound)
}

func TestHandoffExpires(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)
	h := NewHandoffs(rdb)

	code, err := h.Create(ctx, 42, testChallenge)
	require.NoError(t, err)
	ttl := rdb.TTL(ctx, handoffKey(code)).Val()
	assert.True(t, ttl > 0 && ttl <= handoffTTL, "ttl = %s", ttl)

	require.NoError(t, rdb.PExpire(ctx, handoffKey(code), 50*time.Millisecond).Err())
	time.Sleep(100 * time.Millisecond)
	_, err = h.Redeem(ctx, code, testVerifier)
	assert.ErrorIs(t, err, ErrHandoffNotFound)
}

func TestHandoffNeedsMatchingVerifier(t *testing.T) {
	ctx := context.Background()
	h := NewHandoffs(newTestRedis(t))

	code, err := h.Create(ctx, 42, testChallenge)
	require.NoError(t, err)

	_, err = h.Redeem(ctx, code, "another-verifier-another-verifier-another-ver")
	assert.ErrorIs(t, err, ErrHandoffMismatch)

	_, err = h.Redeem(ctx, code, testVerifier)
	assert.ErrorIs(t, err, ErrHandoffNotFound)
}
