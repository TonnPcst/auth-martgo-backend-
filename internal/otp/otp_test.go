package otp

import (
	"context"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSender struct {
	mu    sync.Mutex
	phone string
	msg   string
}

func (f *fakeSender) Send(_ context.Context, phone, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.phone, f.msg = phone, msg
	return nil
}

var codeRe = regexp.MustCompile(`\d{6}`)

func (f *fakeSender) code() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return codeRe.FindString(f.msg)
}

func newTestManager(t *testing.T, cfg Config) (*Manager, *fakeSender) {
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
	s := &fakeSender{}
	return NewManager(rdb, s, cfg), s
}

var alice = Subject{UserID: 7, Email: "alice@martgo.local"}

func TestVerifyIsSingleUse(t *testing.T) {
	ctx := context.Background()
	m, s := newTestManager(t, DefaultConfig())

	ch, err := m.Start(ctx, alice, "2055551234")
	require.NoError(t, err)
	assert.Equal(t, "2055551234", s.phone)

	sub, err := m.Verify(ctx, ch.ID, s.code())
	require.NoError(t, err)
	assert.Equal(t, alice, sub)

	_, err = m.Verify(ctx, ch.ID, s.code())
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestVerifyDropsChallengeAfterMaxAttempts(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultConfig()
	cfg.MaxAttempts = 3
	m, s := newTestManager(t, cfg)

	ch, err := m.Start(ctx, alice, "2055551234")
	require.NoError(t, err)

	for range 2 {
		sub, err := m.Verify(ctx, ch.ID, "wrong")
		assert.ErrorIs(t, err, ErrInvalidCode)
		assert.Equal(t, alice, sub)
	}
	_, err = m.Verify(ctx, ch.ID, "wrong")
	assert.ErrorIs(t, err, ErrTooManyAttempts)

	_, err = m.Verify(ctx, ch.ID, s.code())
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestResend(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultConfig()
	cfg.ResendAfter = 0
	cfg.MaxSends = 2
	m, s := newTestManager(t, cfg)

	ch, err := m.Start(ctx, alice, "2055551234")
	require.NoError(t, err)
	oldCode := s.code()

	_, err = m.Resend(ctx, ch.ID)
	require.NoError(t, err)
	_, err = m.Resend(ctx, ch.ID)
	assert.ErrorIs(t, err, ErrTooManySends)

	if oldCode != s.code() {
		_, err = m.Verify(ctx, ch.ID, oldCode)
		assert.ErrorIs(t, err, ErrInvalidCode)
	}
	_, err = m.Verify(ctx, ch.ID, s.code())
	assert.NoError(t, err)
}

func TestResendTooSoon(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(t, DefaultConfig())

	ch, err := m.Start(ctx, alice, "2055551234")
	require.NoError(t, err)
	_, err = m.Resend(ctx, ch.ID)
	assert.ErrorIs(t, err, ErrResendTooSoon)

	_, err = m.Resend(ctx, "no-such-challenge")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestChallengeExpires(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultConfig()
	cfg.TTL = time.Second
	m, s := newTestManager(t, cfg)

	ch, err := m.Start(ctx, alice, "2055551234")
	require.NoError(t, err)
	time.Sleep(1100 * time.Millisecond)
	_, err = m.Verify(ctx, ch.ID, s.code())
	assert.ErrorIs(t, err, ErrNotFound)
}
