package otp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrNotFound        = errors.New("otp: challenge not found or expired")
	ErrInvalidCode     = errors.New("otp: invalid code")
	ErrTooManyAttempts = errors.New("otp: too many wrong codes")
	ErrResendTooSoon   = errors.New("otp: resend requested too soon")
	ErrTooManySends    = errors.New("otp: resend limit reached")
)

type Sender interface {
	Send(ctx context.Context, phone, message string) error
}

type Config struct {
	TTL         time.Duration
	MaxAttempts int
	ResendAfter time.Duration
	MaxSends    int
}

func DefaultConfig() Config {
	return Config{TTL: 5 * time.Minute, MaxAttempts: 5, ResendAfter: time.Minute, MaxSends: 3}
}

type Challenge struct {
	ID        string
	ExpiresAt time.Time
	ResendAt  time.Time
}

type Subject struct {
	UserID int64
	Email  string
}

type Manager struct {
	rdb    *redis.Client
	sender Sender
	cfg    Config
}

func NewManager(rdb *redis.Client, sender Sender, cfg Config) *Manager {
	return &Manager{rdb: rdb, sender: sender, cfg: cfg}
}

func key(id string) string { return "otp:login:" + id }

func (m *Manager) Start(ctx context.Context, sub Subject, phone string) (Challenge, error) {
	id := rand.Text()
	code, err := newCode()
	if err != nil {
		return Challenge{}, err
	}
	now := time.Now()
	k := key(id)
	_, err = m.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, k, "uid", sub.UserID, "email", sub.Email, "phone", phone, "code", hashCode(id, code), "attempts", 0, "sends", 1, "sent_at", now.Unix())
		p.Expire(ctx, k, m.cfg.TTL)
		return nil
	})
	if err != nil {
		return Challenge{}, fmt.Errorf("store otp challenge: %w", err)
	}
	if err := m.sender.Send(ctx, phone, message(code, m.cfg.TTL)); err != nil {
		m.rdb.Del(context.WithoutCancel(ctx), k)
		return Challenge{}, fmt.Errorf("send otp sms: %w", err)
	}
	return Challenge{ID: id, ExpiresAt: now.Add(m.cfg.TTL), ResendAt: now.Add(m.cfg.ResendAfter)}, nil
}

var resendScript = redis.NewScript(`
local v = redis.call('HMGET', KEYS[1], 'sent_at', 'sends', 'phone')
if not v[1] then return {-1} end
if tonumber(ARGV[1]) < tonumber(v[1]) + tonumber(ARGV[2]) then return {-2} end
if tonumber(v[2]) >= tonumber(ARGV[3]) then return {-3} end
redis.call('HSET', KEYS[1], 'code', ARGV[4], 'attempts', 0, 'sent_at', ARGV[1])
redis.call('HINCRBY', KEYS[1], 'sends', 1)
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return {1, v[3]}
`)

func (m *Manager) Resend(ctx context.Context, id string) (Challenge, error) {
	code, err := newCode()
	if err != nil {
		return Challenge{}, err
	}
	now := time.Now()
	res, err := resendScript.Run(ctx, m.rdb, []string{key(id)},
		now.Unix(), int64(m.cfg.ResendAfter/time.Second), m.cfg.MaxSends,
		hashCode(id, code), m.cfg.TTL.Milliseconds()).Slice()
	if err != nil {
		return Challenge{}, fmt.Errorf("resend otp: %w", err)
	}
	switch res[0].(int64) {
	case -1:
		return Challenge{}, ErrNotFound
	case -2:
		return Challenge{}, ErrResendTooSoon
	case -3:
		return Challenge{}, ErrTooManySends
	}
	if err := m.sender.Send(ctx, str(res[1]), message(code, m.cfg.TTL)); err != nil {
		return Challenge{}, fmt.Errorf("send otp sms: %w", err)
	}
	return Challenge{ID: id, ExpiresAt: now.Add(m.cfg.TTL), ResendAt: now.Add(m.cfg.ResendAfter)}, nil
}

var verifyScript = redis.NewScript(`
local v = redis.call('HMGET', KEYS[1], 'code', 'uid', 'email')
if not v[1] then return {-1} end
if v[1] == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return {1, v[2], v[3]}
end
if redis.call('HINCRBY', KEYS[1], 'attempts', 1) >= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  return {-2, v[2], v[3]}
end
return {0, v[2], v[3]}
`)

func (m *Manager) Verify(ctx context.Context, id, code string) (Subject, error) {
	res, err := verifyScript.Run(ctx, m.rdb, []string{key(id)}, hashCode(id, code), m.cfg.MaxAttempts).Slice()
	if err != nil {
		return Subject{}, fmt.Errorf("verify otp: %w", err)
	}
	status := res[0].(int64)
	if status == -1 {
		return Subject{}, ErrNotFound
	}
	uid, _ := strconv.ParseInt(str(res[1]), 10, 64)
	sub := Subject{UserID: uid, Email: str(res[2])}
	switch status {
	case 1:
		return sub, nil
	case -2:
		return sub, ErrTooManyAttempts
	}
	return sub, ErrInvalidCode
}

func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func hashCode(id, code string) string {
	sum := sha256.Sum256([]byte(id + ":" + code))
	return hex.EncodeToString(sum[:])
}

func message(code string, ttl time.Duration) string {
	return fmt.Sprintf("MartGo login code: %s. It expires in %d minutes. Never share this code.", code, int(ttl.Minutes()))
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
