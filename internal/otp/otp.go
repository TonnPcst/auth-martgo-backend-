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

// DefaultConfig returns the standard OTP settings.
//
// ENG: Codes live 5 minutes, 5 wrong tries end the challenge, a resend is allowed after
// 1 minute and at most 3 SMS are sent per challenge.
// LAO: ການຕັ້ງຄ່າ OTP ມາດຕະຖານ — ອາຍຸ 5 ນາທີ, ຜິດໄດ້ 5 ຄັ້ງ, ສົ່ງໃໝ່ໄດ້ຫຼັງ 1 ນາທີ, ສູງສຸດ 3 ຄັ້ງ.
//
// @returns the default config
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

// NewManager creates the OTP manager.
//
// ENG: Challenges are stored in Redis; codes are delivered through sender.
// LAO: ສ້າງຕົວຈັດການ OTP — ເກັບໃນ Redis ແລະ ສົ່ງຜ່ານ SMS sender.
//
// @param rdb - Redis client
// @param sender - SMS sender (Telbiz or log)
// @param cfg - OTP limits and timings
// @returns the manager
func NewManager(rdb *redis.Client, sender Sender, cfg Config) *Manager {
	return &Manager{rdb: rdb, sender: sender, cfg: cfg}
}

// key returns the Redis key of an OTP challenge.
//
// ENG: Format: "otp:login:<challenge id>".
// LAO: ສ້າງ key ຂອງ Redis ສຳລັບ OTP challenge.
//
// @param id - challenge ID
// @returns the Redis key
func key(id string) string { return "otp:login:" + id }

// Start creates a login challenge and texts a new code to the user.
//
// ENG: Generates a random challenge ID and a 6-digit code, stores the user, phone and a
// hash of the code in Redis with the TTL (the plain code is never stored), then sends
// the SMS. If sending fails the challenge is deleted.
// LAO: ສ້າງ OTP challenge — ສ້າງລະຫັດ 6 ຫຼັກ, ເກັບ hash ໃນ Redis (TTL), ແລ້ວສົ່ງ SMS.
//
// @param ctx - request context
// @param sub - user the code is for
// @param phone - normalized phone number to send to
// @returns the challenge (ID, expiry, earliest resend time), or an error if Redis or SMS fails
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

// Resend replaces the code of an open challenge and texts the new one.
//
// ENG: A Lua script checks and updates the challenge atomically: it must exist, the
// resend cooldown must have passed and the send limit must not be reached. The
// wrong-attempt counter and the TTL are reset.
// LAO: ສົ່ງລະຫັດ OTP ໃໝ່ — ກວດ cooldown ແລະ ຈຳນວນຄັ້ງແບບ atomic ດ້ວຍ Lua script.
//
// @param ctx - request context
// @param id - challenge ID
// @returns the updated challenge, or ErrNotFound, ErrResendTooSoon, ErrTooManySends or an SMS error
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

// Verify checks a code against a challenge.
//
// ENG: A Lua script compares the hashed code atomically. A correct code deletes the
// challenge so it cannot be reused. A wrong code increases the attempt counter, and
// the challenge is deleted once MaxAttempts is reached. The subject is returned even
// on a wrong code so the caller can count the failure against that user.
// LAO: ຢືນຢັນລະຫັດ OTP — ຖືກຈະລຶບ challenge, ຜິດຈະນັບຄັ້ງ, ຄົບກຳນົດຈະລຶບທິ້ງ.
//
// @param ctx - request context
// @param id - challenge ID
// @param code - code typed by the user
// @returns the subject, or ErrNotFound, ErrInvalidCode or ErrTooManyAttempts
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

// newCode generates a random 6-digit code using crypto/rand.
//
// ENG: Leading zeros are kept, e.g. "004213".
// LAO: ສ້າງລະຫັດ 6 ຫຼັກແບບສຸ່ມ (crypto/rand).
//
// @returns the code, or an error if the random source fails
func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// hashCode hashes a code together with its challenge ID using SHA-256.
//
// ENG: Mixing in the ID means the same code gives a different hash in every challenge.
// LAO: hash ລະຫັດ OTP ຮ່ວມກັບ challenge ID ດ້ວຍ SHA-256.
//
// @param id - challenge ID
// @param code - 6-digit code
// @returns the hex-encoded hash
func hashCode(id, code string) string {
	sum := sha256.Sum256([]byte(id + ":" + code))
	return hex.EncodeToString(sum[:])
}

// message builds the SMS text for a login code.
//
// ENG: Includes the code, how many minutes it is valid and a warning not to share it.
// LAO: ສ້າງຂໍ້ຄວາມ SMS ທີ່ມີລະຫັດ OTP ແລະ ເວລາໝົດອາຍຸ.
//
// @param code - 6-digit code
// @param ttl - how long the code is valid
// @returns the SMS text
func message(code string, ttl time.Duration) string {
	return fmt.Sprintf("MartGo login code: %s. It expires in %d minutes. Never share this code.", code, int(ttl.Minutes()))
}

// str converts a Redis script result value to a string.
//
// ENG: Returns "" when the value is not a string (e.g. nil).
// LAO: ແປງຄ່າຈາກ Redis script ເປັນ string.
//
// @param v - value from the script result
// @returns the string, or ""
func str(v any) string {
	s, _ := v.(string)
	return s
}
