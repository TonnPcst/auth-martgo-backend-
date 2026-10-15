package service

import (
	"sync"
	"time"
)

const maxGuardEntries = 10_000

type loginAttempt struct {
	fails       int
	lastFail    time.Time
	lockedUntil time.Time
}

// loginGuard locks an email out after too many failed logins. It is in-memory,
// so it resets on restart and is per instance; use Redis if you run several replicas.
type loginGuard struct {
	mu      sync.Mutex
	max     int
	lockFor time.Duration
	entries map[string]*loginAttempt
}

// newLoginGuard creates an in-memory login lockout tracker.
//
// ENG: State is per instance and lost on restart; use Redis to share it across replicas.
// LAO: ສ້າງຕົວຕິດຕາມການເຂົ້າສູ່ລະບົບລົ້ມເຫຼວ (ເກັບໃນ memory).
//
// @param max - failures allowed before locking
// @param lockFor - lock duration, also how long failures are remembered
// @returns the guard
func newLoginGuard(max int, lockFor time.Duration) *loginGuard {
	return &loginGuard{max: max, lockFor: lockFor, entries: make(map[string]*loginAttempt)}
}

// locked reports whether key is locked out right now.
//
// ENG: Safe for concurrent use.
// LAO: ກວດວ່າ email ນີ້ຖືກລັອກຢູ່ຫຼືບໍ່.
//
// @param key - normalized email
// @param now - current time
// @returns true while the lock is active
func (g *loginGuard) locked(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	a, ok := g.entries[key]
	return ok && now.Before(a.lockedUntil)
}

// fail records a failed login for key and locks it after too many.
//
// ENG: Failures older than lockFor are forgotten. On the max-th failure the key is
// locked for lockFor and the counter restarts. Old entries are swept when the map
// grows past 10,000 to keep memory bounded.
// LAO: ບັນທຶກການເຂົ້າສູ່ລະບົບລົ້ມເຫຼວ — ຄົບກຳນົດຈະລັອກ.
//
// @param key - normalized email
// @param now - current time
func (g *loginGuard) fail(key string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.entries) > maxGuardEntries {
		g.sweep(now)
	}
	a, ok := g.entries[key]
	if !ok || now.Sub(a.lastFail) > g.lockFor {
		a = &loginAttempt{}
		g.entries[key] = a
	}
	a.fails++
	a.lastFail = now
	if a.fails >= g.max {
		a.lockedUntil = now.Add(g.lockFor)
		a.fails = 0
	}
}

// reset clears the failure history for key after a successful login.
//
// ENG: Safe for concurrent use.
// LAO: ລ້າງປະຫວັດການລົ້ມເຫຼວ ຫຼັງເຂົ້າສູ່ລະບົບສຳເລັດ.
//
// @param key - normalized email
func (g *loginGuard) reset(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.entries, key)
}

// sweep deletes entries that are neither locked nor recent.
//
// ENG: The caller must hold g.mu.
// LAO: ລຶບລາຍການເກົ່າທີ່ບໍ່ຖືກລັອກ ແລະ ໝົດອາຍຸແລ້ວ.
//
// @param now - current time
func (g *loginGuard) sweep(now time.Time) {
	for k, a := range g.entries {
		if now.After(a.lockedUntil) && now.Sub(a.lastFail) > g.lockFor {
			delete(g.entries, k)
		}
	}
}
