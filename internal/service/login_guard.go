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

func newLoginGuard(max int, lockFor time.Duration) *loginGuard {
	return &loginGuard{max: max, lockFor: lockFor, entries: make(map[string]*loginAttempt)}
}

func (g *loginGuard) locked(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	a, ok := g.entries[key]
	return ok && now.Before(a.lockedUntil)
}

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

func (g *loginGuard) reset(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.entries, key)
}

func (g *loginGuard) sweep(now time.Time) {
	for k, a := range g.entries {
		if now.After(a.lockedUntil) && now.Sub(a.lastFail) > g.lockFor {
			delete(g.entries, k)
		}
	}
}
