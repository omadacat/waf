package store

// Package store provides an in-memory concurrent store with TTL expiration, used for nonces, CSS session state, rate-limit windows, and IP blacklists.
// Use a simple sync.Map-backed store rather than a full cache library to keep dependencies minimal. A background goroutine sweeps expired entries every minute so memory doesn't grow unboundedly.
// For multi-instance deployments, swap this out for a Redis-backed store using the same Store interface the rest of the codebase doesn't change.

import (
	"sync"
	"time"
)

// entry wraps a value with an optional expiry.
type entry struct {
	value  any
	expiry time.Time // zero = no expiry
}

func (e entry) expired() bool {
	return !e.expiry.IsZero() && time.Now().After(e.expiry)
}

// Store is a generic concurrent in-memory key-value store with TTL.
type Store struct {
	mu   sync.RWMutex
	data map[string]entry
}

// New creates a Store and starts a background cleanup goroutine.
func New() *Store {
	s := &Store{data: make(map[string]entry)}
	go s.sweep()
	return s
}

// Set stores a value; ttl=0 means no expiry.
func (s *Store) Set(key string, value any, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := entry{value: value}
	if ttl > 0 {
		e.expiry = time.Now().Add(ttl)
	}
	s.data[key] = e
}

// get retrieves a value. Returns (value, true) if found and not expired.
func (s *Store) Get(key string) (any, bool) {
	s.mu.RLock()
	e, ok := s.data[key]
	s.mu.RUnlock()
	if !ok || e.expired() {
		return nil, false
	}
	return e.value, true
}

// delete removes a key immediately.
func (s *Store) Delete(key string) {
	s.mu.Lock()
	delete(s.data, key)
	s.mu.Unlock()
}

// Exists returns true if key exists and is not expired.
func (s *Store) Exists(key string) bool {
	_, ok := s.Get(key)
	return ok
}

// sweep runs every 60 seconds and removes expired entries, it prevents unbounded memory growth under sustained attack traffic.
func (s *Store) sweep() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		for k, e := range s.data {
			if e.expired() {
				delete(s.data, k)
			}
		}
		s.mu.Unlock()
	}
}

// ============================================================
// Sliding Window Rate Limiter
// ============================================================

// window tracks request timestamps for one IP within a sliding window.
type Window struct {
	mu         sync.Mutex
	timestamps []time.Time
}

// add records a new request timestamp and returns the count of requests within the last windowSize duration.
func (w *Window) Add(windowSize time.Duration) int {
	now := time.Now()
	cutoff := now.Add(-windowSize)
	w.mu.Lock()
	defer w.mu.Unlock()
	// Prune old timestamps
	i := 0
	for i < len(w.timestamps) && w.timestamps[i].Before(cutoff) {
		i++
	}
	w.timestamps = append(w.timestamps[i:], now)
	return len(w.timestamps)
}

// RateLimiter manages per-IP sliding windows.
type RateLimiter struct {
	mu      sync.RWMutex
	windows map[string]*Window
}

// NewRateLimiter constructs a RateLimiter and starts its sweep goroutine.
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{windows: make(map[string]*Window)}
	go rl.sweep()
	return rl
}

// Count adds a request for the given IP and returns the current window count.
func (rl *RateLimiter) Count(ip string, windowSize time.Duration) int {
	rl.mu.RLock()
	w, ok := rl.windows[ip]
	rl.mu.RUnlock()
	if !ok {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		if w, ok = rl.windows[ip]; !ok {
			w = &Window{}
			rl.windows[ip] = w
		}
		rl.mu.Unlock()
	}
	return w.Add(windowSize)
}

// sweep evicts empty windows periodically.
func (rl *RateLimiter) sweep() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		for ip, w := range rl.windows {
			w.mu.Lock()
			if len(w.timestamps) == 0 {
				delete(rl.windows, ip)
			}
			w.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}
