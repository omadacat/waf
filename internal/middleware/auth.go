package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"git.omada.cafe/atf/waf/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// BasicAuth provides HTTP Basic Authentication for specific path prefixes.
// Passwords are stored as bcrypt hashes — never plaintext.
// Auth attempts are rate-limited per IP (5 attempts per 10 seconds)
// to slow brute-force without a full account lockout.
//
// Wire it between Session and the WAF:
//
//	authMW := middleware.NewBasicAuth(wafInner, cfg.Auth, log)
//	sessionMW := middleware.NewSession(mux, dispatcher, tokenMgr, cfg, log)
type BasicAuth struct {
	next      http.Handler
	users     map[string][]byte // username -> hash
	paths     map[string][]string // path prefix -> allowed usernames
	realm     string
	mu        sync.RWMutex
	attempts  map[string][]time.Time // IP -> attempt timestamps
	log       *slog.Logger
}

// AuthConfig is the YAML-loaded configuration for basic auth.
type AuthConfig struct {
	Enabled bool              `yaml:"enabled"`
	Realm   string            `yaml:"realm"`
	Users   map[string]string `yaml:"users"` // username -> hash string
	Paths   map[string][]string `yaml:"paths"` // path prefix -> [usernames]
}

// TODO: impl OIDC for omada logins

func NewBasicAuth(next http.Handler, cfg config.AuthConfig, log *slog.Logger) *BasicAuth {
	ba := &BasicAuth{
		next:     next,
		users:    make(map[string][]byte),
		paths:    make(map[string][]string),
		realm:    cfg.Realm,
		attempts: make(map[string][]time.Time),
		log:      log,
	}
	if ba.realm == "" {
		ba.realm = "Restricted"
	}
	for user, hash := range cfg.Users {
		ba.users[user] = []byte(hash)
	}
	for pathPrefix, users := range cfg.Paths {
		ba.paths[pathPrefix] = users
	}
	// cleanup goroutine for attempt history
	go ba.sweepAttempts()
	return ba
}

func (ba *BasicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requiredUsers := ba.getRequiredUsers(r.URL.Path)
	if requiredUsers == nil {
		// Path not protected
		ba.next.ServeHTTP(w, r)
		return
	}

	ip := extractIP(r)

	// Rate limit: max 5 attempts per 10 seconds per IP
	if ba.isRateLimited(ip) {
		ba.log.Warn("auth: rate limited", "ip", ip, "path", r.URL.Path)
		w.Header().Set("Retry-After", "10")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		ba.challenge(w, r)
		return
	}

	ba.mu.RLock()
	hash, exists := ba.users[user]
	ba.mu.RUnlock()

	if !exists || bcrypt.CompareHashAndPassword(hash, []byte(pass)) != nil {
		ba.recordAttempt(ip)
		ba.log.Warn("auth: failed attempt", "ip", ip, "user", user, "path", r.URL.Path)
		ba.challenge(w, r)
		return
	}

	// Check the user is allowed for this specific path
	allowed := false
	for _, u := range requiredUsers {
		if u == user || u == "*" {
			allowed = true
			break
		}
	}
	if !allowed {
		ba.log.Warn("auth: user not allowed for path", "ip", ip, "user", user, "path", r.URL.Path)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	ba.log.Debug("auth: authenticated", "ip", ip, "user", user, "path", r.URL.Path)
	ba.next.ServeHTTP(w, r)
}

func (ba *BasicAuth) challenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+ba.realm+`", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (ba *BasicAuth) getRequiredUsers(reqPath string) []string {
	ba.mu.RLock()
	defer ba.mu.RUnlock()
	// Longest matching prefix wins
	var longestMatch string
	var users []string
	for prefix, u := range ba.paths {
		if strings.HasPrefix(reqPath, prefix) && len(prefix) > len(longestMatch) {
			longestMatch = prefix
			users = u
		}
	}
	return users
}

func (ba *BasicAuth) isRateLimited(ip string) bool {
	ba.mu.Lock()
	defer ba.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-10 * time.Second)
	recent := ba.attempts[ip]
	var kept []time.Time
	for _, t := range recent {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	ba.attempts[ip] = kept
	return len(kept) >= 5
}

func (ba *BasicAuth) recordAttempt(ip string) {
	ba.mu.Lock()
	ba.attempts[ip] = append(ba.attempts[ip], time.Now())
	ba.mu.Unlock()
}

func (ba *BasicAuth) sweepAttempts() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ba.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Second)
		for ip, times := range ba.attempts {
			var kept []time.Time
			for _, t := range times {
				if t.After(cutoff) {
					kept = append(kept, t)
				}
			}
			if len(kept) == 0 {
				delete(ba.attempts, ip)
			} else {
				ba.attempts[ip] = kept
			}
		}
		ba.mu.Unlock()
	}
}

// HashPassword generates a hash suitable for use in config.yaml.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}
