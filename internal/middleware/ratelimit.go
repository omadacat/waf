package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"git.omada.cafe/atf/waf/internal/config"
	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/store"
)

type RateLimit struct {
	next      http.Handler
	cfg       config.RateLimitConfig
	limiter   *store.RateLimiter
	blacklist *store.Store
	log       *slog.Logger
}

func NewRateLimit(next http.Handler, cfg config.RateLimitConfig, log *slog.Logger) *RateLimit {
	return &RateLimit{
		next:      next,
		cfg:       cfg,
		limiter:   store.NewRateLimiter(),
		blacklist: store.New(),
		log:       log,
	}
}

func (rl *RateLimit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !rl.cfg.Enabled {
		rl.next.ServeHTTP(w, r)
		return
	}
	ip := extractIP(r)
	if rl.blacklist.Exists("bl:" + ip) {
		rl.log.Info("rate_limit: blacklisted", "ip", ip)
		w.Header().Set("Retry-After", "3600")
		errorpage.Write(w, http.StatusTooManyRequests)
		return
	}
	window := time.Duration(rl.cfg.WindowSeconds) * time.Second
	count := rl.limiter.Count(ip, window)
	if count > rl.cfg.MaxRequests {
		rl.blacklist.Set("bl:"+ip, true, rl.cfg.BlacklistDuration.Duration)
		rl.log.Warn("rate_limit: threshold exceeded — blacklisted",
			"ip", ip, "count", count, "limit", rl.cfg.MaxRequests)
		w.Header().Set("Retry-After", "3600")
		errorpage.Write(w, http.StatusTooManyRequests)
		return
	}
	rl.next.ServeHTTP(w, r)
}
