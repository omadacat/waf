package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"git.omada.cafe/atf/waf/internal/bans"
	"git.omada.cafe/atf/waf/internal/config"
	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/store"
)

type RateLimit struct {
	next      http.Handler
	cfg       config.RateLimitConfig
	limiter   *store.RateLimiter
	blacklist *store.Store
	banMgr    *bans.BanManager // this is optional, nil only means no persistent bans
	log       *slog.Logger
}

// NewRateLimit creates the rate-limiting middleware.
// banMgr may be nil; if set, IPs that exceed the threshold are also recorded in the persistent ban store and emitted to fail2ban.
func NewRateLimit(next http.Handler, cfg config.RateLimitConfig, banMgr *bans.BanManager, log *slog.Logger) *RateLimit {
	return &RateLimit{
		next:      next,
		cfg:       cfg,
		limiter:   store.NewRateLimiter(),
		blacklist: store.New(),
		banMgr:    banMgr,
		log:       log,
	}
}

func (rl *RateLimit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !rl.cfg.Enabled {
		rl.next.ServeHTTP(w, r)
		return
	}
	ip := extractIP(r)

	// Check in-memory blacklist first (somehow fastest)
	if rl.blacklist.Exists("bl:" + ip) {
		rl.log.Info("rate_limit: blacklisted", "ip", ip)
		w.Header().Set("Retry-After", "3600")
		errorpage.WriteBlock(w, http.StatusTooManyRequests, ip, "rate_limit:blacklisted", rl.log)
		return
	}

	// Check persistent ban manager
	if rl.banMgr != nil {
		if banned, entry := rl.banMgr.IsBanned(ip); banned {
			rl.log.Info("rate_limit: persistently banned", "ip", ip, "reason", entry.Reason)
			w.Header().Set("Retry-After", "3600")
			errorpage.WriteBlock(w, http.StatusTooManyRequests, ip, "rate_limit", rl.log)
			return
		}
	}

	window := time.Duration(rl.cfg.WindowSeconds) * time.Second
	count := rl.limiter.Count(ip, window)
	if count > rl.cfg.MaxRequests {
		rl.blacklist.Set("bl:"+ip, true, rl.cfg.BlacklistDuration.Duration)
		if rl.banMgr != nil {
			rl.banMgr.Ban(ip, "rate_limit", rl.cfg.BlacklistDuration.Duration, "rate-001", 25)
		}
		rl.log.Warn("rate_limit: threshold exceeded",
			"ip", ip, "count", count, "limit", rl.cfg.MaxRequests)
		w.Header().Set("Retry-After", "3600")
		errorpage.WriteBlock(w, http.StatusTooManyRequests, ip, "rate_limit:threshold", rl.log)
		return
	}

	rl.next.ServeHTTP(w, r)
}
