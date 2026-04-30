package middleware

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"git.omada.cafe/atf/waf/internal/bans"
	"git.omada.cafe/atf/waf/internal/config"
	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/policy"
)

type BandwidthTracker struct {
	next   http.Handler
	cfg    config.BandwidthConfig
	pol    *policy.Engine
	banMgr *bans.BanManager
	log    *slog.Logger

	mu    sync.Mutex
	state map[string]*bwState
}

type bwState struct {
	mu          sync.Mutex
	bytes       int64
	windowStart time.Time
}

func NewBandwidthTracker(next http.Handler, cfg config.BandwidthConfig, pol *policy.Engine, banMgr *bans.BanManager, log *slog.Logger) *BandwidthTracker {
	bt := &BandwidthTracker{
		next:   next,
		cfg:    cfg,
		pol:    pol,
		banMgr: banMgr,
		log:    log,
		state:  make(map[string]*bwState),
	}
	go bt.cleanup()
	return bt
}

func (bt *BandwidthTracker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !bt.cfg.Enabled {
		bt.next.ServeHTTP(w, r)
		return
	}

	// Skip bandwidth tracking for policy-exempt paths (e.g. Nextcloud WebDAV uploads user is uploading TO the server, not consuming bandwidth FROM it).
	if bt.pol != nil {
		if action, matched := bt.pol.Match(r); matched && action.SkipChallenge {
			bt.next.ServeHTTP(w, r)
			return
		}
	}

	ip := extractIP(r)

	// Wrap the response writer to count bytes sent.
	bw := &countingWriter{ResponseWriter: w}
	bt.next.ServeHTTP(bw, r)

	// Record bytes served after response completes.
	bt.record(ip, bw.written, r)
}

func (bt *BandwidthTracker) record(ip string, written int64, r *http.Request) {
	bt.mu.Lock()
	st, ok := bt.state[ip]
	if !ok {
		st = &bwState{windowStart: time.Now()}
		bt.state[ip] = st
	}
	bt.mu.Unlock()

	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	if now.Sub(st.windowStart) > bt.cfg.Window.Duration {
		st.bytes = 0
		st.windowStart = now
	}

	st.bytes += written
	total := st.bytes

	banBytes := int64(bt.cfg.BanThresholdMB) * 1024 * 1024
	warnBytes := int64(bt.cfg.WarnThresholdMB) * 1024 * 1024

	if banBytes > 0 && total >= banBytes {
		if bt.banMgr != nil {
			bt.banMgr.Ban(ip, "bandwidth_abuse", bt.cfg.BanDuration.Duration, "bandwidth-001", 75)
		}
		bt.log.Warn("bandwidth: IP banned",
			"ip", ip,
			"mb", total/1024/1024,
			"threshold_mb", bt.cfg.BanThresholdMB,
			"path", r.URL.Path,
		)
	} else if warnBytes > 0 && total >= warnBytes {
		bt.log.Info("bandwidth: high usage",
			"ip", ip,
			"mb", total/1024/1024,
			"threshold_mb", bt.cfg.WarnThresholdMB,
		)
	}
}

func (bt *BandwidthTracker) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-bt.cfg.Window.Duration * 2)
		bt.mu.Lock()
		for ip, st := range bt.state {
			st.mu.Lock()
			stale := st.windowStart.Before(cutoff)
			st.mu.Unlock()
			if stale {
				delete(bt.state, ip)
			}
		}
		bt.mu.Unlock()
	}
}

// countingWriter wraps http.ResponseWriter and counts bytes written.
type countingWriter struct {
	http.ResponseWriter
	written int64
}

func (cw *countingWriter) Write(b []byte) (int, error) {
	n, err := cw.ResponseWriter.Write(b)
	cw.written += int64(n)
	return n, err
}

// BandwidthBlock returns a 429 if an IP is already in the ban store
// for bandwidth abuse, BEFORE serving the response (so we don't waste
// bytes on clients we've already decided to cut off).
func (bt *BandwidthTracker) shouldBlock(ip string) bool {
	if bt.banMgr == nil {
		return false
	}
	banned, entry := bt.banMgr.IsBanned(ip)
	return banned && entry.Reason == "bandwidth_abuse"
}

// ServeHTTP checks ban first, then tracks.
func (bt *BandwidthTracker) serveWithBanCheck(w http.ResponseWriter, r *http.Request) {
	if !bt.cfg.Enabled {
		bt.next.ServeHTTP(w, r)
		return
	}

	ip := extractIP(r)

	if bt.shouldBlock(ip) {
		w.Header().Set("Retry-After", "3600")
		errorpage.WriteBlock(w, http.StatusTooManyRequests, ip, "bandwidth_abuse", bt.log)
		return
	}

	bw := &countingWriter{ResponseWriter: w}
	bt.next.ServeHTTP(bw, r)
	bt.record(ip, bw.written, r)
}
