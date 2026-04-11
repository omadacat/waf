package middleware

import (
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"git.omada.cafe/atf/waf/internal/bans"
	"git.omada.cafe/atf/waf/internal/config"
	"git.omada.cafe/atf/waf/internal/errorpage"
)

// reSequential matches paths that contain a run of digits — used to detect
// sequential enumeration (e.g. /post/1, /post/2, /post/3 …).
var reSequential = regexp.MustCompile(`/\d+(?:/|$)`)

// ipState tracks per-IP crawl signals within a sliding window.
type ipState struct {
	mu sync.Mutex

	// Unique paths seen in the current window.
	paths map[string]struct{}

	// Sequential numeric path IDs seen (last N values).
	seqIDs []int64

	// Timestamps of the last maxTimings requests (for regularity check).
	timings []time.Time

	// Total requests in the current window.
	total int

	// Window start.
	windowStart time.Time

	// Score accumulated against this IP (higher = more bot-like).
	score int
}

// ScraperDetector analyses per-IP request behaviour to catch crawlers that
// have already passed the JS/scrypt challenge and hold a valid token.
//
// Signals tracked:
//   - Unique-path ratio: crawlers hit many distinct URLs; browsers revisit.
//   - Sequential path enumeration: /item/1, /item/2, /item/3 …
//   - Missing Referer on HTML navigations: browsers carry the chain.
//   - Suspiciously uniform inter-request timing: bots are metronomic.
type ScraperDetector struct {
	next   http.Handler
	cfg    config.ScraperConfig
	banMgr *bans.BanManager
	log    *slog.Logger

	mu    sync.Mutex
	state map[string]*ipState // ip → state
}

// NewScraperDetector constructs the middleware. banMgr may be nil.
func NewScraperDetector(next http.Handler, cfg config.ScraperConfig, banMgr *bans.BanManager, log *slog.Logger) *ScraperDetector {
	sd := &ScraperDetector{
		next:   next,
		cfg:    cfg,
		banMgr: banMgr,
		log:    log,
		state:  make(map[string]*ipState),
	}
	go sd.cleanup()
	return sd
}

func (sd *ScraperDetector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !sd.cfg.Enabled {
		sd.next.ServeHTTP(w, r)
		return
	}

	ip := extractIP(r)
	score := sd.analyse(ip, r)

	if score >= sd.cfg.BanThreshold {
		if sd.banMgr != nil {
			sd.banMgr.Ban(ip, "scraper_behavior", sd.cfg.BanDuration.Duration, "scraper-001", score)
		}
		sd.log.Warn("scraper: banned",
			"ip", ip, "score", score,
			"path", r.URL.Path, "ua", r.Header.Get("User-Agent"))
		errorpage.Write(w, http.StatusForbidden)
		return
	}

	if score >= sd.cfg.ChallengeThreshold {
		sd.log.Info("scraper: challenge threshold reached",
			"ip", ip, "score", score, "path", r.URL.Path)
		// Let the request fall through; the upstream challenge gate will
		// invalidate the token on the next token check if desired.
		// For now we add a header the challenge dispatcher can act on.
		r.Header.Set("X-WAF-Scraper-Score", itoa(score))
	}

	sd.next.ServeHTTP(w, r)
}

// analyse updates the per-IP state and returns a bot-likelihood score (0–100+).
func (sd *ScraperDetector) analyse(ip string, r *http.Request) int {
	sd.mu.Lock()
	st, ok := sd.state[ip]
	if !ok {
		st = &ipState{
			paths:       make(map[string]struct{}),
			windowStart: time.Now(),
		}
		sd.state[ip] = st
	}
	sd.mu.Unlock()

	st.mu.Lock()
	defer st.mu.Unlock()

	window := sd.cfg.Window.Duration
	now := time.Now()

	// Roll window.
	if now.Sub(st.windowStart) > window {
		st.paths = make(map[string]struct{})
		st.seqIDs = st.seqIDs[:0]
		st.timings = st.timings[:0]
		st.total = 0
		st.score = 0
		st.windowStart = now
	}

	path := r.URL.Path
	st.paths[path] = struct{}{}
	st.total++

	maxTimings := 20
	st.timings = append(st.timings, now)
	if len(st.timings) > maxTimings {
		st.timings = st.timings[len(st.timings)-maxTimings:]
	}

	score := 0

	// ── Signal 1: high unique-path ratio ──────────────────────────────────
	// Only evaluate after enough requests to be statistically meaningful.
	if st.total >= sd.cfg.MinRequests {
		ratio := float64(len(st.paths)) / float64(st.total)
		if ratio >= sd.cfg.UniquePathRatioHard {
			score += 50 // near-certain crawl
		} else if ratio >= sd.cfg.UniquePathRatioSoft {
			score += 25
		}
	}

	// ── Signal 2: sequential numeric path enumeration ─────────────────────
	if reSequential.MatchString(path) {
		id := extractTrailingInt(path)
		if id > 0 {
			st.seqIDs = append(st.seqIDs, id)
			if len(st.seqIDs) > 10 {
				st.seqIDs = st.seqIDs[len(st.seqIDs)-10:]
			}
			if isSequentialRun(st.seqIDs, sd.cfg.SeqRunLength) {
				score += 40
			}
		}
	}

	// ── Signal 3: missing Referer on HTML navigations ─────────────────────
	// Skip assets, API endpoints, and the first request from any IP.
	accept := r.Header.Get("Accept")
	referer := r.Header.Get("Referer")
	isHTML := strings.Contains(accept, "text/html")
	if isHTML && referer == "" && st.total > 3 && !isAssetPath(path) {
		score += 15
	}

	// ── Signal 4: metronomic inter-request timing ─────────────────────────
	if len(st.timings) >= 10 {
		if isMetronomic(st.timings, sd.cfg.MetronomeJitterMs) {
			score += 30
		}
	}

	// Accumulate into persistent IP score.
	st.score += score
	return st.score
}

// cleanup removes stale IP entries every 5 minutes.
func (sd *ScraperDetector) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-sd.cfg.Window.Duration * 2)
		sd.mu.Lock()
		for ip, st := range sd.state {
			st.mu.Lock()
			stale := st.windowStart.Before(cutoff)
			st.mu.Unlock()
			if stale {
				delete(sd.state, ip)
			}
		}
		sd.mu.Unlock()
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

var reTrailingInt = regexp.MustCompile(`/(\d+)(?:/[^/]*)?$`)

func extractTrailingInt(path string) int64 {
	m := reTrailingInt.FindStringSubmatch(path)
	if m == nil {
		return 0
	}
	var n int64
	for _, c := range m[1] {
		n = n*10 + int64(c-'0')
	}
	return n
}

// isSequentialRun returns true if the last `run` values in ids form a strictly
// increasing sequence with step ≤ 2 (allows small gaps).
func isSequentialRun(ids []int64, run int) bool {
	if len(ids) < run {
		return false
	}
	tail := ids[len(ids)-run:]
	for i := 1; i < len(tail); i++ {
		diff := tail[i] - tail[i-1]
		if diff <= 0 || diff > 2 {
			return false
		}
	}
	return true
}

// isMetronomic returns true if inter-request gaps have very low variance —
// characteristic of a bot with a fixed sleep interval.
func isMetronomic(ts []time.Time, maxJitterMs int) bool {
	if len(ts) < 4 {
		return false
	}
	gaps := make([]int64, len(ts)-1)
	var sum int64
	for i := 1; i < len(ts); i++ {
		gaps[i-1] = ts[i].Sub(ts[i-1]).Milliseconds()
		sum += gaps[i-1]
	}
	mean := sum / int64(len(gaps))
	if mean <= 0 {
		return false
	}
	var variance int64
	for _, g := range gaps {
		d := g - mean
		variance += d * d
	}
	variance /= int64(len(gaps))
	// stddev in ms
	stddev := isqrt(variance)
	return stddev <= int64(maxJitterMs)
}

func isqrt(n int64) int64 {
	if n <= 0 {
		return 0
	}
	x := n
	for {
		x1 := (x + n/x) / 2
		if x1 >= x {
			return x
		}
		x = x1
	}
}

var assetExts = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
	".svg", ".ico", ".woff", ".woff2", ".ttf", ".webp", ".avif",
}

func isAssetPath(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range assetExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return strings.HasPrefix(path, "/_waf/") ||
		strings.HasPrefix(path, "/api/")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
