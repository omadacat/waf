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
	"git.omada.cafe/atf/waf/internal/policy"
)

var reSequential = regexp.MustCompile(`/\d+(?:/|$)`)

// ipState tracks per-IP crawl signals within a sliding window.
type ipState struct {
	mu sync.Mutex

	// navPaths / navTotal track non-asset navigation requests only.
	// Asset requests (.png, .css, etc.) are excluded from ratio and referer signals because they are trivially unique and cause false positives on image-heavy pages.
	navPaths map[string]struct{}
	navTotal int

	// total counts all requests; used only for timing analysis.
	total int

	seqIDs  []int64
	timings []time.Time

	windowStart time.Time
	score       int

	// signalsFired tracks which signals have already contributed to the
	// score in this window.  Once a signal fires, it cannot fire again
	// until the window rolls.  This prevents runaway score accumulation
	// where e.g. metronomic adds +30 on every single asset request.
	signalsFired map[string]bool
}

// ScraperDetector analyses per-IP request behaviour.
//
// Signals:
//   - High unique navigation-path ratio (assets excluded)
//   - Sequential numeric path enumeration
//   - Missing Referer on HTML navigations
//   - Metronomic inter-request timing with deliberate pacing (mean gap > 200ms)
//
// Each signal fires AT MOST ONCE per window per IP to prevent score runaway from burst browser asset loading.
type ScraperDetector struct {
	next   http.Handler
	cfg    config.ScraperConfig
	pol    *policy.Engine
	banMgr *bans.BanManager
	log    *slog.Logger

	mu    sync.Mutex
	state map[string]*ipState
}

func NewScraperDetector(next http.Handler, cfg config.ScraperConfig, pol *policy.Engine, banMgr *bans.BanManager, log *slog.Logger) *ScraperDetector {
	sd := &ScraperDetector{
		next:   next,
		cfg:    cfg,
		pol:    pol,
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

	// Skip behavioural analysis for known service endpoints.
	if sd.pol != nil {
		if action, matched := sd.pol.Match(r); matched && action.SkipChallenge {
			sd.next.ServeHTTP(w, r)
			return
		}
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
		errorpage.WriteBlock(w, http.StatusForbidden, ip, "scraper:behavior", sd.log)
		return
	}

	if score >= sd.cfg.ChallengeThreshold {
		sd.log.Info("scraper: challenge threshold reached",
			"ip", ip, "score", score, "path", r.URL.Path)
		r.Header.Set("X-WAF-Scraper-Score", itoa(score))
	}

	sd.next.ServeHTTP(w, r)
}

func (sd *ScraperDetector) analyse(ip string, r *http.Request) int {
	sd.mu.Lock()
	st, ok := sd.state[ip]
	if !ok {
		st = &ipState{
			navPaths:    make(map[string]struct{}),
			windowStart: time.Now(),
			signalsFired: make(map[string]bool),
		}
		sd.state[ip] = st
	}
	sd.mu.Unlock()

	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	window := sd.cfg.Window.Duration

	// Roll window — reset all state including which signals have fired.
	if now.Sub(st.windowStart) > window {
		st.navPaths     = make(map[string]struct{})
		st.navTotal     = 0
		st.total        = 0
		st.seqIDs       = st.seqIDs[:0]
		st.timings      = st.timings[:0]
		st.score        = 0
		st.signalsFired = make(map[string]bool)
		st.windowStart  = now
	}

	path  := r.URL.Path
	asset := isAssetPath(path)

	st.total++
	maxTimings := 30
	st.timings = append(st.timings, now)
	if len(st.timings) > maxTimings {
		st.timings = st.timings[len(st.timings)-maxTimings:]
	}

	if !asset {
		st.navPaths[path] = struct{}{}
		st.navTotal++
	}

	score := 0

	if !st.signalsFired["ratio"] && st.navTotal >= sd.cfg.MinRequests {
		ratio := float64(len(st.navPaths)) / float64(st.navTotal)
		if ratio >= sd.cfg.UniquePathRatioHard {
			score += 50
			st.signalsFired["ratio"] = true
		} else if ratio >= sd.cfg.UniquePathRatioSoft {
			score += 25
			st.signalsFired["ratio"] = true
		}
	}

	if !asset && !st.signalsFired["seq"] && reSequential.MatchString(path) {
		id := extractTrailingInt(path)
		if id > 0 {
			st.seqIDs = append(st.seqIDs, id)
			if len(st.seqIDs) > 10 {
				st.seqIDs = st.seqIDs[len(st.seqIDs)-10:]
			}
			if isSequentialRun(st.seqIDs, sd.cfg.SeqRunLength) {
				score += 40
				st.signalsFired["seq"] = true
			}
		}
	}

	if !asset && !st.signalsFired["referer"] && st.navTotal > 5 {
		accept  := r.Header.Get("Accept")
		referer := r.Header.Get("Referer")
		if strings.Contains(accept, "text/html") && referer == "" {
			score += 15
			st.signalsFired["referer"] = true
		}
	}

	if !st.signalsFired["metro"] && len(st.timings) >= 10 {
		if isMetronomic(st.timings, sd.cfg.MetronomeJitterMs) {
			score += 30
			st.signalsFired["metro"] = true
		}
	}

	st.score += score
	return st.score
}

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

// isMetronomic returns true when inter-request gaps are suspiciously uniform AND the mean gap is large enough to indicate deliberate pacing rather than a browser asset burst.
//
// Threshold reasoning:
//   - Browser HTTP/2 parallel requests: mean gap 0–50ms, stddev ~10ms → not metronomic
//   - Bot sleeping 500ms between requests: mean gap ~500ms, stddev ~20ms → metronomic
//   - Bot sleeping 1s: mean ~1000ms, stddev ~30ms → metronomic
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
	// Require deliberate pacing — reject browser parallel-fetch bursts.
	if mean < 200 {
		return false
	}
	var variance int64
	for _, g := range gaps {
		d := g - mean
		variance += d * d
	}
	variance /= int64(len(gaps))
	return isqrt(variance) <= int64(maxJitterMs)
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
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
	".webp", ".avif", ".bmp", ".tiff",
	".woff", ".woff2", ".ttf", ".otf", ".eot",
	".js", ".mjs", ".css", ".map",
	".mp4", ".mp3", ".ogg", ".webm", ".flac", ".wav",
	".pdf", ".xml",
}

func isAssetPath(path string) bool {
	if strings.HasPrefix(path, "/_waf/") {
		return true
	}
	lower := strings.ToLower(path)
	for _, ext := range assetExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
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
