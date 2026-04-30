package challenges

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/store"
	"git.omada.cafe/atf/waf/internal/token"
)

// MouseEvent is a single mouse movement sample (x, y, timestamp).
type MouseEvent struct {
	X int `json:"x"`
	Y int `json:"y"`
	T int `json:"t"`
}

// KeyEvent is a single keypress timing sample (no key value stored).
type KeyEvent struct {
	T int `json:"t"`
}

// TimingData holds Navigation Timing API values from the browser.
type TimingData struct {
	NavigationStart int64 `json:"navigationStart"`
	LoadEventEnd    int64 `json:"loadEventEnd"`
}

// FingerprintData is the JSON payload POSTed by the challenge page.
type FingerprintData struct {
	UserAgent      string            `json:"ua"`
	Platform       string            `json:"platform"`
	Languages      []string          `json:"languages"`
	ScreenRes      string            `json:"screen"`
	Timezone       string            `json:"timezone"`
	Plugins        []string          `json:"plugins"`
	Canvas         string            `json:"canvas"`
	WebGL          string            `json:"webgl"`
	Fonts          []string          `json:"fonts"`
	TouchSupport   bool              `json:"touch"`
	DoNotTrack     bool              `json:"dnt"`
	Headers        map[string]string `json:"headers"`
	MouseMovements []MouseEvent      `json:"mouse"`
	KeyEvents      []KeyEvent        `json:"keys"`
	Timing         TimingData        `json:"timing"`
}

type FingerprintHandler struct {
	store    *store.Store
	tokenMgr *token.Manager
	nonceTTL time.Duration
	basePath string
	log      *slog.Logger
}

func NewFingerprintHandler(s *store.Store, tm *token.Manager, nonceTTL time.Duration, basePath string, log *slog.Logger) *FingerprintHandler {
	return &FingerprintHandler{
		store:    s,
		tokenMgr: tm,
		nonceTTL: nonceTTL,
		basePath: strings.TrimRight(basePath, "/"),
		log:      log,
	}
}

func (h *FingerprintHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.serve(w, r)
	case http.MethodPost:
		h.verify(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *FingerprintHandler) serve(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	nonce := randomHexStr(16)
	ip := extractClientIP(r)
	h.store.Set("fp:"+nonce, ip, h.nonceTTL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	mustTemplate("fingerprint.html", tmplFingerprint).Execute(w, map[string]string{
		"Host":     cleanHost(r),
		"BasePath": h.basePath,
		"Nonce":    nonce,
		"Redirect": redirect,
	})
	h.log.Debug("fingerprint: challenge served", "ip", ip)
}

func (h *FingerprintHandler) verify(w http.ResponseWriter, r *http.Request) {
	var fp FingerprintData
	if err := json.NewDecoder(r.Body).Decode(&fp); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ip := extractClientIP(r)
	score := h.scoreFingerprint(&fp)

	if score < 50 {
		h.log.Warn("fingerprint: low score — blocking", "ip", ip, "score", score)
		errorpage.Write(w, http.StatusForbidden)
		return
	}

	tok := h.tokenMgr.Issue(ip)
	secure := r.Header.Get("X-Forwarded-Proto") == "https"
	w.Header().Set("Set-Cookie", token.CookieHeader(tok, h.tokenMgr.TTL(), secure))
	h.log.Info("fingerprint: challenge passed — token issued", "ip", ip, "score", score)
	w.WriteHeader(http.StatusOK)
}

func (h *FingerprintHandler) scoreFingerprint(fp *FingerprintData) int {
	score := 100

	// ── HTTP header signals ───────────────────────────────────────────────
	if fp.Headers["accept-language"] == "" {
		score -= 20 // increased: every real browser sends this
	}
	if fp.Headers["accept-encoding"] == "" {
		score -= 15 // increased: all browsers compress
	}

	// ── Browser capability signals ────────────────────────────────────────
	if len(fp.Plugins) == 0 {
		score -= 10 // mild: modern Chrome reports no plugins via Plugin API
	}
	if fp.Canvas == "" {
		score -= 20 // no canvas = almost certainly not a real browser
	}
	if fp.WebGL == "" {
		score -= 15 // headless browsers often lack WebGL
	}
	if len(fp.Fonts) < 3 {
		score -= 10 // real browsers can enumerate at least a handful of fonts
	}
	if fp.Platform == "" {
		score -= 15 // navigator.platform is always set in real browsers
	}
	if len(fp.Languages) == 0 {
		score -= 15 // navigator.languages always non-empty in real browsers
	}

	// ── Behavioural signals ───────────────────────────────────────────────
	if len(fp.MouseMovements) == 0 {
		score -= 25 // strongest single signal: bots never move the mouse
	} else if len(fp.MouseMovements) < 3 {
		score -= 10 // too few movements to be organic
	} else {
		// Check that movements aren't perfectly linear (scripted).
		if mouseIsLinear(fp.MouseMovements) {
			score -= 15
		}
	}
	if len(fp.KeyEvents) == 0 && len(fp.MouseMovements) < 5 {
		// No keyboard OR very few mouse events = likely automated.
		score -= 10
	}

	// ── Navigation timing ─────────────────────────────────────────────────
	if fp.Timing.NavigationStart > 0 {
		elapsed := fp.Timing.LoadEventEnd - fp.Timing.NavigationStart
		if elapsed > 0 && elapsed < 300 {
			// Page rendered in under 300 ms — suspiciously fast even for a
			// local server; real browsers need time to parse and paint.
			score -= 20
		} else if elapsed <= 0 {
			// loadEventEnd before navigationStart is impossible in a real browser.
			score -= 20
		}
	}

	// ── Screen sanity ─────────────────────────────────────────────────────
	if fp.ScreenRes == "" || fp.ScreenRes == "0x0" {
		score -= 15
	}

	return score
}

// mouseIsLinear returns true if all mouse movements lie on a single straight
// line — a sign of scripted / replay-based fingerprint spoofing.
func mouseIsLinear(events []MouseEvent) bool {
	if len(events) < 3 {
		return false
	}
	// Use the first and last point to define the line; check all middle points.
	x0, y0 := events[0].X, events[0].Y
	xN, yN := events[len(events)-1].X, events[len(events)-1].Y
	dx := xN - x0
	dy := yN - y0
	if dx == 0 && dy == 0 {
		return true // cursor didn't move at all
	}
	for _, e := range events[1 : len(events)-1] {
		// Cross-product of (dx,dy) and (e.X-x0, e.Y-y0) should be non-zero
		// for an organic path. We allow ±2 pixel tolerance.
		cross := dx*(e.Y-y0) - dy*(e.X-x0)
		if cross < -2 || cross > 2 {
			return false // genuinely non-linear
		}
	}
	return true
}
