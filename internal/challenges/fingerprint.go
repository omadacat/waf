package challenges

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/store"
	"git.omada.cafe/atf/waf/internal/token"
)

//go:embed templates/fingerprint.html
var fingerprintTemplate string

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
	tmpl     *template.Template
}

func NewFingerprintHandler(s *store.Store, tm *token.Manager, nonceTTL time.Duration, basePath string, log *slog.Logger) *FingerprintHandler {
	tmpl := template.Must(template.New("fp").Parse(fingerprintTemplate))
	return &FingerprintHandler{
		store:    s,
		tokenMgr: tm,
		nonceTTL: nonceTTL,
		basePath: strings.TrimRight(basePath, "/"),
		log:      log,
		tmpl:     tmpl,
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
	h.tmpl.Execute(w, map[string]string{
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

	if fp.Headers["accept-language"] == "" {
		score -= 15
	}
	if fp.Headers["accept-encoding"] == "" {
		score -= 10
	}
	if len(fp.Plugins) == 0 {
		score -= 20
	}
	if fp.Canvas == "" {
		score -= 15
	}
	if len(fp.MouseMovements) == 0 {
		score -= 20
	}
	if fp.Timing.NavigationStart > 0 {
		elapsed := fp.Timing.LoadEventEnd - fp.Timing.NavigationStart
		if elapsed > 0 && elapsed < 50 {
			score -= 10 // suspiciously fast
		}
	}

	return score
}
