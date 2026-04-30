package challenges

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/store"
	"git.omada.cafe/atf/waf/internal/token"
)

type JSHandler struct {
	store      *store.Store
	tokenMgr   *token.Manager
	nonceTTL   time.Duration
	difficulty int
	basePath   string
	log        *slog.Logger
}

func NewJSHandler(s *store.Store, tm *token.Manager, nonceTTL time.Duration, difficulty int, basePath string, log *slog.Logger) *JSHandler {
	return &JSHandler{
		store:      s,
		tokenMgr:   tm,
		nonceTTL:   nonceTTL,
		difficulty: difficulty,
		basePath:   strings.TrimRight(basePath, "/"),
		log:        log,
	}
}

func (h *JSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.serve(w, r)
	case http.MethodPost:
		h.verify(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// jsTemplateData is passed to templates/js_pow.html.
// String fields in <script> context are automatically JSON-encoded by
// html/template so no manual escaping is needed.
type jsTemplateData struct {
	Host        string // actual hostname the visitor navigated to
	BasePath    string
	Nonce       string
	Difficulty  int
	Redirect    string
	RedirectEnc string // percent-encoded for use in href= attributes
}

func (h *JSHandler) serve(w http.ResponseWriter, r *http.Request) {
	ip := extractClientIP(r)
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	nonce := randomHexStr(16)
	h.store.Set("js:"+nonce, ip, h.nonceTTL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	data := jsTemplateData{
		Host:        cleanHost(r),
		BasePath:    h.basePath,
		Nonce:       nonce,
		Difficulty:  h.difficulty,
		Redirect:    redirect,
		RedirectEnc: urlPercentEncode(redirect),
	}
	if err := mustTemplate("js_pow.html", tmplJS).Execute(w, data); err != nil {
		h.log.Error("js: template execute error", "err", err)
	}
	h.log.Debug("js: challenge served", "ip", ip)
}

func (h *JSHandler) verify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	nonce := r.FormValue("nonce")
	answer := r.FormValue("answer")
	redirect := r.FormValue("redirect")
	if redirect == "" {
		redirect = "/"
	}
	ip := extractClientIP(r)

	storedIP, ok := h.store.Get("js:" + nonce)
	if !ok {
		http.Error(w, "Challenge expired — reload", http.StatusBadRequest)
		return
	}
	if storedIP.(string) != ip {
		errorpage.Write(w, http.StatusForbidden)
		return
	}
	h.store.Delete("js:" + nonce)

	// Reject solutions that arrived suspiciously fast.
	// No real browser can render the page, spin up workers, and solve
	// difficulty=20 in under 300 ms.  Bots that solve instantly are caught here.
	if elapsedStr := r.FormValue("elapsedTime"); elapsedStr != "" {
		if ms, err := strconv.ParseInt(elapsedStr, 10, 64); err == nil && ms < 300 {
			h.log.Warn("js: solution too fast — likely bot", "ip", ip, "elapsed_ms", ms)
			errorpage.Write(w, http.StatusForbidden)
			return
		} else if err == nil {
			h.log.Debug("js: solution timing", "ip", ip, "elapsed_ms", ms)
		}
	}

	hash := sha256Sum([]byte(nonce + answer))
	if !meetsHashDifficulty(hash[:], h.difficulty) {
		h.log.Warn("js: invalid solution", "ip", ip)
		errorpage.Write(w, http.StatusForbidden)
		return
	}

	tok := h.tokenMgr.Issue(ip)
	secure := r.Header.Get("X-Forwarded-Proto") == "https"
	w.Header().Set("Set-Cookie", token.CookieHeader(tok, h.tokenMgr.TTL(), secure))
	h.log.Info("js: challenge passed — token issued", "ip", ip)
	http.Redirect(w, r, redirect, http.StatusFound)
}
