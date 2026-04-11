package challenges

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/store"
	"git.omada.cafe/atf/waf/internal/token"
	"golang.org/x/crypto/scrypt"
)

type ScryptHandler struct {
	store           *store.Store
	tokenMgr        *token.Manager
	nonceTTL        time.Duration
	difficulty      int
	N, r, p, keyLen int
	basePath        string
	log             *slog.Logger
}

func NewScryptHandler(s *store.Store, tm *token.Manager, nonceTTL time.Duration, difficulty, N, r, p, keyLen int, basePath string, log *slog.Logger) *ScryptHandler {
	if N == 0 {
		N = 32768
	}
	if r == 0 {
		r = 8
	}
	if p == 0 {
		p = 1
	}
	if keyLen == 0 {
		keyLen = 32
	}
	return &ScryptHandler{
		store: s, tokenMgr: tm, nonceTTL: nonceTTL,
		difficulty: difficulty, N: N, r: r, p: p, keyLen: keyLen,
		basePath: strings.TrimRight(basePath, "/"), log: log,
	}
}

func (h *ScryptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.serve(w, r)
	case http.MethodPost:
		h.verify(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

type scryptTemplateData struct {
	BasePath    string
	Challenge   string
	Difficulty  int
	Redirect    string
	RedirectEnc string
}

func (h *ScryptHandler) serve(w http.ResponseWriter, r *http.Request) {
	ip := extractClientIP(r)
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	challenge := randomHexStr(32)
	h.store.Set("scrypt:"+challenge, ip, h.nonceTTL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	data := scryptTemplateData{
		BasePath:    h.basePath,
		Challenge:   challenge,
		Difficulty:  h.difficulty,
		Redirect:    redirect,
		RedirectEnc: urlPercentEncode(redirect),
	}
	if err := mustTemplate("scrypt.html", tmplScrypt).Execute(w, data); err != nil {
		h.log.Error("scrypt: template execute error", "err", err)
	}
	h.log.Debug("scrypt: challenge served", "ip", ip)
}

func (h *ScryptHandler) verify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	challenge := r.FormValue("challenge")
	nonce := r.FormValue("nonce")
	redirect := r.FormValue("redirect")
	if redirect == "" {
		redirect = "/"
	}
	ip := extractClientIP(r)

	storedIP, ok := h.store.Get("scrypt:" + challenge)
	if !ok {
		http.Error(w, "Challenge expired — reload", http.StatusBadRequest)
		return
	}
	if storedIP.(string) != ip {
		errorpage.Write(w, http.StatusForbidden)
		return
	}
	h.store.Delete("scrypt:" + challenge)

	key, err := scrypt.Key([]byte(challenge+nonce), []byte("scrypt-v1"), h.N, h.r, h.p, h.keyLen)
	if err != nil {
		h.log.Error("scrypt: key error", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !meetsHashDifficulty(key, h.difficulty) {
		h.log.Warn("scrypt: invalid solution", "ip", ip)
		errorpage.Write(w, http.StatusForbidden)
		return
	}

	tok := h.tokenMgr.Issue(ip)
	secure := r.Header.Get("X-Forwarded-Proto") == "https"
	w.Header().Set("Set-Cookie", token.CookieHeader(tok, h.tokenMgr.TTL(), secure))
	h.log.Info("scrypt: challenge passed — token issued", "ip", ip)
	http.Redirect(w, r, redirect, http.StatusFound)
}
