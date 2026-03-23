package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"git.omada.cafe/atf/waf/internal/config"
	"git.omada.cafe/atf/waf/internal/token"
)

type Session struct {
	inner     http.Handler
	challenge http.Handler
	tokens    *token.Manager
	cfg       *config.Config
	log       *slog.Logger
}

func NewSession(inner, challenge http.Handler, tokens *token.Manager, cfg *config.Config, log *slog.Logger) *Session {
	return &Session{inner: inner, challenge: challenge, tokens: tokens, cfg: cfg, log: log}
}

func (s *Session) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	host := r.Host
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	if s.cfg.IsExemptPath(path) || s.cfg.IsExemptHost(host) {
		s.inner.ServeHTTP(w, r)
		return
	}
	ip := extractIP(r)
	if cookie, err := r.Cookie(token.CookieName()); err == nil && cookie.Value != "" {
		if s.tokens.Validate(cookie.Value, ip) {
			newTok := s.tokens.Issue(ip)
			secure := r.Header.Get("X-Forwarded-Proto") == "https"
			w.Header().Set("Set-Cookie", token.CookieHeader(newTok, s.tokens.TTL(), secure))
			s.inner.ServeHTTP(w, r)
			return
		}
	}
	s.log.Debug("session: no valid token — dispatching challenge", "ip", ip, "path", path)
	s.challenge.ServeHTTP(w, r)
}
