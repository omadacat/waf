package middleware

import (
	"log/slog"
	"net/http"

	"git.omada.cafe/atf/waf/internal/token"
)

type TokenValidator struct {
	next    http.Handler
	manager *token.Manager
	log     *slog.Logger
	exempt  func(*http.Request) bool
}

func NewTokenValidator(next http.Handler, manager *token.Manager, log *slog.Logger, exempt func(*http.Request) bool) *TokenValidator {
	return &TokenValidator{next: next, manager: manager, log: log, exempt: exempt}
}

func (tv *TokenValidator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if tv.exempt != nil && tv.exempt(r) {
		tv.next.ServeHTTP(w, r)
		return
	}
	cookie, err := r.Cookie(token.CookieName())
	if err == nil && tv.manager.Validate(cookie.Value, extractIP(r)) {
		tv.next.ServeHTTP(w, r)
		return
	}
	tv.next.ServeHTTP(w, r)
}
