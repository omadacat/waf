package middleware

import (
	"log/slog"
	"net/http"

	"git.omada.cafe/atf/waf/internal/challenges"
)

// ChallengeGate delegates unauthenticated requests to the challenges.Dispatcher.
// It is a thin wrapper so the middleware package doesn't need to know about challenge internals.
type ChallengeGate struct {
	next       http.Handler
	dispatcher *challenges.Dispatcher
	log        *slog.Logger
}

func NewChallengeGate(next http.Handler, d *challenges.Dispatcher, log *slog.Logger) *ChallengeGate {
	return &ChallengeGate{next: next, dispatcher: d, log: log}
}

func (cg *ChallengeGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cg.dispatcher.Dispatch(w, r)
}
