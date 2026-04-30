package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"git.omada.cafe/atf/waf/internal/config"
	"git.omada.cafe/atf/waf/internal/policy"
	"git.omada.cafe/atf/waf/internal/token"
)

// Session is the challenge gate.  For each request it:
//
//  1. Passes exempt paths and hosts directly to the inner handler.
//  2. Consults the policy engine — if the policy says "none", passes through
//     without issuing or validating a token.
//  3. Validates an existing WAF token; if valid, refreshes it and passes through.
//  4. If the policy engine specifies a challenge type, annotates the request
//     with X-WAF-Policy-Challenge so the dispatcher can honour it.
//  5. Dispatches to the challenge handler.
type Session struct {
	inner     http.Handler
	challenge http.Handler
	tokens    *token.Manager
	cfg       *config.Config
	policy    *policy.Engine // may be nil when no policies are configured
	log       *slog.Logger
}

func NewSession(
	inner, challenge http.Handler,
	tokens *token.Manager,
	cfg *config.Config,
	pol *policy.Engine,
	log *slog.Logger,
) *Session {
	return &Session{
		inner:     inner,
		challenge: challenge,
		tokens:    tokens,
		cfg:       cfg,
		policy:    pol,
		log:       log,
	}
}

func (s *Session) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	host := r.Host
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}

	// ── Exempt paths and hosts (challenge endpoints, well-known, etc.) ────
	if s.cfg.IsExemptPath(path) || s.cfg.IsExemptHost(host) {
		s.inner.ServeHTTP(w, r)
		return
	}

	// ── Policy engine ────────────────────────────────────────────────────
	var policyChallenge string
	if s.policy != nil {
		if action, matched := s.policy.Match(r); matched {
			if action.SkipChallenge {
				// Policy explicitly says no challenge for this host/path.
				s.inner.ServeHTTP(w, r)
				return
			}
			if action.Challenge != "" {
				// Annotate so the dispatcher sends the right challenge type.
				policyChallenge = action.Challenge
				r = r.Clone(r.Context())
				r.Header.Set("X-WAF-Policy-Challenge", policyChallenge)
			}
		}
	}

	// ── Token validation ─────────────────────────────────────────────────
	ip := extractIP(r)
	if cookie, err := r.Cookie(token.CookieName()); err == nil && cookie.Value != "" {
		if s.tokens.Validate(cookie.Value, ip) {
			// Valid token: refresh sliding window and serve.
			newTok := s.tokens.Issue(ip)
			secure := r.Header.Get("X-Forwarded-Proto") == "https"
			w.Header().Set("Set-Cookie", token.CookieHeader(newTok, s.tokens.TTL(), secure))

			// If the policy demands a harder challenge than the existing token
			// represents, escalate only when the policy specifically requires
			// scrypt and we have a non-scrypt token.  In practice, this is
			// enforced by the reputation escalation path; policy-based forced
			// re-challenge would need token metadata we don't store.
			// For now, an existing valid token always passes — policy "scrypt"
			// means "use scrypt for *new* challenges", not "revoke existing tokens".
			s.inner.ServeHTTP(w, r)
			return
		}
	}

	s.log.Debug("session: no valid token — dispatching challenge",
		"ip", ip, "path", path, "policy_challenge", policyChallenge)
	s.challenge.ServeHTTP(w, r)
}
