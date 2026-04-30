package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"git.omada.cafe/atf/waf/internal/bans"
	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/reputation"
)

// Reputation is the outermost middleware.  It sits before every other layer
// so its response-writer wrapper observes all upstream 403/429 decisions.
//
// On each request it:
//  1. Resolves the JA4 fingerprint (header or native listener).
//  2. Queries the reputation store for the combined group score
//     (subnet /24, JA4 fingerprint, ASN if DB is configured).
//  3. If score ≥ ban_threshold → bans the IP and returns 403 immediately.
//     This is the only action taken against IPs that hold a valid token;
//     a high-enough score indicates the entire group is hostile.
//  4. If score ≥ challenge_threshold → annotates the request with
//     X-WAF-Rep-Score so the challenge dispatcher can escalate to a harder
//     challenge type (scrypt).  The existing token is NOT revoked: revoking
//     a valid token on every request creates an unresolvable redirect loop
//     for any legitimate user whose /24 shares space with bots.
//  5. Wraps the ResponseWriter to intercept 403/429 responses and
//     propagate a penalty back to the IP's groups.
type Reputation struct {
	next   http.Handler
	store  *reputation.Store
	banMgr   *bans.BanManager
	cfg      reputation.Config
	log      *slog.Logger
}

// NewReputation constructs the middleware.
// listener and banMgr may be nil.
func NewReputation(next http.Handler, store *reputation.Store, banMgr *bans.BanManager, cfg reputation.Config, log *slog.Logger) *Reputation {
	return &Reputation{
		next:     next,
		store:    store,
		banMgr:   banMgr,
		cfg:      cfg,
		log:      log,
	}
}

func (rep *Reputation) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !rep.cfg.Enabled {
		rep.next.ServeHTTP(w, r)
		return
	}

	// Strip headers that should only originate from trusted upstream sources.
	// This runs at the outermost layer so every downstream middleware sees a
	// clean request regardless of what the client sent.
	for _, h := range []string{
		"X-Real-Ip",
		"X-Ja4-Hash", "X-Ja4", "X-Waf-Ja4",
		"X-Waf-Rep-Score",
		"X-Ssl-Protocol", "X-Ssl-Cipher",
	} {
		r.Header.Del(h)
	}

	ip := extractIP(r)
	fingerprint := rep.resolveFingerprint(r)
	score := rep.store.GroupScore(ip, fingerprint)

	// ── Pre-emptive ban ───────────────────────────────────────────────────
	// ban_threshold is intentionally high (default 60) so legitimate users
	// in a bad subnet are not caught.  A full ban applies regardless of
	// whether the IP holds a valid token — if a group has accumulated this
	// much damage, we want them gone.
	if score >= rep.cfg.BanThreshold {
		if rep.banMgr != nil {
			rep.banMgr.Ban(ip, "reputation:group_score", rep.cfg.BanDuration, "rep-001", int(score))
		}
		rep.log.Info("reputation: pre-emptive ban",
			"ip", ip, "score", score, "fp", fingerprint)
		errorpage.WriteBlock(w, http.StatusForbidden, ip, "reputation:group_score", rep.log)
		return
	}

	// ── Challenge escalation annotation ───────────────────────────────────
	// When score ≥ challenge_threshold, annotate the request so the
	// challenge dispatcher routes to scrypt instead of JS PoW.
	// We do NOT strip or revoke the existing token: that causes an
	// unresolvable redirect loop (token set → request → token stripped →
	// challenge → token set → ...).  Legitimate users who have already
	// passed a challenge keep their session.  Tokenless requests from
	// flagged subnets are naturally challenged by sessionMW anyway;
	// the annotation only upgrades the challenge difficulty.
	if score >= rep.cfg.ChallengeThreshold {
		r.Header.Set("X-WAF-Rep-Score", fmt.Sprintf("%.0f", score))
		rep.log.Debug("reputation: escalating challenge",
			"ip", ip, "score", score, "fp", fingerprint)
	}

	// ── Reactive penalty recording ─────────────────────────────────────
	rw := &reputationWriter{ResponseWriter: w}
	rep.next.ServeHTTP(rw, r)

	if rw.status == http.StatusForbidden || rw.status == http.StatusTooManyRequests {
		penalty := penaltyForStatus(rw.status)
		rep.store.RecordPenalty(ip, fingerprint, penalty)
		rep.log.Debug("reputation: penalty recorded",
			"ip", ip, "status", rw.status, "penalty", penalty,
			"fp", fingerprint, "subnet", subnetKeyFor(ip))
	}
}

// resolveFingerprint returns the JA4 fingerprint from (in priority order):
//  1. X-JA4-Hash / X-JA4 headers set by an upstream proxy.
//  2. X-WAF-JA4 set by ja3MW further down the chain (already resolved).
//  3. Native listener map when the WAF terminates TLS directly.
func (rep *Reputation) resolveFingerprint(r *http.Request) string {
	for _, hdr := range []string{"X-JA4-Hash", "X-JA4", "X-WAF-JA4"} {
		if h := r.Header.Get(hdr); h != "" {
			return strings.ToLower(strings.TrimSpace(h))
		}
	}
	return ""
}

// ── helpers ───────────────────────────────────────────────────────────────────

func penaltyForStatus(status int) float64 {
	switch status {
	case http.StatusForbidden:
		return 40
	case http.StatusTooManyRequests:
		return 20
	default:
		return 10
	}
}

func subnetKeyFor(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
	}
	return ip
}

// ── reputationWriter ─────────────────────────────────────────────────────────

type reputationWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (rw *reputationWriter) WriteHeader(code int) {
	if !rw.written {
		rw.status = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *reputationWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.status = http.StatusOK
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

func (rw *reputationWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}
