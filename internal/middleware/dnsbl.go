package middleware

import (
	"log/slog"
	"net/http"

	"git.omada.cafe/atf/waf/internal/dnsbl"
	"git.omada.cafe/atf/waf/internal/reputation"
)

// DNSBLGate checks the DNSBL cache for the client IP and feeds any listed
// result into the reputation store as a penalty.  The first request from an
// unknown IP always passes through — the lookup fires asynchronously in the
// background.  Subsequent requests from the same IP carry the penalty.
//
// Sits inside the allowlist so allowlisted IPs are never DNSBL-checked.
type DNSBLGate struct {
	next    http.Handler
	checker *dnsbl.Checker
	store   *reputation.Store
	penalty float64
	log     *slog.Logger
}

func NewDNSBLGate(next http.Handler, checker *dnsbl.Checker, store *reputation.Store, penalty float64, log *slog.Logger) *DNSBLGate {
	if penalty <= 0 {
		penalty = 30
	}
	return &DNSBLGate{next: next, checker: checker, store: store, penalty: penalty, log: log}
}

func (d *DNSBLGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r)
	if result, cached := d.checker.Check(ip); cached && result.Listed {
		// Propagate to reputation store so group scores (subnet, fingerprint)
		// absorb the penalty and flag related IPs.
		penaltyPerZone := d.penalty
		total := float64(len(result.Zones)) * penaltyPerZone
		if total > 0 {
			fp := r.Header.Get("X-WAF-JA4")
			d.store.RecordPenalty(ip, fp, total)
			d.log.Debug("dnsbl gate: penalty applied", "ip", ip, "zones", len(result.Zones), "penalty", total)
		}
	}
	d.next.ServeHTTP(w, r)
}
