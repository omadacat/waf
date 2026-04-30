package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// Allowlist is the outermost middleware — checked before anything else.
// Matching IPs bypass all challenges, WAF rules, rate limits, and reputation
// checks.  Use for monitoring probes, CDN health checks, and your own IPs.
type Allowlist struct {
	next   http.Handler
	nets   []*net.IPNet
	log    *slog.Logger
}

// NewAllowlist parses cidrs and wraps next.
// If enabled is false or cidrs is empty, next is returned unwrapped.
func NewAllowlist(next http.Handler, enabled bool, cidrs []string, log *slog.Logger) http.Handler {
	if !enabled || len(cidrs) == 0 {
		return next
	}
	al := &Allowlist{next: next, log: log}
	for _, cidr := range cidrs {
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warn("allowlist: invalid CIDR — skipping", "cidr", cidr, "err", err)
			continue
		}
		al.nets = append(al.nets, ipnet)
	}
	if len(al.nets) == 0 {
		return next
	}
	log.Info("allowlist: active", "entries", len(al.nets))
	return al
}

func (al *Allowlist) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := net.ParseIP(extractIP(r))
	if ip != nil {
		for _, n := range al.nets {
			if n.Contains(ip) {
				al.log.Debug("allowlist: bypass", "ip", ip)
				al.next.ServeHTTP(w, r)
				return
			}
		}
	}
	al.next.ServeHTTP(w, r)
}
