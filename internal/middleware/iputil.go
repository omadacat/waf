package middleware

import (
	"net/http"
	"strings"
)

// extractIP returns the real client IP, normalising loopback variants so local development works consistently regardless of IPv4/IPv6.
func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return normaliseLoopback(strings.TrimSpace(parts[0]))
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return normaliseLoopback(xri)
	}
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i != -1 {
		addr = addr[:i]
	}
	addr = strings.TrimPrefix(addr, "[")
	addr = strings.TrimSuffix(addr, "]")
	return normaliseLoopback(addr)
}

func normaliseLoopback(ip string) string {
	if ip == "::1" || ip == "0:0:0:0:0:0:0:1" {
		return "127.0.0.1"
	}
	return ip
}
