package challenges

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"strings"
)

func randomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomHexStr(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func meetsHashDifficulty(data []byte, bits int) bool {
	if bits <= 0 {
		return true
	}
	n := new(big.Int).SetBytes(data)
	threshold := new(big.Int).Lsh(big.NewInt(1), uint(len(data)*8-bits))
	return n.Cmp(threshold) < 0
}

// extractClientIP returns the real client IP. When running behind Nginx, X-Forwarded-For is set to $remote_addr.
// When running directly (local dev), RemoteAddr is used and normalised: IPv6 loopback "::1" is mapped to "127.0.0.1" so IP-binding works consistently regardless of whether the listener uses IPv4 or IPv6.
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		return normaliseLoopback(ip)
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

// normaliseLoopback maps all loopback variants to "127.0.0.1" so that the IP stored and the IP on the verify request always match, even when the host switches between IPv4 and IPv6 loopback.
func normaliseLoopback(ip string) string {
	if ip == "::1" || ip == "0:0:0:0:0:0:0:1" {
		return "127.0.0.1"
	}
	return ip
}

func urlPercentEncode(s string) string {
	var sb strings.Builder
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
			c == '~' || c == '/' || c == '?' || c == '=' || c == '&' || c == '#' {
			sb.WriteRune(c)
		} else {
			sb.WriteString("%" + hex.EncodeToString([]byte(string(c))))
		}
	}
	return sb.String()
}

// sha256Sum is a thin wrapper around crypto/sha256.Sum256.
// It lets challenge handlers avoid importing crypto/sha256 directly.
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// cleanHost returns the hostname from a request, stripping the port number.
// Used to populate {{.Host}} in challenge templates so the page header
// shows the domain the visitor actually navigated to rather than a hardcoded value.
func cleanHost(r *http.Request) string {
	host := r.Host
	if host == "" {
		return "unknown"
	}
	// Strip port: be careful not to strip the port from bare IPv6 addresses ([::1]).
	if last := strings.LastIndex(host, ":"); last > 0 {
		if !strings.Contains(host[:last], ":") { // IPv4 or hostname, not IPv6
			return host[:last]
		}
	}
	return host
}
