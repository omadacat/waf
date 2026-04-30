// Package errorpage serves HTML error pages with unique request IDs.
//
// There are two entry points:
//
//   - Write(w, status) — static page, no ID (used for proxy errors: 502/503/504)
//   - WriteBlock(w, status, ip, reason, log) — injects a unique request ID,
//     logs the block event, so operators can correlate user reports to log lines.
package errorpage

import (
	_ "embed"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

//go:embed 403.html
var page403 string

//go:embed 429.html
var page429 string

//go:embed 502.html
var page502 string

//go:embed 503.html
var page503 string

//go:embed 504.html
var page504 string

var pages = map[int]string{
	http.StatusForbidden:          page403,
	http.StatusTooManyRequests:    page429,
	http.StatusBadGateway:         page502,
	http.StatusServiceUnavailable: page503,
	http.StatusGatewayTimeout:     page504,
}

// Write sends an error page without a request ID.
// Use for proxy-level errors (502, 503, 504) where there is no meaningful
// block event to correlate.
func Write(w http.ResponseWriter, status int) {
	page, ok := pages[status]
	if !ok {
		http.Error(w, fmt.Sprintf("%d %s", status, http.StatusText(status)), status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// Strip the placeholder so it doesn't appear as literal text.
	fmt.Fprint(w, strings.ReplaceAll(page, "{{REQUEST_ID}}", ""))
}

// WriteBlock sends an error page with a unique request ID injected.
// The ID is logged alongside ip and reason so operators can look it up
// when a user reports being blocked.
//
//	"I got a 403. My request ID is a3f8c21d."
//	→ grep '"request_id":"a3f8c21d"' /var/log/waf/waf.log
func WriteBlock(w http.ResponseWriter, status int, ip, reason string, log *slog.Logger) {
	id := newID()
	if log != nil {
		log.Info("block",
			"status", status,
			"ip", ip,
			"reason", reason,
			"request_id", id,
		)
	}
	page, ok := pages[status]
	if !ok {
		http.Error(w, fmt.Sprintf("%d %s — request ID: %s", status, http.StatusText(status), id), status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprint(w, strings.ReplaceAll(page, "{{REQUEST_ID}}", id))
}

func newID() string {
	b := make([]byte, 6) // 12 hex chars — long enough to be unique, short enough to read aloud
	rand.Read(b)
	return hex.EncodeToString(b)
}
