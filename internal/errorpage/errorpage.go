// Package errorpage serves pre-built HTML error pages for block responses.
//
// Pages are embedded directly into the binary at compile time using go:embed, so no external files are needed at runtime.
//
// Usage - replace bare http.Error calls with:
//
//	errorpage.Write(w, http.StatusForbidden)
//	errorpage.Write(w, http.StatusTooManyRequests)
//	errorpage.Write(w, http.StatusBadGateway)
package errorpage

import (
	_ "embed"
	"fmt"
	"net/http"
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

// Write sends the appropriate error page for status.
// Falls back to plain text if no custom page exists for that code.
func Write(w http.ResponseWriter, status int) {
	page, ok := pages[status]
	if !ok {
		http.Error(w, fmt.Sprintf("%d %s", status, http.StatusText(status)), status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprint(w, page)
}
