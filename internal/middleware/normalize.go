package middleware

import (
	"net/http"
	"path"
	"strings"
	"unicode/utf8"
)

type PathNormalizer struct {
	next    http.Handler
	exempt  string // basePath prefix to never rewrite
}

func NewPathNormalizer(next http.Handler, exemptPrefix string) *PathNormalizer {
	return &PathNormalizer{next: next, exempt: exemptPrefix}
}

func (pn *PathNormalizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path

	// Reject non-UTF-8 paths immediately, no legitimate client should send these
	if !utf8.ValidString(p) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Reject null bytes and bare control characters
	if strings.ContainsAny(p, "\x00\r\n") {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Reject encoded traversal sequences (case-insensitive)
	lp := strings.ToLower(p)
	for _, bad := range []string{
		"%2e%2e", // ..
		"%252e",  // double-encoded .
		"%c0%ae", // overlong UTF-8 .
		"%2f",    // encoded /
		"%5c",    // encoded backslash
		"%00",    // null byte
		"%0a",    // newline
		"%0d",    // carriage return
	} {
		if strings.Contains(lp, bad) {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
	}

	// Reject raw backslashes
	if strings.ContainsRune(p, '\\') {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Resolve dot-segments (/../, /./) using path.Clean.
	// Skip /_waf/* so challenge redirects never get mangled.
	if !strings.HasPrefix(p, pn.exempt) {
		clean := path.Clean(p)
		if !strings.HasPrefix(clean, "/") {
			clean = "/" + clean
		}
		// If Clean changed the path, redirect to the canonical form.
		// This turns /foo/../bar into /bar (302) rather than silently rewriting,
		// which is both safer and more cache-friendly.
		if clean != p {
			q := r.URL.RawQuery
			target := clean
			if q != "" {
				target += "?" + q
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
	}

	pn.next.ServeHTTP(w, r)
}
