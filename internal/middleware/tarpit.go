package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// Tarpit delays responses for IPs that carry the X-WAF-Scraper-Score annotation,
// which the scraper detector sets when an IP crosses the challenge threshold but
// hasn't yet reached the ban threshold.
//
// Why tarpit instead of immediately banning:
//   - A banned IP gets an instant 429 and can immediately retry from a new IP.
//   - A tarpitted IP receives a normal response, but after a 2–10 second wait.
//     Its scraping threads block for the duration, reducing effective throughput
//     by 20–100x without triggering retry logic.
//   - Residential proxy scrapers (which rotate IPs) are forced to hold a
//     connection open on every single request, exhausting their pool.
//
// The delay scales with the scraper score:
//   - Score 80–119  → 2s delay (mild suspicion)
//   - Score 120+    → 8s delay (strong suspicion)
//
// Only applies to IPs that are in the challenge zone, not the ban zone.
// Once the ban threshold is hit, the scraper or rate-limit middleware bans
// them outright and the tarpit is bypassed.
type Tarpit struct {
	next    http.Handler
	enabled bool
	log     *slog.Logger
}

func NewTarpit(next http.Handler, enabled bool, log *slog.Logger) *Tarpit {
	return &Tarpit{next: next, enabled: enabled, log: log}
}

func (t *Tarpit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !t.enabled {
		t.next.ServeHTTP(w, r)
		return
	}

	scraperScore := parseIntHeader(r.Header.Get("X-WAF-Scraper-Score"))
	if scraperScore <= 0 {
		t.next.ServeHTTP(w, r)
		return
	}

	delay := t.delayFor(scraperScore)
	if delay > 0 {
		ip := extractIP(r)
		t.log.Debug("tarpit: delaying response",
			"ip", ip,
			"score", scraperScore,
			"delay", delay,
			"path", r.URL.Path,
		)

		// Sleep without holding a goroutine busy the whole time.
		// We still hold the connection (that's the point), but we can
		// respond to context cancellation if the client gives up.
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}

	t.next.ServeHTTP(w, r)
}

func (t *Tarpit) delayFor(score int) time.Duration {
	switch {
	case score >= 120:
		return 8 * time.Second
	case score >= 80:
		return 2 * time.Second
	default:
		return 0
	}
}

func parseIntHeader(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
