// Package abuseipdb provides async IP reputation checking via the AbuseIPDB
// v2 API (https://www.abuseipdb.com/api.html).
//
// Like the DNSBL checker, lookups fire in the background on first sight of a
// new IP.  Results are cached and feed into the reputation store as penalties.
// The first request from an unknown IP always passes through — subsequent
// requests carry the penalty.
//
// Free tier: 1 000 lookups/day.  A 24h cache TTL means the same IP only
// costs one lookup regardless of how many times it visits.
//
// To enable, set abuseipdb.api_key in config.yaml.  Without an API key the
// checker is a no-op.
package abuseipdb

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

const apiURL = "https://api.abuseipdb.com/api/v2/check"

// Result holds the outcome of an AbuseIPDB check for one IP.
type Result struct {
	Score       int       // 0-100 abuse confidence score
	ISP         string
	CountryCode string
	TotalReports int
	Checked     time.Time
}

// Penalty returns the reputation penalty for this result.
// Scaled: score 80+ = 60pts, score 50+ = 40pts, score 25+ = 20pts.
func (r Result) Penalty() float64 {
	switch {
	case r.Score >= 80:
		return 60
	case r.Score >= 50:
		return 40
	case r.Score >= 25:
		return 20
	default:
		return 0
	}
}

// Checker runs AbuseIPDB lookups asynchronously and caches results.
type Checker struct {
	apiKey  string
	ttl     time.Duration
	client  *http.Client
	mu      sync.RWMutex
	cache   map[string]Result
	pending map[string]bool
	log     *slog.Logger
}

// New creates a Checker. apiKey may be empty — in that case Check always
// returns (Result{}, true) so callers can skip without a nil check.
func New(apiKey string, ttl time.Duration, log *slog.Logger) *Checker {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Checker{
		apiKey:  apiKey,
		ttl:     ttl,
		client:  &http.Client{Timeout: 5 * time.Second},
		cache:   make(map[string]Result),
		pending: make(map[string]bool),
		log:     log,
	}
}

// Enabled reports whether the checker has an API key configured.
func (c *Checker) Enabled() bool { return c.apiKey != "" }

// Check returns (Result, true) when a cached result is available and fresh.
// Returns (Result{}, false) and starts a background lookup otherwise.
// Callers should only apply the penalty when the second return is true.
func (c *Checker) Check(ip string) (Result, bool) {
	if !c.Enabled() || !isRoutableIPv4(ip) {
		return Result{}, true // no-op
	}

	c.mu.RLock()
	r, ok := c.cache[ip]
	c.mu.RUnlock()

	if ok && time.Since(r.Checked) < c.ttl {
		return r, true
	}

	c.mu.Lock()
	if !c.pending[ip] {
		c.pending[ip] = true
		go c.lookup(ip)
	}
	c.mu.Unlock()

	return Result{}, false
}

func (c *Checker) lookup(ip string) {
	defer func() {
		c.mu.Lock()
		delete(c.pending, ip)
		c.mu.Unlock()
	}()

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return
	}
	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	q.Set("verbose", "")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		c.log.Debug("abuseipdb: lookup failed", "ip", ip, "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		c.log.Warn("abuseipdb: rate limit hit — daily quota exhausted")
		return
	}
	if resp.StatusCode != http.StatusOK {
		c.log.Debug("abuseipdb: unexpected status", "ip", ip, "status", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return
	}

	var payload struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			Isp                  string `json:"isp"`
			CountryCode          string `json:"countryCode"`
			TotalReports         int    `json:"totalReports"`
		} `json:"data"`
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return
	}
	if len(payload.Errors) > 0 {
		c.log.Debug("abuseipdb: API error", "ip", ip, "detail", payload.Errors[0].Detail)
		return
	}

	result := Result{
		Score:        payload.Data.AbuseConfidenceScore,
		ISP:          payload.Data.Isp,
		CountryCode:  payload.Data.CountryCode,
		TotalReports: payload.Data.TotalReports,
		Checked:      time.Now(),
	}

	c.mu.Lock()
	c.cache[ip] = result
	c.mu.Unlock()

	if result.Score >= 25 {
		c.log.Info("abuseipdb: flagged IP",
			"ip", ip,
			"score", result.Score,
			"isp", result.ISP,
			"country", result.CountryCode,
			"reports", result.TotalReports,
			"penalty", fmt.Sprintf("%.0f", result.Penalty()),
		)
	} else {
		c.log.Debug("abuseipdb: clean IP", "ip", ip, "score", result.Score)
	}
}

func isRoutableIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	return ip.To4() != nil
}
