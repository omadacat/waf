package dnsbl

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// DefaultZones is a conservative set of public DNSBLs.
// All are freely queryable without registration for reasonable query volumes.
var DefaultZones = []string{
	"zen.spamhaus.org",    // combined Spamhaus blocklist (SBL + XBL + PBL)
	"dnsbl.dronebl.org",   // DroneBL — botnets and DDoS sources
}

// Result holds the outcome of a DNSBL check for one IP.
type Result struct {
	Listed  bool
	Zones   []string  // which zones returned a hit
	Checked time.Time
}

// Penalty returns the reputation penalty for this result.
// Returns 0 for unlisted IPs.
func (r Result) Penalty() float64 {
	if !r.Listed {
		return 0
	}
	// 30 points per zone hit, up to 60.
	p := float64(len(r.Zones)) * 30
	if p > 60 {
		p = 60
	}
	return p
}

// Checker runs DNSBL lookups asynchronously and caches results.
type Checker struct {
	zones   []string
	ttl     time.Duration
	mu      sync.RWMutex
	cache   map[string]Result
	pending map[string]bool // IPs currently being looked up
	log     *slog.Logger
}

// New creates a Checker.  If zones is empty, DefaultZones are used.
// ttl controls how long results are cached before a new lookup is attempted.
func New(zones []string, ttl time.Duration, log *slog.Logger) *Checker {
	if len(zones) == 0 {
		zones = DefaultZones
	}
	if ttl <= 0 {
		ttl = 4 * time.Hour
	}
	return &Checker{
		zones:   zones,
		ttl:     ttl,
		cache:   make(map[string]Result),
		pending: make(map[string]bool),
		log:     log,
	}
}

// Check returns the cached DNSBL result for ip. If no cached result exists or it has expired, a background lookup is started and (Result{}, false) is returned immediately
// the caller should not block on the first request from a new IP.
//
// The second return value is true when a cached result was found.
func (c *Checker) Check(ip string) (Result, bool) {
	if !isRoutableIPv4(ip) {
		return Result{}, true // skip private/loopback addresses
	}

	c.mu.RLock()
	r, ok := c.cache[ip]
	c.mu.RUnlock()

	if ok && time.Since(r.Checked) < c.ttl {
		return r, true
	}

	// Cache miss or expired — start async lookup if not already in flight.
	c.mu.Lock()
	if !c.pending[ip] {
		c.pending[ip] = true
		go c.lookup(ip)
	}
	c.mu.Unlock()

	return Result{}, false
}

// lookup performs the actual DNS queries synchronously in a goroutine.
func (c *Checker) lookup(ip string) {
	reversed := reverseIP(ip)
	if reversed == "" {
		c.mu.Lock()
		delete(c.pending, ip)
		c.mu.Unlock()
		return
	}

	var hits []string
	for _, zone := range c.zones {
		host := reversed + "." + zone
		addrs, err := net.LookupHost(host)
		if err == nil && len(addrs) > 0 {
			hits = append(hits, zone)
		}
	}

	result := Result{
		Listed:  len(hits) > 0,
		Zones:   hits,
		Checked: time.Now(),
	}

	c.mu.Lock()
	c.cache[ip] = result
	delete(c.pending, ip)
	c.mu.Unlock()

	if result.Listed {
		c.log.Info("dnsbl: IP listed",
			"ip", ip,
			"zones", strings.Join(hits, ","),
			"penalty", result.Penalty(),
		)
	} else {
		c.log.Debug("dnsbl: IP clean", "ip", ip)
	}
}

// reverseIP returns the dotted-decimal octets of an IPv4 address reversed.
// Returns "" if ip is not a valid IPv4 address.
func reverseIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	v4 := ip.To4()
	if v4 == nil {
		return "" // IPv6 DNSBL format is different; skip for now
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}

// isRoutableIPv4 returns false for private, loopback, and link-local addresses
// that should never appear in public DNSBLs.
func isRoutableIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	v4 := ip.To4()
	return v4 != nil
}
