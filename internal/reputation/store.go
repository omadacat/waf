// Package reputation tracks per-group (subnet, fingerprint, ASN) threat
// scores derived from observed bad behaviour.  When any middleware bans or
// challenges an IP, the penalty propagates — at configurable weights — to
// the IP's /24 subnet, JA4 fingerprint, and ASN groups.
//
// New IPs that share a high-scoring group inherit a suspicion score before
// they do anything wrong, enabling pre-emptive challenges against known
// bot fleets that rotate residential proxies.
//
// Scores decay exponentially with a configurable half-life so that
// well-behaved traffic from a previously flagged subnet eventually
// recovers to clean standing.
package reputation

import (
	"encoding/json"
	"math"
	"os"
	"sync"
	"time"
)

// Config controls reputation scoring behaviour.
type Config struct {
	Enabled             bool
	PersistFile         string
	ASNDBPath           string
	SubnetPropagation      float64
	FingerprintPropagation float64
	ASNPropagation         float64
	ChallengeThreshold  float64
	BanThreshold        float64
	BanDuration         time.Duration
	HalfLife            time.Duration
}

// groupEntry is the persistent state for a single group key.
type groupEntry struct {
	// RawScore is the score as of LastUpdated, before decay.
	RawScore    float64   `json:"raw_score"`
	Hits        int       `json:"hits"`
	Bans        int       `json:"bans"`
	LastUpdated time.Time `json:"last_updated"`
}

// currentScore applies exponential decay and returns the effective score now.
func (e *groupEntry) currentScore(halfLife time.Duration) float64 {
	if halfLife <= 0 || e.RawScore <= 0 {
		return e.RawScore
	}
	elapsed := time.Since(e.LastUpdated)
	if elapsed <= 0 {
		return e.RawScore
	}
	halvings := float64(elapsed) / float64(halfLife)
	return e.RawScore * math.Pow(0.5, halvings)
}

// Store holds group reputation scores indexed by a string key that encodes the group type and identity:
//
//	"1.2.3.0/24"       -> IPv4 /24 subnet
//	"2001:db8::/48"    -> IPv6 /48 subnet
//	"AS15169"          -> Autonomous System Number
//	"fp:t13d..."       -> JA4 fingerprint
type Store struct {
	mu     sync.RWMutex
	groups map[string]*groupEntry
	cfg    Config
	asn    *ASNLookup
}

// New creates a Store, loading any previously persisted state from cfg.PersistFile. It opens the ASN database if cfg.ASNDBPath is set.
func New(cfg Config) (*Store, error) {
	asn, err := NewASNLookup(cfg.ASNDBPath)
	if err != nil {
		return nil, err
	}
	s := &Store{
		groups: make(map[string]*groupEntry),
		cfg:    cfg,
		asn:    asn,
	}
	if cfg.PersistFile != "" {
		_ = s.load() // missing file is fine on first start
	}
	go s.cleanupLoop()
	return s, nil
}

// GroupScore returns the combined, decayed group score for ip using the given JA4 fingerprint.
// The score is the maximum across all groups the IP belongs to (subnet, fingerprint, ASN).
func (s *Store) GroupScore(ip, fingerprint string) float64 {
	hl := s.halfLife()
	s.mu.RLock()
	defer s.mu.RUnlock()

	var max float64
	for _, key := range s.keysFor(ip, fingerprint) {
		if key == "" {
			continue
		}
		if e, ok := s.groups[key]; ok {
			if score := e.currentScore(hl); score > max {
				max = score
			}
		}
	}
	return max
}

// RecordPenalty propagates a penalty (e.g. from a ban or challenge event) to all groups the IP belongs to.
// The full penalty applies to the IP's /24 subnet; fingerprint and ASN receive weighted fractions.
func (s *Store) RecordPenalty(ip, fingerprint string, penalty float64) {
	hl := s.halfLife()
	isBan := penalty >= 50

	weights := map[string]float64{
		subnetKey(ip):  s.cfg.SubnetPropagation,
		fpKey(fingerprint): s.cfg.FingerprintPropagation,
	}
	if asnNum := s.asn.Lookup(ip); asnNum != 0 {
		weights[asnKey(asnNum)] = s.cfg.ASNPropagation
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, weight := range weights {
		if key == "" || weight <= 0 {
			continue
		}
		e, ok := s.groups[key]
		if !ok {
			e = &groupEntry{}
			s.groups[key] = e
		}
		// Start from the current decayed score, then add the weighted penalty.
		decayed := e.currentScore(hl)
		e.RawScore = decayed + penalty*weight
		e.Hits++
		if isBan {
			e.Bans++
		}
		e.LastUpdated = now
	}

	if s.cfg.PersistFile != "" && isBan {
		_ = s.save()
	}
}

// Close releases the ASN database handle and saves state.
func (s *Store) Close() {
	s.asn.Close()
	if s.cfg.PersistFile != "" {
		s.mu.RLock()
		_ = s.save()
		s.mu.RUnlock()
	}
}

func (s *Store) save() error {
	data, err := json.Marshal(s.groups)
	if err != nil {
		return err
	}
	tmp := s.cfg.PersistFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.cfg.PersistFile)
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.cfg.PersistFile)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Unmarshal(data, &s.groups)
}

// keysFor returns all group keys for ip + fingerprint.
func (s *Store) keysFor(ip, fingerprint string) []string {
	keys := []string{subnetKey(ip), fpKey(fingerprint)}
	if asnNum := s.asn.Lookup(ip); asnNum != 0 {
		keys = append(keys, asnKey(asnNum))
	}
	return keys
}

func (s *Store) halfLife() time.Duration {
	if s.cfg.HalfLife <= 0 {
		return 6 * time.Hour
	}
	return s.cfg.HalfLife
}

// cleanupLoop removes entries whose decayed score has fallen below 0.5 every 30 minutes to prevent unbounded memory growth.
func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		hl := s.halfLife()
		s.mu.Lock()
		for key, e := range s.groups {
			if e.currentScore(hl) < 0.5 {
				delete(s.groups, key)
			}
		}
		if s.cfg.PersistFile != "" {
			_ = s.save()
		}
		s.mu.Unlock()
	}
}
