package middleware

import (
	"bufio"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"git.omada.cafe/atf/waf/internal/bans"
	"git.omada.cafe/atf/waf/internal/config"
	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/tlsfp"
)

// ja3Lister is the subset of tlsfp.Listener we need, allowing tests to
// substitute a stub without importing the full listener.
type ja3Lister interface {
	Get(remoteAddr string) (string, bool)
	Delete(remoteAddr string)
}

// JA3Check is a middleware that fingerprints TLS ClientHellos via JA3 and
// blocks or scores requests from known automated clients.
//
// Hash source priority:
//  1. X-JA4-Hash header set by an upstream proxy (nginx, haproxy, …)
//  2. tlsfp.Listener native map keyed by r.RemoteAddr (WAF terminates TLS)
//
// When a hash matches the built-in or configured blocklist the request is
// immediately rejected with 403.  When a hash is unrecognised but the
// configured action is "score", the middleware adds a penalty to the
// X-WAF-JA4-Score header for downstream scoring instead of hard-blocking.
type JA3Check struct {
	next     http.Handler
	cfg      config.JA3Config
	listener ja3Lister // nil when not in native TLS mode
	banMgr   *bans.BanManager
	log      *slog.Logger

	// merged blocklist: built-in KnownBadFingerprints + entries from blocklist_file
	blocklist map[string]string
}

// NewJA3Check constructs the middleware.
//   - listener may be nil (header-only mode).
//   - banMgr may be nil (no persistent bans on tlsfp hits).
func NewJA3Check(next http.Handler, cfg config.JA3Config, listener ja3Lister, banMgr *bans.BanManager, log *slog.Logger) *JA3Check {
	m := &JA3Check{
		next:     next,
		cfg:      cfg,
		listener: listener,
		banMgr:   banMgr,
		log:      log,
		blocklist: make(map[string]string),
	}
	// seed with built-ins
	for k, v := range tlsfp.KnownBadFingerprints {
		m.blocklist[k] = v
	}
	// load operator-supplied file
	if cfg.BlocklistFile != "" {
		if err := m.loadBlocklistFile(cfg.BlocklistFile); err != nil {
			log.Warn("tlsfp: could not load blocklist file", "file", cfg.BlocklistFile, "err", err)
		} else {
			log.Info("tlsfp: loaded blocklist file", "file", cfg.BlocklistFile, "total", len(m.blocklist))
		}
	}
	// merge inline hashes from config
	for hash, label := range cfg.BlocklistHashes {
		m.blocklist[strings.ToLower(hash)] = label
	}
	return m
}

func (j *JA3Check) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !j.cfg.Enabled {
		j.next.ServeHTTP(w, r)
		return
	}

	hash := j.resolveHash(r)
	if hash == "" {
		// No JA4 fingerprint available (plain HTTP, no upstream header). Pass through.
		j.next.ServeHTTP(w, r)
		return
	}

	ip := extractIP(r)

	if label, blocked := j.blocklist[hash]; blocked {
		if j.banMgr != nil {
			j.banMgr.Ban(ip, "tlsfp:"+label, j.cfg.BanDuration.Duration, "tlsfp-001", 100)
		}
		j.log.Info("tlsfp: blocked known-bad fingerprint",
			"ip", ip, "hash", hash, "label", label,
			"path", r.URL.Path, "ua", r.Header.Get("User-Agent"))
		errorpage.Write(w, http.StatusForbidden)
		return
	}

	// Unknown fingerprint: pass through but annotate for downstream
	// scoring (scraper detector, anomaly scorer, etc.).
	r.Header.Set("X-WAF-JA4", hash)
	j.log.Debug("tlsfp: fingerprint recorded", "ip", ip, "hash", hash)
	j.next.ServeHTTP(w, r)
}

// resolveHash returns the JA4 fingerprint for this request from whatever source
// is available, or "" if none.
func (j *JA3Check) resolveHash(r *http.Request) string {
	// 1. Trusted upstream proxy header (nginx, haproxy, caddy).
	if h := r.Header.Get("X-JA4-Hash"); h != "" {
		return strings.ToLower(strings.TrimSpace(h))
	}
	if h := r.Header.Get("X-JA4"); h != "" { // alternate header name used by some setups
		return strings.ToLower(strings.TrimSpace(h))
	}

	// 2. Native listener map (WAF terminates TLS directly).
	if j.listener != nil {
		if hash, ok := j.listener.Get(r.RemoteAddr); ok {
			// Clean up to keep the map from growing indefinitely.
			j.listener.Delete(r.RemoteAddr)
			return hash
		}
	}

	return ""
}

// loadBlocklistFile reads a flat text file of "hash [optional-label]" lines
// (one per line, # = comment, blank lines ignored) and merges them into the
// blocklist.
func (j *JA3Check) loadBlocklistFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		hash := strings.ToLower(parts[0])
		label := "blocklist-file"
		if len(parts) > 1 {
			label = strings.Join(parts[1:], " ")
		}
		j.blocklist[hash] = label
	}
	return sc.Err()
}
