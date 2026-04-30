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

// JA3Check fingerprints TLS ClientHellos via JA4 and blocks requests from
// known automated clients.
//
// Fingerprint source priority (first non-empty wins):
//  1. X-JA4-Hash request header set by an upstream proxy (nginx + OpenResty).
//  2. tlsfp.Listener native map when the WAF terminates TLS directly.
//
// When neither source is available (plain HTTP, no upstream header, no native
// TLS) the middleware is a no-op: the request passes through unchanged.
type JA3Check struct {
	next     http.Handler
	cfg      config.JA3Config
	banMgr   *bans.BanManager
	log      *slog.Logger

	blocklist map[string]string // built-ins + operator entries
}

// NewJA3Check constructs the middleware.
//   - listener must be a concrete *tlsfp.Listener or nil — never a
//     nil pointer wrapped in an interface (that would defeat the nil check).
//   - banMgr may be nil.
func NewJA3Check(next http.Handler, cfg config.JA3Config, banMgr *bans.BanManager, log *slog.Logger) *JA3Check {
	m := &JA3Check{
		next:      next,
		cfg:       cfg,
		banMgr:    banMgr,
		log:       log,
		blocklist: make(map[string]string),
	}
	for k, v := range tlsfp.KnownBadFingerprints {
		m.blocklist[k] = v
	}
	if cfg.BlocklistFile != "" {
		if err := m.loadBlocklistFile(cfg.BlocklistFile); err != nil {
			log.Warn("tlsfp: could not load blocklist file", "file", cfg.BlocklistFile, "err", err)
		} else {
			log.Info("tlsfp: loaded blocklist file", "file", cfg.BlocklistFile, "total", len(m.blocklist))
		}
	}
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
		// No fingerprint available — nginx handles TLS and no header was set,
		// or this is plain HTTP. Pass through without penalty.
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
		errorpage.WriteBlock(w, http.StatusForbidden, ip, "ja4:"+label, j.log)
		return
	}

	// Annotate for downstream layers (reputation, scraper detector).
	r.Header.Set("X-WAF-JA4", hash)
	j.log.Debug("tlsfp: fingerprint recorded", "ip", ip, "hash", hash)
	j.next.ServeHTTP(w, r)
}

// resolveHash returns the JA4 fingerprint for this request, or "" if none is
// available.  It uses concrete-type nil checks so a nil *tlsfp.Listener never
// panics.
func (j *JA3Check) resolveHash(r *http.Request) string {
	// 1. Header from trusted upstream proxy.
	if h := r.Header.Get("X-JA4-Hash"); h != "" {
		return strings.ToLower(strings.TrimSpace(h))
	}
	if h := r.Header.Get("X-JA4"); h != "" {
		return strings.ToLower(strings.TrimSpace(h))
	}
	return ""
}

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
