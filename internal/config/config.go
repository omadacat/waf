package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr  string            `yaml:"listen_addr"`
	TokenSecret string            `yaml:"token_secret"`
	TokenTTL    Duration          `yaml:"token_ttl"`
	Backends    map[string]string `yaml:"backends"`
	RateLimit   RateLimitConfig   `yaml:"rate_limit"`
	Reputation  ReputationConfig  `yaml:"reputation"`
	Policies    []PolicyRule      `yaml:"policies"`
	DNSBL       DNSBLConfig       `yaml:"dnsbl"`
	AbuseIPDB   AbuseIPDBConfig   `yaml:"abuseipdb"`
	Bandwidth   BandwidthConfig   `yaml:"bandwidth"`
	Tarpit      TarpitConfig      `yaml:"tarpit"`
	Allowlist   AllowlistConfig   `yaml:"allowlist"`
	AntiBot     AntiBotConfig     `yaml:"antibot"`
	JA3         JA3Config         `yaml:"ja3"`
	Scraper     ScraperConfig     `yaml:"scraper"`
	Challenges  ChallengesConfig  `yaml:"challenges"`
	Bans        BansConfig        `yaml:"bans"`
	WAF         WAFConfig         `yaml:"waf"`
	Logging     LoggingConfig     `yaml:"logging"`
	Metrics     MetricsConfig     `yaml:"metrics"`
}


type JA3Config struct {
	Enabled bool `yaml:"enabled"`

	// BlocklistFile is a path to a flat "hash [label]" file.
	// Built-in KnownBadHashes are always active; this file extends them.
	BlocklistFile string `yaml:"blocklist_file"`

	// BlocklistHashes are inline hash→label pairs merged at startup.
	BlocklistHashes map[string]string `yaml:"blocklist_hashes"`

	// BanDuration controls how long a tlsfp-matched IP stays banned.
	BanDuration Duration `yaml:"ban_duration"`
}

// PolicyRule is one entry in the policies list.
// Policies are evaluated in order; first match wins.
type PolicyRule struct {
	Name      string   `yaml:"name"`
	Hosts     []string `yaml:"hosts"`  // empty = all hosts
	Paths     []string `yaml:"paths"`  // prefix match; empty = all paths
	Challenge string   `yaml:"challenge"` // "" | "none" | "cookie" | "js" | "scrypt" | "css"
	SkipWAF   bool     `yaml:"skip_waf"`
}

// DNSBLConfig controls async DNS blocklist checking.
type DNSBLConfig struct {
	Enabled bool     `yaml:"enabled"`
	Zones   []string `yaml:"zones"`   // empty = use built-in defaults
	TTL     Duration `yaml:"ttl"`     // how long to cache results (default 4h)
	Penalty float64  `yaml:"penalty"` // reputation penalty per zone hit (default 30)
}

// AllowlistConfig lists IPs and CIDRs that bypass all challenges and WAF rules.
// Use for monitoring probes, CDN health checks, and your own IPs.
type AllowlistConfig struct {
	Enabled bool     `yaml:"enabled"`
	CIDRs   []string `yaml:"cidrs"`  // "1.2.3.4/32", "10.0.0.0/8", etc.
}

// AbuseIPDBConfig — async IP reputation checking via AbuseIPDB v2 API.
// Requires a free API key from https://www.abuseipdb.com/
// Free tier: 1 000 checks/day.  Results cached for TTL (default 24h) so
// each unique IP only costs one API call regardless of visit frequency.
type AbuseIPDBConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIKey  string `yaml:"api_key"`  // set via WAF_ABUSEIPDB_KEY env var
	TTL     Duration `yaml:"ttl"`
}

// BandwidthConfig — per-IP bandwidth accounting to protect constrained links.
// Tracks bytes served per IP per window.  Heavy downloaders (scrapers pulling
// large media, image galleries, or git repos) are caught even if they pass PoW.
type BandwidthConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Window          Duration `yaml:"window"`           // rolling window (default 10m)
	WarnThresholdMB int      `yaml:"warn_threshold_mb"` // log warning (default 100 MB)
	BanThresholdMB  int      `yaml:"ban_threshold_mb"`  // ban IP (default 500 MB)
	BanDuration     Duration `yaml:"ban_duration"`
}

// TarpitConfig — delay responses for suspected scrapers in the challenge zone.
// Occupies scraper threads without banning, reducing effective throughput
// by 20–100x and exhausting residential proxy pools.
type TarpitConfig struct {
	Enabled bool `yaml:"enabled"`
}

// ReputationConfig controls cross-IP group reputation scoring.
// When an IP is penalised by any middleware the penalty propagates (at the
// configured weight) to its /24 subnet, JA4 fingerprint, and ASN groups.
// New IPs that share a high-scoring group are pre-emptively challenged or
// banned before they do anything wrong.
type ReputationConfig struct {
	Enabled     bool   `yaml:"enabled"`
	PersistFile string `yaml:"persist_file"`

	// ASNDBPath is the path to a MaxMind GeoLite2-ASN (or GeoIP2-ASN) MMDB
	// file.  Leave empty to disable ASN grouping.  Building with -tags maxmind
	// is also required; see internal/reputation/asn_stub.go.
	ASNDBPath string `yaml:"asn_db"`

	// Propagation weights: fraction of an IP-level penalty that is added to
	// each group score when the IP is penalised.
	SubnetPropagation      float64  `yaml:"subnet_propagation"`
	FingerprintPropagation float64  `yaml:"fingerprint_propagation"`
	ASNPropagation         float64  `yaml:"asn_propagation"`

	// ChallengeThreshold is the inherited group score at which a new IP is
	// forced through a fresh challenge even if it holds a valid token.
	ChallengeThreshold float64 `yaml:"challenge_threshold"`

	// BanThreshold is the inherited group score at which a new IP is
	// immediately banned.
	BanThreshold float64 `yaml:"ban_threshold"`

	// BanDuration controls how long a reputation-triggered ban lasts.
	BanDuration Duration `yaml:"ban_duration"`

	// HalfLife controls how fast group scores decay.
	// After one half-life the score is halved; after two it is quartered.
	HalfLife Duration `yaml:"half_life"`
}

type RateLimitConfig struct {
	Enabled           bool     `yaml:"enabled"`
	WindowSeconds     int      `yaml:"window_seconds"`
	MaxRequests       int      `yaml:"max_requests"`
	BlacklistDuration Duration `yaml:"blacklist_duration"`
}

// AntiBotConfig — header-based bot filtering.
//
// CrawlerPolicy controls how verified search-engine crawlers are handled:
//   - "challenge" (default): same PoW as everyone else.
//   - "permissive": bypass challenges (still rate-limited + WAF rules).
//   - "strict": block all crawlers outright.
type AntiBotConfig struct {
	Enabled             bool   `yaml:"enabled"`
	BlockEmptyUserAgent bool   `yaml:"block_empty_user_agent"`
	BlockEmptyAccept    bool   `yaml:"block_empty_accept"`
	BotUAListFile       string `yaml:"bot_ua_list_file"`
	CrawlerPolicy       string `yaml:"crawler_policy"` // challenge | permissive | strict
}

// ScraperConfig drives the behaviour-based scraper detection middleware.
// The middleware accumulates a score per IP within a sliding window and
// either issues a fresh challenge (challenge_threshold) or hard-bans the IP
// (ban_threshold) when the score is reached.
type ScraperConfig struct {
	Enabled bool `yaml:"enabled"`

	// Window is the sliding time window for per-IP analysis.
	Window Duration `yaml:"window"`

	// MinRequests is the minimum number of requests before ratio-based
	// signals are evaluated (avoids false positives on first page load).
	MinRequests int `yaml:"min_requests"`

	// UniquePathRatioSoft/Hard — fraction of requests hitting distinct paths.
	// Browsers revisit JS/CSS/images; crawlers don't.
	UniquePathRatioSoft float64 `yaml:"unique_path_ratio_soft"` // +25 score
	UniquePathRatioHard float64 `yaml:"unique_path_ratio_hard"` // +50 score

	// SeqRunLength — how many consecutive incrementing numeric IDs in a
	// path (e.g. /post/41, /post/42, /post/43) before flagging as enumeration.
	SeqRunLength int `yaml:"seq_run_length"`

	// MetronomeJitterMs — maximum standard deviation (ms) of inter-request
	// gaps that is considered "bot-like uniform timing".
	MetronomeJitterMs int `yaml:"metronome_jitter_ms"`

	// ChallengeThreshold — score at which a fresh challenge is forced.
	ChallengeThreshold int `yaml:"challenge_threshold"`

	// BanThreshold — score at which the IP is hard-banned.
	BanThreshold int `yaml:"ban_threshold"`

	// BanDuration — how long a scraper ban lasts.
	BanDuration Duration `yaml:"ban_duration"`
}

type ChallengesConfig struct {
	BasePath            string   `yaml:"base_path"`
	NonceTTL            Duration `yaml:"nonce_ttl"`
	Strategy            string   `yaml:"strategy"` // js_first | css_first | scrypt_for_datacenter
	JSDifficulty        int      `yaml:"js_difficulty"`
	ScryptDifficulty    int      `yaml:"scrypt_difficulty"`
	ScryptN             int      `yaml:"scrypt_n"`
	ScryptR             int      `yaml:"scrypt_r"`
	ScryptP             int      `yaml:"scrypt_p"`
	ScryptKeyLen        int      `yaml:"scrypt_key_len"`
	CSSSequenceLength   int      `yaml:"css_sequence_length"`
	ExemptPaths         []string `yaml:"exempt_paths"`
	ExemptHosts         []string `yaml:"exempt_hosts"`
	TorFriendly         bool     `yaml:"tor_friendly"`
	TorExitListURL      string   `yaml:"tor_exit_list_url"`
	TorExitRefresh      Duration `yaml:"tor_exit_refresh"`
	TorJSDifficulty     int      `yaml:"tor_js_difficulty"`
	TorScryptDifficulty int      `yaml:"tor_scrypt_difficulty"`

	// TemplateDir is an optional path to a directory containing challenge
	// page templates. Files present in this directory override the embedded
	// defaults; absent files fall back to the embedded versions. This lets
	// operators customise branding without recompiling the binary.
	//
	// Supported file names: js_pow.html, scrypt.html, css.html, fingerprint.html
	TemplateDir string `yaml:"template_dir"`
}

// BansConfig — persistent ban storage and fail2ban integration.
type BansConfig struct {
	Enabled            bool     `yaml:"enabled"`
	PersistFile        string   `yaml:"persist_file"`
	Fail2banLog        string   `yaml:"fail2ban_log"`
	DefaultDuration    Duration `yaml:"default_ban_duration"`
	ScoreThreshold     int      `yaml:"score_threshold"`
}

type WAFConfig struct {
	Enabled   bool        `yaml:"enabled"`
	Engine    string      `yaml:"engine"` // must be "regex"... for now :3
	Regex     RegexConfig `yaml:"regex"`
	LogBlocks bool        `yaml:"log_blocks"`
	SkipHosts []string    `yaml:"skip_hosts"`
}

type RegexConfig struct {
	RulesFile string `yaml:"rules_file"`
}

type LoggingConfig struct {
	Format         string `yaml:"format"` // json | text
	Level          string `yaml:"level"`  // debug | info | warn | error
	Output         string `yaml:"output"` // - for stdout
	LogAllRequests bool   `yaml:"log_all_requests"`
}

type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
}

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(v *yaml.Node) error {
	dur, err := time.ParseDuration(v.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", v.Value, err)
	}
	d.Duration = dur
	return nil
}

// Load reads the YAML config file and applies WAF_* environment overrides.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config YAML: %w", err)
	}
	if v := os.Getenv("WAF_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("WAF_TOKEN_SECRET"); v != "" {
		cfg.TokenSecret = v
	}
	return &cfg, cfg.validate()
}

func (c *Config) validate() error {
	if strings.HasPrefix(c.TokenSecret, "CHANGE_ME") || c.TokenSecret == "" {
		return fmt.Errorf("token_secret must be set - use WAF_TOKEN_SECRET env var")
	}
	if len(c.Backends) == 0 {
		return fmt.Errorf("at least one backend must be configured")
	}
	if c.WAF.Enabled && c.WAF.Engine != "regex" {
		return fmt.Errorf("waf.engine must be \"regex\".")
	}
	if c.Challenges.JSDifficulty < 1 {
		c.Challenges.JSDifficulty = 16
	}
	if c.Challenges.CSSSequenceLength < 2 {
		c.Challenges.CSSSequenceLength = 3
	}
	// Defaults for bans
	if c.Bans.DefaultDuration.Duration == 0 {
		c.Bans.DefaultDuration.Duration = 1 * time.Hour
	}
	if c.Bans.ScoreThreshold == 0 {
		c.Bans.ScoreThreshold = 50
	}
	// Defaults for tlsfp
	if c.JA3.BanDuration.Duration == 0 {
		c.JA3.BanDuration.Duration = 24 * time.Hour
	}
	// Defaults for DNSBL
	if c.DNSBL.TTL.Duration == 0 {
		c.DNSBL.TTL.Duration = 4 * time.Hour
	}
	if c.DNSBL.Penalty == 0 {
		c.DNSBL.Penalty = 30
	}
	// Defaults for reputation
	if c.Reputation.SubnetPropagation == 0 {
		c.Reputation.SubnetPropagation = 0.25
	}
	if c.Reputation.FingerprintPropagation == 0 {
		c.Reputation.FingerprintPropagation = 0.50
	}
	if c.Reputation.ASNPropagation == 0 {
		c.Reputation.ASNPropagation = 0.08
	}
	if c.Reputation.ChallengeThreshold == 0 {
		c.Reputation.ChallengeThreshold = 50
	}
	if c.Reputation.BanThreshold == 0 {
		c.Reputation.BanThreshold = 80
	}
	if c.Reputation.BanDuration.Duration == 0 {
		c.Reputation.BanDuration.Duration = 4 * time.Hour
	}
	if c.Reputation.HalfLife.Duration == 0 {
		c.Reputation.HalfLife.Duration = 6 * time.Hour
	}
	// Defaults for scraper detector
	if c.Scraper.Window.Duration == 0 {
		c.Scraper.Window.Duration = 2 * time.Minute
	}
	if c.Scraper.MinRequests == 0 {
		c.Scraper.MinRequests = 15
	}
	if c.Scraper.UniquePathRatioSoft == 0 {
		c.Scraper.UniquePathRatioSoft = 0.75
	}
	if c.Scraper.UniquePathRatioHard == 0 {
		c.Scraper.UniquePathRatioHard = 0.92
	}
	if c.Scraper.SeqRunLength == 0 {
		c.Scraper.SeqRunLength = 5
	}
	if c.Scraper.MetronomeJitterMs == 0 {
		c.Scraper.MetronomeJitterMs = 50
	}
	if c.Scraper.ChallengeThreshold == 0 {
		c.Scraper.ChallengeThreshold = 80
	}
	if c.Scraper.BanThreshold == 0 {
		c.Scraper.BanThreshold = 180
	}
	if c.Scraper.BanDuration.Duration == 0 {
		c.Scraper.BanDuration.Duration = 4 * time.Hour
	}
	return nil
}

func (c *Config) IsExemptPath(path string) bool {
	for _, p := range c.Challenges.ExemptPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (c *Config) IsExemptHost(host string) bool {
	for _, h := range c.Challenges.ExemptHosts {
		if h == host {
			return true
		}
	}
	return false
}

func (c *Config) ShouldSkipWAF(host string) bool {
	for _, h := range c.WAF.SkipHosts {
		if h == host {
			return true
		}
	}
	return false
}
