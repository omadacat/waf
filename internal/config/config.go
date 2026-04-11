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
	TLS         TLSConfig         `yaml:"tls"`
	RateLimit   RateLimitConfig   `yaml:"rate_limit"`
	AntiBot     AntiBotConfig     `yaml:"antibot"`
	JA3         JA3Config         `yaml:"ja3"`
	Scraper     ScraperConfig     `yaml:"scraper"`
	Challenges  ChallengesConfig  `yaml:"challenges"`
	Auth        AuthConfig        `yaml:"auth"`
	Bans        BansConfig        `yaml:"bans"`
	WAF         WAFConfig         `yaml:"waf"`
	Logging     LoggingConfig     `yaml:"logging"`
	Metrics     MetricsConfig     `yaml:"metrics"`
}

// TLSConfig enables native TLS termination at the WAF.
// When both CertFile and KeyFile are set the WAF serves HTTPS directly and
// the tlsfp.Listener can compute JA4 fingerprints from raw ClientHellos.
// Leave empty when nginx (or another proxy) terminates TLS upstream.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

func (t TLSConfig) Enabled() bool { return t.CertFile != "" && t.KeyFile != "" }

// JA3Config controls TLS ClientHello fingerprint checking.
//
// Two hash sources are supported (checked in order):
//  1. X-JA4-Hash / X-JA4 header set by an upstream proxy (nginx, haproxy…).
//  2. Native tlsfp.Listener when the WAF terminates TLS directly.
//
// Nginx setup (requires ngx_ssl_ja3 module or OpenResty):
//
//	proxy_set_header X-JA4-Hash $ssl_ja4_hash;
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

type RateLimitConfig struct {
	Enabled           bool     `yaml:"enabled"`
	WindowSeconds     int      `yaml:"window_seconds"`
	MaxRequests       int      `yaml:"max_requests"`
	BlacklistDuration Duration `yaml:"blacklist_duration"`
}

type AntiBotConfig struct {
	Enabled             bool   `yaml:"enabled"`
	BlockEmptyUserAgent bool   `yaml:"block_empty_user_agent"`
	BlockEmptyAccept    bool   `yaml:"block_empty_accept"`
	BotUAListFile       string `yaml:"bot_ua_list_file"`
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

// AuthConfig — HTTP Basic Auth for sensitive path prefixes.
// Users stores bcrypt hashes (generate with: htpasswd -nbB user pass).
// Paths maps path prefixes to lists of allowed usernames.
// Use "*" as a username to allow any authenticated user.
type AuthConfig struct {
	Enabled bool                `yaml:"enabled"`
	Realm   string              `yaml:"realm"`
	Users   map[string]string   `yaml:"users"`  // username -> "$2a$..." bcrypt hash
	Paths   map[string][]string `yaml:"paths"`  // "/servers" -> ["admin"]
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
	// Defaults for scraper detector
	if c.Scraper.Window.Duration == 0 {
		c.Scraper.Window.Duration = 2 * time.Minute
	}
	if c.Scraper.MinRequests == 0 {
		c.Scraper.MinRequests = 10
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
		c.Scraper.ChallengeThreshold = 40
	}
	if c.Scraper.BanThreshold == 0 {
		c.Scraper.BanThreshold = 80
	}
	if c.Scraper.BanDuration.Duration == 0 {
		c.Scraper.BanDuration.Duration = 24 * time.Hour
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
