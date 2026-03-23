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
	AntiBot     AntiBotConfig     `yaml:"antibot"`
	Challenges  ChallengesConfig  `yaml:"challenges"`
	WAF         WAFConfig         `yaml:"waf"`
	Logging     LoggingConfig     `yaml:"logging"`
	Metrics     MetricsConfig     `yaml:"metrics"`
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
