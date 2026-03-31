// Package waf implements a lightweight regex-based WAF engine.
package waf

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"git.omada.cafe/atf/waf/internal/errorpage"
)

type Rule struct {
	ID      string   `yaml:"id"`
	Pattern string   `yaml:"pattern"`
	Targets []string `yaml:"targets"`
	Message string   `yaml:"message"`
	Tag     string   `yaml:"tag"`
	Action  string   `yaml:"action"`  // block | log
	Score   int      `yaml:"score"`   // ban score contribution (0 = no ban)
}

type compiledRule struct {
	Rule
	re *regexp.Regexp
}

type Engine struct {
	rules []compiledRule
	log   *slog.Logger
}

type Violation struct {
	RuleID  string
	Message string
	Tag     string
	Score   int
}

// BanRecorder is the subset of bans.BanManager needed by the WAF middleware.
// Using an interface keeps waf/ free of a direct import of bans/.
type BanRecorder interface {
	Ban(ip, reason string, duration time.Duration, ruleID string, score int)
}

func New(rulesFile string, log *slog.Logger) (*Engine, error) {
	if rulesFile != "" {
		if _, err := os.Stat(rulesFile); err == nil {
			return loadFromFile(rulesFile, log)
		}
		log.Warn("WAF rules file not found — using built-in rules", "file", rulesFile)
	}
	return compile(builtinRules(), log)
}

func loadFromFile(path string, log *slog.Logger) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading WAF rules %q: %w", path, err)
	}
	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parsing WAF rules: %w", err)
	}
	e, err := compile(rules, log)
	if err != nil {
		return nil, err
	}
	log.Info("WAF rules loaded", "file", path, "count", len(e.rules))
	return e, nil
}

func compile(rules []Rule, log *slog.Logger) (*Engine, error) {
	e := &Engine{log: log}
	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			log.Warn("invalid WAF rule — skipping", "id", r.ID, "err", err)
			continue
		}
		if r.Action == "" {
			r.Action = "block"
		}
		e.rules = append(e.rules, compiledRule{r, re})
	}
	log.Info("WAF engine ready", "rules", len(e.rules))
	return e, nil
}

func (e *Engine) Inspect(r *http.Request) *Violation {
	for i := range e.rules {
		cr := &e.rules[i]
		for _, target := range cr.Targets {
			subject := extractTarget(r, target)
			if subject == "" {
				continue
			}
			if cr.re.MatchString(subject) {
				if cr.Action == "log" {
					e.log.Info("WAF log-only match", "rule", cr.ID, "tag", cr.Tag, "path", r.URL.Path)
					continue
				}
				return &Violation{
					RuleID:  cr.ID,
					Message: cr.Message,
					Tag:     cr.Tag,
					Score:   cr.Score,
				}
			}
		}
	}
	return nil
}

func extractTarget(r *http.Request, target string) string {
	switch {
	case target == "uri":
		return r.URL.Path + "?" + r.URL.RawQuery
	case target == "ua":
		return r.Header.Get("User-Agent")
	case target == "all":
		var sb strings.Builder
		sb.WriteString(r.URL.Path + "?" + r.URL.RawQuery)
		for k, vs := range r.Header {
			sb.WriteString(" " + k + ": " + strings.Join(vs, ","))
		}
		return sb.String()
	case strings.HasPrefix(target, "header:"):
		return r.Header.Get(strings.TrimPrefix(target, "header:"))
	}
	return ""
}

type Middleware struct {
	engine    *Engine
	next      http.Handler
	cfg       interface{ ShouldSkipWAF(string) bool }
	banMgr    BanRecorder // optional
	banDur    time.Duration
	log       *slog.Logger
}

func NewMiddleware(engine *Engine, next http.Handler, cfg interface{ ShouldSkipWAF(string) bool }, log *slog.Logger) *Middleware {
	return &Middleware{engine: engine, next: next, cfg: cfg, log: log, banDur: time.Hour}
}

// WithBanManager attaches a ban recorder so WAF violations feed into the
// persistent ban store and fail2ban.
func (m *Middleware) WithBanManager(b BanRecorder, defaultDuration time.Duration) *Middleware {
	m.banMgr = b
	m.banDur = defaultDuration
	return m
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	if m.cfg.ShouldSkipWAF(host) {
		m.next.ServeHTTP(w, r)
		return
	}
	if v := m.engine.Inspect(r); v != nil {
		m.log.Warn("WAF block",
			"rule", v.RuleID,
			"tag", v.Tag,
			"host", host,
			"path", r.URL.Path,
			"ip", realIP(r),
		)
		if m.banMgr != nil && v.Score > 0 {
			m.banMgr.Ban(realIP(r), v.Message, m.banDur, v.RuleID, v.Score)
		}
		errorpage.Write(w, http.StatusForbidden)
		return
	}
	m.next.ServeHTTP(w, r)
}

func realIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i != -1 {
		return addr[:i]
	}
	return addr
}

func builtinRules() []Rule {
	return []Rule{
		{ID: "sqli-001", Tag: "sqli", Action: "block", Score: 75, Targets: []string{"uri", "all"},
			Pattern: `(?i)(union[\s\/\*]+select|select[\s\/\*]+.*from|insert[\s\/\*]+into|drop[\s\/\*]+table|delete[\s\/\*]+from|exec[\s]*\()`,
			Message: "SQL injection"},
		{ID: "sqli-002", Tag: "sqli", Action: "block", Score: 50, Targets: []string{"uri"},
			Pattern: "(?i)('\\s*or\\s+'|'\\s*or\\s+1|--\\s*$|;\\s*drop|;\\s*select)",
			Message: "SQL injection — tautology"},
		{ID: "xss-001", Tag: "xss", Action: "block", Score: 50, Targets: []string{"uri", "all"},
			Pattern: `(?i)(<[\s]*script[\s/>]|javascript[\s]*:|on\w+[\s]*=[\s]*["\\x27]?[^"\\x27\s>]+|<[\s]*iframe[\s/>])`,
			Message: "XSS — script or event handler"},
		{ID: "xss-002", Tag: "xss", Action: "block", Score: 50, Targets: []string{"uri", "all"},
			Pattern: `(?i)(vbscript[\s]*:|data[\s]*:[\s]*text\/html)`,
			Message: "XSS — alternative vector"},
		{ID: "traversal-001", Tag: "traversal", Action: "block", Score: 75, Targets: []string{"uri"},
			Pattern: `(\.\.[\/\\]|%2e%2e[\/\\%]|%252e%252e)`,
			Message: "Path traversal"},
		{ID: "traversal-002", Tag: "traversal", Action: "block", Score: 75, Targets: []string{"uri"},
			Pattern: `(?i)(\/etc\/passwd|\/etc\/shadow|\/proc\/self|\/windows\/system32|\/wp-config\.php)`,
			Message: "Sensitive file access"},
		{ID: "cmdi-001", Tag: "cmdi", Action: "block", Score: 75, Targets: []string{"uri", "all"},
			Pattern: "(?i)([;|`]\\s*(cat|ls|id|whoami|uname|wget|curl|bash|sh\\b|cmd\\.exe)\\b|\\$\\([^)]+\\))",
			Message: "Command injection"},
		{ID: "ssrf-001", Tag: "ssrf", Action: "block", Score: 50, Targets: []string{"uri"},
			Pattern: `(?i)(localhost|127\.0\.0\.1|169\.254\.|::1|0\.0\.0\.0|metadata\.google\.internal)`,
			Message: "SSRF — internal address"},
		{ID: "lfi-001", Tag: "lfi", Action: "block", Score: 50, Targets: []string{"uri"},
			Pattern: `(?i)(php:\/\/filter|php:\/\/input|data:\/\/|expect:\/\/|phar:\/\/)`,
			Message: "LFI — PHP stream wrapper"},
		{ID: "scanner-001", Tag: "scanner", Action: "block", Score: 25, Targets: []string{"ua"},
			Pattern: `(?i)(nikto|sqlmap|nmap|masscan|nuclei|dirbuster|gobuster|ffuf|wfuzz|acunetix|nessus)`,
			Message: "Security scanner UA"},
	}
}
