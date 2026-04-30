package middleware

import (
	"bufio"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"

	"git.omada.cafe/atf/waf/internal/config"
	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/policy"
)

// builtinBadBotPatterns are unconditionally blocked regardless of crawler policy. \
// These are scraping frameworks and AI content scrapers that have no legitimate reason to hit a self-hosted webapp.

var builtinBadBotPatterns = []string{
	`(?i)(GPTBot|ChatGPT-User|CCBot|anthropic-ai|ClaudeBot|cohere-ai|PerplexityBot|YouBot|Bytespider|Google-Extended|AhrefsBot|MJ12bot|DotBot|SemrushBot|BLEXBot|PetalBot|DataForSeoBot|scrapy|mechanize|libwww-perl|lwp-trivial)`
}

// searchEngineCrawlers are patterns for legitimate search engine crawlers.
// Used by crawler_policy: permissive (let through) and strict (block).
var searchEngineCrawlers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Googlebot`),
	regexp.MustCompile(`(?i)bingbot`),
	regexp.MustCompile(`(?i)Baiduspider`),
	regexp.MustCompile(`(?i)YandexBot`),
	regexp.MustCompile(`(?i)DuckDuckBot`),
	regexp.MustCompile(`(?i)Applebot`),
	regexp.MustCompile(`(?i)Twitterbot`),
}

type AntiBot struct {
	next     http.Handler
	cfg      config.AntiBotConfig
	pol      *policy.Engine
	patterns []*regexp.Regexp
	log      *slog.Logger
}

// NoBot constructs the antibot middleware.
// pol may be nil; if provided, requests matching challenge:"none" policies skip all antibot checks.
func NoBot(next http.Handler, cfg config.AntiBotConfig, pol *policy.Engine, log *slog.Logger) *AntiBot {
	g := &AntiBot{next: next, cfg: cfg, pol: pol, log: log}
	g.patterns = compilePatterns(builtinBadBotPatterns)

	if cfg.BotUAListFile != "" {
		extra, err := loadPatternFile(cfg.BotUAListFile)
		if err != nil {
			log.Warn("could not load bot UA list file", "file", cfg.BotUAListFile, "err", err)
		} else {
			g.patterns = append(g.patterns, compilePatterns(extra)...)
			log.Info("loaded bot UA patterns", "file", cfg.BotUAListFile, "count", len(extra))
		}
	}

	if cfg.CrawlerPolicy == "" {
		cfg.CrawlerPolicy = "challenge"
	}
	g.cfg = cfg

	return g
}

func (g *AntiBot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !g.cfg.Enabled {
		g.next.ServeHTTP(w, r)
		return
	}

	// Policy-exempt paths skip all antibot checks.
	if g.pol != nil {
		if action, matched := g.pol.Match(r); matched && action.SkipChallenge {
			g.next.ServeHTTP(w, r)
			return
		}
	}

	ip := extractIP(r)
	ua := r.Header.Get("User-Agent")
	accept := r.Header.Get("Accept")

	// Empty UA check (configurable — some legitimate embedded clients
	// don't set a UA, which is why this is a flag, not a builtin pattern).
	if g.cfg.BlockEmptyUserAgent && strings.TrimSpace(ua) == "" {
		g.block(w, r, ip, "empty_user_agent")
		return
	}

	// Empty Accept check.
	if g.cfg.BlockEmptyAccept && strings.TrimSpace(accept) == "" {
		g.block(w, r, ip, "empty_accept")
		return
	}

	// Crawler policy: handle search engine bots before general patterns.
	if isSearchCrawler(ua) {
		switch g.cfg.CrawlerPolicy {
		case "permissive":
			// Let verified crawlers through without challenge.
			g.log.Debug("antibot: crawler permitted", "ip", ip, "ua", ua)
			g.next.ServeHTTP(w, r)
			return
		case "strict":
			// Block all crawlers outright.
			g.block(w, r, ip, "crawler_blocked")
			return
		default: // "challenge"
			// Fall through — crawlers solve the same challenge as everyone.
		}
	}

	// Bad bot patterns (builtins + external file).
	for _, pat := range g.patterns {
		if pat.MatchString(ua) {
			g.block(w, r, ip, "bot_ua_match")
			return
		}
	}

	g.next.ServeHTTP(w, r)
}

func isSearchCrawler(ua string) bool {
	for _, re := range searchEngineCrawlers {
		if re.MatchString(ua) {
			return true
		}
	}
	return false
}

func (g *AntiBot) block(w http.ResponseWriter, r *http.Request, ip, reason string) {
	g.log.Info("go_away block",
		"ip", ip,
		"reason", reason,
		"ua", r.Header.Get("User-Agent"),
		"path", r.URL.Path,
		"host", r.Host,
	)
	errorpage.WriteBlock(w, http.StatusForbidden, ip, "antibot:"+reason, g.log)
}

func compilePatterns(patterns []string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			out = append(out, re)
		}
	}
	return out
}

func loadPatternFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, sc.Err()
}
