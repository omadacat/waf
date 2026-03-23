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
)

// Default built-in bad bot User-Agent patterns (regex).
// These catch the most common AI scrapers and generic HTTP clients.
// The external bot_ua_list_file extends this list at runtime.
var builtinBadBotPatterns = []string{
	// Generic HTTP libraries — rarely a real browser
	`(?i)^(curl|wget|python-requests|python-urllib|go-http-client|java\/|okhttp|apache-httpclient)`,
	// Known AI scrapers
	`(?i)(GPTBot|ChatGPT-User|CCBot|anthropic-ai|ClaudeBot|cohere-ai|PerplexityBot|YouBot|Bytespider)`,
	`(?i)(AhrefsBot|MJ12bot|DotBot|SemrushBot|BLEXBot|PetalBot|DataForSeoBot)`,
	// Generic scrapers
	`(?i)(scrapy|mechanize|libwww-perl|lwp-trivial|urllib|httpx|aiohttp|httplib)`,
	// Empty / whitespace-only
	`^\s*$`,
}

// AntiBot is the first filter layer. It blocks obvious bots by inspecting
// headers before any challenge logic runs, saving compute.
type AntiBot struct {
	next     http.Handler
	cfg      config.AntiBotConfig
	patterns []*regexp.Regexp
	log      *slog.Logger
}

// NoBot constructs the AntiBot middleware.
// It compiles all UA patterns at startup so the hot path only does regexp matching, not compilation.
func NoBot(next http.Handler, cfg config.AntiBotConfig, log *slog.Logger) *AntiBot {
	g := &AntiBot{next: next, cfg: cfg, log: log}
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

	return g
}

func (g *AntiBot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !g.cfg.Enabled {
		g.next.ServeHTTP(w, r)
		return
	}

	ip := extractIP(r)
	ua := r.Header.Get("User-Agent")
	accept := r.Header.Get("Accept")

	// you can have empty user agents apparently
	if g.cfg.BlockEmptyUserAgent && strings.TrimSpace(ua) == "" {
		g.block(w, r, ip, "empty_user_agent")
		return
	}

	// Block empty Accept header (browsers always send Accept)
	if g.cfg.BlockEmptyAccept && strings.TrimSpace(accept) == "" {
		g.block(w, r, ip, "empty_accept")
		return
	}

	// Match against UA
	for _, pat := range g.patterns {
		if pat.MatchString(ua) {
			g.block(w, r, ip, "bot_ua_match")
			return
		}
	}

	g.next.ServeHTTP(w, r)
}

func (g *AntiBot) block(w http.ResponseWriter, r *http.Request, ip, reason string) {
	g.log.Info("go_away block",
		"ip", ip,
		"reason", reason,
		"ua", r.Header.Get("User-Agent"),
		"path", r.URL.Path,
		"host", r.Host,
	)
	errorpage.Write(w, http.StatusForbidden)
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

// Since we're behind Nginx, X-Forwarded-For is set by our own proxy and can be trusted for the first IP in the chain.
