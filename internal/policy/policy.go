// Package policy provides per-host and per-path challenge policies.
// See full documentation inline.
package policy

import (
	"net/http"
	"strings"
)

type Action struct {
	Challenge     string // "" = global default | "none" | "cookie" | "js" | "scrypt" | "css"
	SkipWAF       bool
	SkipChallenge bool
}

type Rule struct {
	Name      string   `yaml:"name"`
	Hosts     []string `yaml:"hosts"`
	Paths     []string `yaml:"paths"`
	Challenge string   `yaml:"challenge"`
	SkipWAF   bool     `yaml:"skip_waf"`
}

type Engine struct{ rules []Rule }

func New(rules []Rule) *Engine { return &Engine{rules: rules} }

func (e *Engine) Match(r *http.Request) (Action, bool) {
	host := r.Host
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[:i], ":") {
		host = host[:i]
	}
	path := r.URL.Path
	for _, rule := range e.rules {
		if !matchHosts(rule.Hosts, host) || !matchPaths(rule.Paths, path) {
			continue
		}
		return Action{
			Challenge:     rule.Challenge,
			SkipWAF:       rule.SkipWAF,
			SkipChallenge: rule.Challenge == "none",
		}, true
	}
	return Action{}, false
}

func matchHosts(hosts []string, host string) bool {
	if len(hosts) == 0 { return true }
	for _, h := range hosts {
		if strings.EqualFold(h, host) { return true }
	}
	return false
}

func matchPaths(paths []string, path string) bool {
	if len(paths) == 0 { return true }
	for _, p := range paths {
		if strings.HasPrefix(path, p) { return true }
	}
	return false
}
