package challenges

import (
	"bufio"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Tor users often disable JavaScript for privacy; we lower challenge difficulty for them rather than blocking outright
type TorExitList struct {
	mu      sync.RWMutex
	ips     map[string]struct{}
	url     string
	refresh time.Duration
	log     *slog.Logger
}

func NewTorExitList(url string, refresh time.Duration, log *slog.Logger) *TorExitList {
	t := &TorExitList{
		ips:     make(map[string]struct{}),
		url:     url,
		refresh: refresh,
		log:     log,
	}
	if err := t.fetch(); err != nil {
		log.Warn("tor: initial exit-list fetch failed", "err", err)
	}
	go t.loop()
	return t
}

func (t *TorExitList) Contains(ip string) bool {
	t.mu.RLock()
	_, ok := t.ips[ip]
	t.mu.RUnlock()
	return ok
}

func (t *TorExitList) loop() {
	ticker := time.NewTicker(t.refresh)
	defer ticker.Stop()
	for range ticker.C {
		if err := t.fetch(); err != nil {
			t.log.Warn("tor: exit-list refresh failed", "err", err)
		}
	}
}

func (t *TorExitList) fetch() error {
	resp, err := http.Get(t.url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	newIPs := make(map[string]struct{})
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 8<<20))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		newIPs[line] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	t.ips = newIPs
	t.mu.Unlock()
	t.log.Info("tor: exit-list refreshed", "count", len(newIPs))
	return nil
}
