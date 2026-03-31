package bans

import (
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"
)

type BanManager struct {
    bans       map[string]BanEntry
    mu         sync.RWMutex
    fail2ban   *Fail2banAdapter
    persistFile string
    log        *slog.Logger
}

type BanEntry struct {
    IP        string    `json:"ip"`
    Reason    string    `json:"reason"`
    CreatedAt time.Time `json:"created_at"`
    ExpiresAt time.Time `json:"expires_at"`
    Score     int       `json:"score"`
    RuleIDs   []string  `json:"rule_ids"`
}

func NewBanManager(persistFile string, log *slog.Logger) *BanManager {
    bm := &BanManager{
        bans:       make(map[string]BanEntry),
        persistFile: persistFile,
        log:        log,
    }
    bm.load()
    bm.fail2ban = NewFail2banAdapter(log)
    return bm
}

func (bm *BanManager) Ban(ip, reason string, duration time.Duration, ruleID string, score int) {
    bm.mu.Lock()
    defer bm.mu.Unlock()

    entry := BanEntry{
        IP:        ip,
        Reason:    reason,
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(duration),
        Score:     score,
        RuleIDs:   []string{ruleID},
    }

    if existing, ok := bm.bans[ip]; ok {
        existing.RuleIDs = append(existing.RuleIDs, ruleID)
        existing.Score += score
        entry = existing
    }

    bm.bans[ip] = entry
    bm.persist()

    // Also ban via fail2ban for network-level blocking
    bm.fail2ban.Ban(ip, duration)

    bm.log.Warn("IP banned", "ip", ip, "reason", reason, "duration", duration, "score", score)
}

func (bm *BanManager) IsBanned(ip string) (bool, BanEntry) {
    bm.mu.RLock()
    defer bm.mu.RUnlock()

    entry, ok := bm.bans[ip]
    if !ok {
        return false, BanEntry{}
    }

    if time.Now().After(entry.ExpiresAt) {
        // Expired, remove
        go bm.unban(ip)
        return false, BanEntry{}
    }

    return true, entry
}

func (bm *BanManager) persist() {
    if bm.persistFile == "" {
        return
    }

    data, _ := json.Marshal(bm.bans)
    os.WriteFile(bm.persistFile, data, 0644)
}

func (bm *BanManager) load() {
    if bm.persistFile == "" {
        return
    }

    data, err := os.ReadFile(bm.persistFile)
    if err != nil {
        return
    }

    json.Unmarshal(data, &bm.bans)

    // Clean expired bans
    for ip, entry := range bm.bans {
        if time.Now().After(entry.ExpiresAt) {
            delete(bm.bans, ip)
        }
    }
}

func (bm *BanManager) unban(ip string) {
	bm.mu.Lock()
	delete(bm.bans, ip)
	bm.mu.Unlock()
	bm.persist()
	if bm.fail2ban != nil {
		bm.fail2ban.Unban(ip)
	}
}

// Cleanup removes all expired bans. Safe to call periodically.
func (bm *BanManager) Cleanup() {
	bm.mu.Lock()
	for ip, entry := range bm.bans {
		if time.Now().After(entry.ExpiresAt) {
			delete(bm.bans, ip)
		}
	}
	bm.mu.Unlock()
	bm.persist()
}

// StartCleanup runs a background goroutine that removes expired bans every 5 minutes.
func (bm *BanManager) StartCleanup() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			bm.Cleanup()
		}
	}()
}

// SetFail2banLog opens the fail2ban log file on the adapter.
func (bm *BanManager) SetFail2banLog(path string) error {
	return bm.fail2ban.SetLogFile(path)
}
