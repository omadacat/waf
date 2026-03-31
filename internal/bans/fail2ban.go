package bans

import (
	"fmt"
	"log/slog"
	"os"
	"time"
)

// Fail2banAdapter writes structured log lines that fail2ban can parse.
type Fail2banAdapter struct {
	log     *slog.Logger
	logFile *os.File
}

func NewFail2banAdapter(log *slog.Logger) *Fail2banAdapter {
	return &Fail2banAdapter{log: log}
}

// SetLogFile opens a dedicated log file for fail2ban consumption.
// If path is empty, lines are written to the structured logger instead.
func (f *Fail2banAdapter) SetLogFile(path string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("fail2ban: opening log file %q: %w", path, err)
	}
	f.logFile = file
	return nil
}

// Ban writes a ban record. fail2ban parses the [BANNED] line.
func (f *Fail2banAdapter) Ban(ip string, duration time.Duration) {
	line := fmt.Sprintf("[BANNED] ip=%s duration=%s ts=%d\n",
		ip, duration, time.Now().Unix())
	if f.logFile != nil {
		f.logFile.WriteString(line)
	} else {
		f.log.Warn("fail2ban: ban recorded", "ip", ip, "duration", duration)
	}
}

// Unban writes an unban record (informational; fail2ban manages its own unban).
func (f *Fail2banAdapter) Unban(ip string) {
	line := fmt.Sprintf("[UNBANNED] ip=%s ts=%d\n", ip, time.Now().Unix())
	if f.logFile != nil {
		f.logFile.WriteString(line)
	} else {
		f.log.Info("fail2ban: unban recorded", "ip", ip)
	}
}
