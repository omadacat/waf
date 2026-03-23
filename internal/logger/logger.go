package logger

import (
	"io"
	"log/slog"
	"os"

	"git.omada.cafe/atf/waf/internal/config"
)

// New constructs a *slog.Logger from the logging config.
// Output "-" means stdout, which systemd captures to journald.
func New(cfg config.LoggingConfig) *slog.Logger {
	var w io.Writer
	if cfg.Output == "-" || cfg.Output == "" {
		w = os.Stdout
	} else {
		f, err := os.OpenFile(cfg.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			slog.Error("failed to open log file, falling back to stdout", "err", err)
			w = os.Stdout
		} else {
			w = f
		}
	}

	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	return slog.New(handler)
}
