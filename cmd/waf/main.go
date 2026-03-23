package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"git.omada.cafe/atf/waf/internal/challenges"
	"git.omada.cafe/atf/waf/internal/config"
	"git.omada.cafe/atf/waf/internal/logger"
	"git.omada.cafe/atf/waf/internal/middleware"
	"git.omada.cafe/atf/waf/internal/proxy"
	"git.omada.cafe/atf/waf/internal/store"
	"git.omada.cafe/atf/waf/internal/token"
	"git.omada.cafe/atf/waf/internal/waf"
)

func main() {
	cfgPath := flag.String("config", "/etc/waf/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: config: %v\n", err)
		os.Exit(1)
	}

	log := logger.New(cfg.Logging)
	log.Info("the WAF is starting", "listen", cfg.ListenAddr, "backends", len(cfg.Backends))

	globalStore := store.New()
	tokenMgr := token.New(cfg.TokenSecret, cfg.TokenTTL.Duration)

	router, err := proxy.New(cfg.Backends, log)
	if err != nil {
		log.Error("failed to initialise proxy router", "err", err)
		os.Exit(1)
	}

	var inner http.Handler = router
	if cfg.WAF.Enabled {
		engine, err := waf.New(cfg.WAF.Regex.RulesFile, log)
		if err != nil {
			log.Error("failed to initialise WAF engine", "err", err)
			os.Exit(1)
		}
		inner = waf.NewMiddleware(engine, router, cfg, log)
	}

	mux := http.NewServeMux()

	// Build the challenge dispatcher using the new API
	c := cfg.Challenges
	dispatcher := challenges.NewDispatcher(
		globalStore, tokenMgr,
		c.TorFriendly, c.TorExitListURL, c.TorExitRefresh.Duration,
		c.Strategy, c.BasePath,
		c.JSDifficulty, c.TorJSDifficulty,
		c.NonceTTL.Duration,
		c.CSSSequenceLength,
		c.ScryptDifficulty, c.ScryptN, c.ScryptR, c.ScryptP, c.ScryptKeyLen,
		c.TorScryptDifficulty,
		log,
	)
	dispatcher.RegisterRoutes(mux)

	// Exempt paths bypass Session + WAF
	base := strings.TrimRight(c.BasePath, "/")
	if !cfg.IsExemptPath(base + "/") {
		cfg.Challenges.ExemptPaths = append(cfg.Challenges.ExemptPaths, base+"/")
	}

	mux.Handle("/", inner)

	sessionMW := middleware.NewSession(
		mux,
		http.HandlerFunc(dispatcher.Dispatch),
		tokenMgr,
		cfg,
		log,
	)
	antiBotMW := middleware.NoBot(sessionMW, cfg.AntiBot, log)
	rateMW := middleware.NewRateLimit(antiBotMW, cfg.RateLimit, log)
	metricsMW := middleware.NewMetrics(rateMW)

	if cfg.Metrics.Enabled {
		metricsSrv := &http.Server{
			Addr:              cfg.Metrics.ListenAddr,
			Handler:           middleware.MetricsHandler(),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Info("metrics server listening", "addr", cfg.Metrics.ListenAddr)
			if err := metricsSrv.ListenAndServe(); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics server error", "err", err)
			}
		}()
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           metricsMW,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		log.Info("WAF proxy listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			log.Error("server fatal error", "err", err)
			os.Exit(1)
		}
	}()

	<-stop
	log.Info("shutdown signal — draining requests")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("graceful shutdown error", "err", err)
	}
	log.Info("the WAF has stopped")
}
