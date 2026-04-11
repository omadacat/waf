package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"git.omada.cafe/atf/waf/internal/bans"
	"git.omada.cafe/atf/waf/internal/challenges"
	"git.omada.cafe/atf/waf/internal/config"
	"git.omada.cafe/atf/waf/internal/tlsfp"
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

	if err := challenges.LoadTemplates(cfg.Challenges.TemplateDir); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: templates: %v\n", err)
		os.Exit(1)
	}

	globalStore := store.New()
	tokenMgr := token.New(cfg.TokenSecret, cfg.TokenTTL.Duration)

	var banMgr *bans.BanManager
	if cfg.Bans.Enabled {
		banMgr = bans.NewBanManager(cfg.Bans.PersistFile, log)
		if cfg.Bans.Fail2banLog != "" {
			if err := banMgr.SetFail2banLog(cfg.Bans.Fail2banLog); err != nil {
				log.Warn("bans: could not open fail2ban log", "err", err)
			}
		}
		banMgr.StartCleanup()
		log.Info("ban manager ready", "persist", cfg.Bans.PersistFile)
	}

	// ── JA4 / TLS listener setup ────────────────────────────────────────
	// Set up before building the middleware chain so ja3Listener is
	// non-nil when passed to NewJA3Check in native TLS mode.
	// In the nginx-fronted case (no tls: config) it stays nil and the
	// middleware falls back to the X-JA4-Hash header nginx sets.
	var tlsfpListener *tlsfp.Listener
	var tlsListener net.Listener // non-nil only in native TLS mode

	if cfg.TLS.Enabled() {
		tcpLn, err := net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			log.Error("tls: cannot bind", "addr", cfg.ListenAddr, "err", err)
			os.Exit(1)
		}
		tlsfpListener = tlsfp.NewListener(tcpLn)
		tlsCert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			log.Error("tls: cannot load key pair", "err", err)
			os.Exit(1)
		}
		tlsListener = tls.NewListener(tlsfpListener, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		})
		log.Info("native TLS enabled", "cert", cfg.TLS.CertFile)
	}

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
		wafMW := waf.NewMiddleware(engine, router, cfg, log)
		if banMgr != nil {
			wafMW.WithBanManager(banMgr, cfg.Bans.DefaultDuration.Duration)
		}
		inner = wafMW
	}

	if cfg.Auth.Enabled {
		inner = middleware.NewBasicAuth(inner, cfg.Auth, log)
		log.Info("basic auth enabled", "paths", len(cfg.Auth.Paths))
	}

	mux := http.NewServeMux()

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

	// Ensure challenge base path is exempt from session/WAF checks
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
	antiBotMW  := middleware.NoBot(sessionMW, cfg.AntiBot, log)
	ja3MW      := middleware.NewJA3Check(antiBotMW, cfg.JA3, tlsfpListener, banMgr, log)
	scraperMW  := middleware.NewScraperDetector(ja3MW, cfg.Scraper, banMgr, log)
	rateMW     := middleware.NewRateLimit(scraperMW, cfg.RateLimit, banMgr, log)
	normMW     := middleware.NewPathNormalizer(rateMW, base)
	metricsMW  := middleware.NewMetrics(normMW)

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

	// Main server
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
		log.Info("WAF proxy listening", "addr", cfg.ListenAddr, "tls", cfg.TLS.Enabled())
		var serveErr error
		if tlsListener != nil {
			serveErr = srv.Serve(tlsListener)
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Error("server fatal error", "err", serveErr)
			os.Exit(1)
		}
	}()

	<-stop
	log.Info("shutdown signal :: draining requests")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("graceful shutdown error", "err", err)
	}
	log.Info("the WAF has stopped")
}
