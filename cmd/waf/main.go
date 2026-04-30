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

	"git.omada.cafe/atf/waf/internal/bans"
	"git.omada.cafe/atf/waf/internal/challenges"
	"git.omada.cafe/atf/waf/internal/config"
	"git.omada.cafe/atf/waf/internal/dnsbl"
	"git.omada.cafe/atf/waf/internal/logger"
	"git.omada.cafe/atf/waf/internal/middleware"
	"git.omada.cafe/atf/waf/internal/policy"
	"git.omada.cafe/atf/waf/internal/proxy"
	"git.omada.cafe/atf/waf/internal/reputation"
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

	repCfg := reputation.Config{
		Enabled:                cfg.Reputation.Enabled,
		PersistFile:            cfg.Reputation.PersistFile,
		ASNDBPath:              cfg.Reputation.ASNDBPath,
		SubnetPropagation:      cfg.Reputation.SubnetPropagation,
		FingerprintPropagation: cfg.Reputation.FingerprintPropagation,
		ASNPropagation:         cfg.Reputation.ASNPropagation,
		ChallengeThreshold:     cfg.Reputation.ChallengeThreshold,
		BanThreshold:           cfg.Reputation.BanThreshold,
		BanDuration:            cfg.Reputation.BanDuration.Duration,
		HalfLife:               cfg.Reputation.HalfLife.Duration,
	}
	repStore, err := reputation.New(repCfg)
	if err != nil {
		log.Error("reputation store init failed", "err", err)
		os.Exit(1)
	}
	defer repStore.Close()

	dnsblChecker := dnsbl.New(cfg.DNSBL.Zones, cfg.DNSBL.TTL.Duration, log)

	var policyRules []policy.Rule
	for _, r := range cfg.Policies {
		policyRules = append(policyRules, policy.Rule{
			Name:      r.Name,
			Hosts:     r.Hosts,
			Paths:     r.Paths,
			Challenge: r.Challenge,
			SkipWAF:   r.SkipWAF,
		})
	}
	policyEngine := policy.New(policyRules)


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
		wafMW.WithPolicy(policyEngine)
		if banMgr != nil {
			wafMW.WithBanManager(banMgr, cfg.Bans.DefaultDuration.Duration)
		}
		inner = wafMW
	}

	mux := http.NewServeMux()

	c := cfg.Challenges
	dispatcher := challenges.NewDispatcher(
		globalStore, tokenMgr,
		cfg.TokenSecret,
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

	base := strings.TrimRight(c.BasePath, "/")
	if !cfg.IsExemptPath(base + "/") {
		cfg.Challenges.ExemptPaths = append(cfg.Challenges.ExemptPaths, base+"/")
	}

	mux.Handle("/", inner)

	//  reputationMW  -> group scoring, pre-emptive ban, challenge escalation
	//  metricsMW     -> prometheus counters (wraps everything)
	//    normMW      -> path normalisation
	//      rateMW    -> per-IP rate limiting + blacklist
	//        scraperMW -> behaviour analysis (path ratio, timing, referer)
	//          ja3MW   -> JA4 fingerprint blocklist (header-only, nginx sets it)
	//            antiBotMW -> UA pattern matching
	//              sessionMW -> token validation / challenge dispatch

	sessionMW  := middleware.NewSession(mux, http.HandlerFunc(dispatcher.Dispatch), tokenMgr, cfg, policyEngine, log)
	antiBotMW  := middleware.NoBot(sessionMW, cfg.AntiBot, policyEngine, log)
	ja3MW      := middleware.NewJA3Check(antiBotMW, cfg.JA3, banMgr, log)
	scraperMW  := middleware.NewScraperDetector(ja3MW, cfg.Scraper, policyEngine, banMgr, log)
	dnsblGate  := middleware.NewDNSBLGate(scraperMW, dnsblChecker, repStore, cfg.DNSBL.Penalty, log)
	rateMW     := middleware.NewRateLimit(dnsblGate, cfg.RateLimit, banMgr, log)
	normMW     := middleware.NewPathNormalizer(rateMW, base)
	repMW      := middleware.NewReputation(normMW, repStore, banMgr, repCfg, log)
	metricsMW  := middleware.NewMetrics(repMW)
	allowlistMW := middleware.NewAllowlist(metricsMW, cfg.Allowlist.Enabled, cfg.Allowlist.CIDRs, log)

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
		Handler:           allowlistMW,
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
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server fatal error", "err", err)
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
