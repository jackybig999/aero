package public

import (
	"flag"
	"fmt"
	"github.com/aero-protocol/aero-ech/internal/api"
	"github.com/aero-protocol/aero-ech/internal/config"
	"github.com/aero-protocol/aero-ech/internal/edgepool"
	"github.com/aero-protocol/aero-ech/internal/split"
	"github.com/aero-protocol/aero-ech/internal/sub"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// -----------------------------------------------------------------------------
// Source: main_cli.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

func RunCLI() {
	setupFileLog()
	healLeftoverAeroDNS()
	stripProcessProxyEnv()
	flag.Parse()
	// Double-click / no flags: reuse last subscription or account credentials.
	if *subURL == "" && (*edgeAddr == "" || *token == "") && *configPath == "" && (*subServer == "" || *subUser == "") {
		if acc := loadLastAccount(); acc != nil {
			*subServer = acc.Server
			*subUser = acc.Username
			*subPass = acc.Password
		}
	}
	// Start paused: mixed port listens but does not take system proxy until Connect().
	// Auto-connect after API is up so console / connect.ps1 / GUI share one path.
	enginePaused.Store(true)

	// Never leave Windows PAC pointing at a dead 19877 after kill/crash.
	defer cleanupOnExit()
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("[SIGNAL] shutting down…")
		cleanupOnExit()
		os.Exit(0)
	}()

	// 配置文件加载：-config 指定时从文件读取，flag 值作为覆盖
	if *configPath != "" {
		if cfg := config.LoadOrNil(*configPath); cfg != nil {
			applyConfig(cfg)
			log.Printf("[CONFIG] Loaded from %s (version=%s)", *configPath, cfg.Version)
		} else {
			log.Printf("[CONFIG] Failed to load %s, using flag defaults", *configPath)
		}
	}

	// TLS 校验策略（Step1 收口）：
	//   - 有 -ca-cert → 强制校验
	//   - -insecure 或 AERO_TLS_INSECURE=1 → 跳过（仅开发/自签）
	//   - 否则系统根证书校验（生产默认）
	if *tlsInsecure {
		certloader.SetInsecure(true)
		log.Printf("[CERT] WARNING: TLS verification disabled (-insecure)")
	}
	if *caCertPath != "" {
		pool, err := certloader.LoadCA(*caCertPath)
		if err != nil {
			log.Fatalf("[CERT] load CA certificate failed: %v", err)
		}
		certloader.SetGlobal(pool)
		certloader.SetInsecure(false)
		log.Printf("[CERT] Server verification enabled using %s", *caCertPath)
	} else if !certloader.ShouldSkipVerify() {
		log.Printf("[CERT] Using system root CAs (set -insecure for self-signed Edge)")
	}

	if *enableSplit {
		splitEngine = split.NewEngine()
		log.Println("[SPLIT] Smart traffic splitting enabled")
	}

	var initialSub *sub.Applied
	if *subServer != "" && *subUser != "" && *subPass != "" {
		app, err := loadPrivateSubscription(*subServer, *subUser, *subPass)
		if err != nil {
			log.Fatalf("load private subscription failed: %v", err)
		}
		initialSub = app
	} else if *subURL != "" {
		app, err := loadSubscription(*subURL)
		if err != nil {
			log.Fatalf("load subscription failed: %v", err)
		}
		initialSub = app
	}

	// 仅 -server/-user/-pass 或 -sub 即可；或 -edge + -token
	if *edgeAddr == "" || *token == "" {
		log.Fatal("需要订阅：aero-ech -server <url> -user <username> -pass <password>  或 -sub <url>")
	}

	pool, err := edgepool.New(*edgeAddr)
	if err != nil {
		log.Fatalf("init edge pool failed: %v", err)
	}
	edgePool = pool

	if *simOnly {
		enginePaused.Store(false)
		edgePool.ProbeAll(0)
		if best := edgePool.Best(); best.Reachable {
			*edgeAddr = best.Address
		}
		os.Exit(runDataPlaneSim())
	}

	if err := startMixedListen(); err != nil {
		log.Fatalf("listen failed: %v", err)
	}
	defer stopMixedListen()

	log.Printf("AERO ech client: MIXED %s (HTTP+HTTPS+SOCKS5) -> %s (SNI=%s, fingerprint=%s)",
		*listenAddr, *edgeAddr, *publicName, *fingerprint)

	// Control API first — GUI waits only ~30s and previously died while ProbeAll blocked.
	apiSrv := api.NewServer("127.0.0.1:19877")
	apiSrv.SetRuntime(apiRuntime{})
	apiSrv.UpdateState(func(st *api.AppState) {
		st.Connected = false
		st.Node = *edgeAddr
		st.UptimeStart = time.Now()
		st.Listen = *listenAddr
		st.HTTPListen = *listenAddr
		st.Mode = "sysproxy"
		st.Protocol = "aero/2.0"
		if *subServer != "" && *subUser != "" {
			st.SubURL = fmt.Sprintf("%s (user: %s)", *subServer, *subUser)
		} else if *subURL != "" {
			st.SubURL = *subURL
		}
	})
	if err := apiSrv.Start(); err != nil {
		log.Printf("[API] Failed to start: %v (continuing without API)", err)
	} else {
		defer apiSrv.Stop()
	}
	setAPIServer(apiSrv)

	if m := strings.ToLower(strings.TrimSpace(*initMode)); m == "tun" || m == "sysproxy" || m == "socks" {
		modeMu.Lock()
		clientMode = m
		modeMu.Unlock()
	}
	// One-click: try TUN. Only a real other-global (TUN Up / catch-all routes)
	// blocks it — resident box/Clash or their system-proxy-only does not.
	// Explicit -mode socks keeps mixed-only so we can verify without grabbing WinINET.
	if who := otherVPNActive(); who != "" {
		modeMu.Lock()
		cur := clientMode
		if cur != "socks" {
			clientMode = "sysproxy"
		}
		modeMu.Unlock()
		log.Printf("[API] other GLOBAL (%s): skip TUN (mode=%s)", who, clientMode)
		apiSrv.UpdateState(func(st *api.AppState) {
			st.Hint = "其它工具已开全局（" + who + "）。AERO 未开 TUN，以免双全局。关掉对方全局后再选 TUN。"
		})
	}
	if err := (apiRuntime{}).Connect(); err != nil {
		log.Printf("[API] auto connect failed: %v", err)
	} else {
		modeMu.RLock()
		got := clientMode
		modeMu.RUnlock()
		apiSrv.UpdateState(func(st *api.AppState) {
			st.Connected = true
			st.Mode = got
		})
		log.Printf("[API] auto connect: %s + mixed %s (tunRunning=%v)", got, *listenAddr, tunRunning)
	}

	startBackgroundServices()
	if *subServer != "" && *subUser != "" && *subPass != "" {
		startPrivateSubRefreshLoop(*subServer, *subUser, *subPass, initialSub)
	} else if *subURL != "" {
		startSubRefreshLoop(*subURL, initialSub)
	}

	select {}
}
