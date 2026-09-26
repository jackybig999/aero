package public

import (
	"embed"
	"flag"
	"fmt"
	"github.com/aero-protocol/aero-ech/internal/api"
	"github.com/aero-protocol/aero-ech/internal/split"
	"github.com/aero-protocol/aero-ech/internal/sub"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// -----------------------------------------------------------------------------
// Source: aeroapp_embed.go
// -----------------------------------------------------------------------------
//
//go:embed ui/*
var uiEmbed embed.FS

//go:embed assets/app.ico
var appIcon []byte

// -----------------------------------------------------------------------------
// Source: aeroapp_main.go
// -----------------------------------------------------------------------------
func RunApp() {
	setupFileLog()
	if logFile != nil {
		log.SetOutput(logFile)
	}
	hideOwnConsole()
	if !ensureSingleInstance() {
		return
	}
	healLeftoverAeroDNS()
	stripProcessProxyEnv()
	flag.Parse()
	// Mixed port is live on launch (Clash/box). Power button only
	// takes sysproxy/TUN. Do not pause tunnels and do not Connect().
	enginePaused.Store(false)
	sessionOn.Store(false)
	modeMu.Lock()
	clientMode = "socks"
	modeMu.Unlock()

	defer cleanupOnExit()
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("[SIGNAL] shutting down…")
		exitApp()
	}()

	if *tlsInsecure {
		certloader.SetInsecure(true)
		log.Printf("[CERT] WARNING: TLS verification disabled (-insecure)")
	}
	if *enableSplit {
		splitEngine = split.NewEngine()
	}

	ui, err := fs.Sub(uiEmbed, "ui")
	if err != nil {
		log.Fatalf("ui embed: %v", err)
	}

	apiSrv := api.NewServer("127.0.0.1:19877")
	apiSrv.SetRuntime(apiRuntime{})
	apiSrv.SetUI(ui)
	apiSrv.UpdateState(func(st *api.AppState) {
		st.Connected = false
		st.Listen = *listenAddr
		st.HTTPListen = *listenAddr
		st.Mode = "socks"
		st.Protocol = "aero/2.0"
		st.Version = "aeroapp"
		if *subURL != "" {
			st.SubURL = *subURL
		}
	})
	if err := apiSrv.Start(); err != nil {
		restoreExistingAERO()
		log.Printf("[API] 19877 busy: %v", err)
		return
	}
	defer apiSrv.Stop()
	setAPIServer(apiSrv)

	if m := strings.ToLower(strings.TrimSpace(*initMode)); m == "tun" || m == "sysproxy" || m == "socks" {
		modeMu.Lock()
		clientMode = m
		modeMu.Unlock()
		apiSrv.UpdateState(func(st *api.AppState) { st.Mode = m })
	}

	if err := startMixedListen(); err != nil {
		log.Printf("[MIXED] %v", err)
		apiSrv.UpdateState(func(st *api.AppState) {
			st.LastError = "混合口 55555 被占用"
			st.Hint = err.Error()
		})
	} else {
		log.Printf("AERO app: MIXED %s ready (fill SOCKS5, no Connect needed)", *listenAddr)
	}

	if *subURL == "" && (*subServer == "" || *subUser == "") {
		if acc := loadLastAccount(); acc != nil {
			*subServer = acc.Server
			*subUser = acc.Username
			*subPass = acc.Password
		}
	}
	var initialSub *sub.Applied
	if *subServer != "" && *subUser != "" && *subPass != "" {
		app, err := loadAndApplyPrivateSubscription(*subServer, *subUser, *subPass)
		if err != nil {
			log.Printf("[SUB] preload private: %v", err)
			apiSrv.UpdateState(func(st *api.AppState) { st.LastError = err.Error() })
		} else {
			initialSub = app
			apiSrv.UpdateState(func(st *api.AppState) { st.SubURL = fmt.Sprintf("%s (user: %s)", *subServer, *subUser) })
		}
	} else if *subURL != "" {
		app, err := loadAndApplySubscription(*subURL)
		if err != nil {
			log.Printf("[SUB] preload: %v", err)
			apiSrv.UpdateState(func(st *api.AppState) { st.LastError = err.Error() })
		} else {
			initialSub = app
			apiSrv.UpdateState(func(st *api.AppState) { st.SubURL = *subURL })
		}
	}
	startBackgroundServices()
	if *subServer != "" && *subUser != "" && *subPass != "" {
		startPrivateSubRefreshLoop(*subServer, *subUser, *subPass, initialSub)
	} else if *subURL != "" {
		startSubRefreshLoop(*subURL, initialSub)
	}

	if err := runAppShell("http://127.0.0.1:19877/"); err != nil {
		log.Printf("[UI] %v", err)
		nativeAlert("AERO", err.Error())
	}
}

// RunWin is the entry point for the Windows client (aerowin).
func RunWin() {
	RunApp()
}

// RunMac is the entry point for the macOS client (aeromac).
func RunMac() {
	RunApp()
}

// RunLinux is the entry point for the Linux client (aerolix).
func RunLinux() {
	RunApp()
}

// -----------------------------------------------------------------------------
// Source: aeroapp_exit.go
// -----------------------------------------------------------------------------
var exitOnce sync.Once

// exitApp always leaves the process. Cleanup is time-boxed so stopTUN
// cannot leave aeroapp + aero-guard stuck in memory.
func exitApp() {
	exitOnce.Do(func() {
		terminateNativeWindow()
		done := make(chan struct{})
		go func() {
			cleanupOnExit()
			close(done)
		}()
		cleaned := false
		select {
		case <-done:
			cleaned = true
		case <-time.After(4 * time.Second):
			log.Printf("[EXIT] cleanup timed out; leaving guard to recover network")
		}
		if cleaned {
			stopCrashGuard()
		}
		os.Exit(0)
	})
}
