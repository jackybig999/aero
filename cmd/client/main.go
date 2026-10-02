// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aero-protocol/aero/internal/client"
)

//go:embed ui/*
var uiEmbed embed.FS

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:55555", "mixed proxy address (SOCKS5/HTTP CONNECT)")
	apiAddr := flag.String("api", "127.0.0.1:19877", "client control API and UI address")
	subURL := flag.String("sub", "", "subscription URL or file")
	mode := flag.String("mode", "tun", "operating mode: tun | socks")
	headless := flag.Bool("headless", false, "run in headless mode without GUI window")
	flag.Parse()

	log.Printf("[CLIENT] initializing AERO client (api=%s, listen=%s, mode=%s)...", *apiAddr, *listenAddr, *mode)

	eng := client.NewEngine()
	eng.SetListenAddr(*listenAddr)
	eng.SetMode(*mode)

	if *subURL != "" {
		if _, err := eng.LoadAndApplySubscription(*subURL); err != nil {
			log.Printf("[CLIENT] initial subscription load failed: %v", err)
		} else {
			log.Printf("[CLIENT] initial subscription loaded from %s", *subURL)
		}
	}

	uiFS, err := fs.Sub(uiEmbed, "ui")
	if err != nil {
		log.Fatalf("[CLIENT] failed to extract embedded ui: %v", err)
	}

	mux := http.NewServeMux()

	// 1. 探活与健康检查白名单 (Rule P6)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("OK\n"))
	})

	// 2. 状态查询
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		st := eng.GetState()
		_ = json.NewEncoder(w).Encode(st)
	})

	// 3. 订阅导入
	mux.HandleFunc("/api/v1/import", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Sub string `json:"sub"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Sub == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": "empty subscription URL"})
			return
		}
		applied, err := eng.LoadAndApplySubscription(req.Sub)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"nodes":  len(applied.Servers),
		})
	})

	// 4. 切换工作模式
	mux.HandleFunc("/api/v1/mode", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			Mode string `json:"mode"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Mode != "" {
			eng.SetMode(req.Mode)
		}
		st := eng.GetState()
		UpdateTrayIcon(st.Mode, st.Connected)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "mode": req.Mode})
	})

	// 5. 启动隧道连接
	mux.HandleFunc("/api/v1/connect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := eng.Start(); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": err.Error()})
			return
		}
		st := eng.GetState()
		UpdateTrayIcon(st.Mode, st.Connected)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	})

	// 6. 断开隧道连接
	mux.HandleFunc("/api/v1/disconnect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = eng.Stop()
		st := eng.GetState()
		UpdateTrayIcon(st.Mode, st.Connected)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	})

	// 7. 快速连通性探针 (真实度量，消灭假数据)
	mux.HandleFunc("/api/v1/probe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		st := eng.GetState()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": st.Connected && st.RttMs > 0,
			"ms": st.RttMs,
		})
	})

	// 8. 真实链路延迟二测探针
	mux.HandleFunc("/api/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		rtt, err := eng.PingActiveNode(ctx)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"rtt_ms": rtt.Milliseconds(),
		})
	})

	// 9. GeoData 规则手动同步端点
	mux.HandleFunc("/api/v1/geodata/sync", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		count, updated, err := eng.SyncGeoData(ctx)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"updated": updated,
			"count":   count,
		})
	})

	// 8. 嵌入 Web 前端静态资源
	mux.Handle("/", http.FileServer(http.FS(uiFS)))

	apiServer := &http.Server{
		Addr:    *apiAddr,
		Handler: mux,
	}

	go func() {
		log.Printf("[CLIENT] Web UI & API ready at http://%s", *apiAddr)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[CLIENT] API server failed: %v", err)
		}
	}()

	shutdown := func() {
		log.Println("[CLIENT] stopping engine and api server...")
		_ = eng.Stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = apiServer.Shutdown(shutdownCtx)
		log.Println("[CLIENT] AERO client shutdown complete.")
	}

	uiURL := fmt.Sprintf("http://%s/", *apiAddr)
	if *headless {
		runHeadless(shutdown)
	} else {
		runClientWindow(uiURL, shutdown)
	}
}

func runHeadless(shutdown func()) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	shutdown()
}
