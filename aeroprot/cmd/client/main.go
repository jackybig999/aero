// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"github.com/aero-protocol/aero/aeroprot/internal/client"
)

var (
	connectLimiter = rate.NewLimiter(rate.Every(time.Second), 1)          // 1 RPS
	probeLimiter   = rate.NewLimiter(rate.Every(200*time.Millisecond), 5) // 5 RPS
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

	// 4. 切换工作模式 (前置探测防冲撞、严格模式校验、故障原子恢复)
	mux.HandleFunc("/api/v1/mode", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !connectLimiter.Allow() {
			http.Error(w, `{"status":"error","code":"RATE_LIMITED","msg":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": "invalid json body"})
			return
		}
		targetMode := strings.TrimSpace(req.Mode)
		if targetMode != "sysproxy" && targetMode != "tun" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  fmt.Sprintf("unsupported mode: %q (only 'tun' or 'sysproxy' allowed)", targetMode),
				"mode":   eng.GetMode(),
			})
			return
		}

		prevMode := eng.GetMode()
		if targetMode == prevMode {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "mode": targetMode})
			return
		}

		wasRunning := eng.IsRunning()

		// 若当前已连通且目标为 TUN 模式，先做探测，命中绝不停掉当前 sysproxy！
		if wasRunning && targetMode == "tun" {
			conflict, vpnName, err := client.DetectThirdPartyTUN()
			if err != nil {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"error":  fmt.Sprintf("检测第三方 TUN 失败: %v", err),
					"mode":   prevMode,
				})
				return
			}
			if conflict {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"code":   "CONFLICT_TUN",
					"vpn":    vpnName,
					"error":  (&client.ErrConflictingTUN{VPNName: vpnName}).Error(),
					"mode":   prevMode,
				})
				return
			}
		}

		if wasRunning {
			_ = eng.Stop()
		}
		eng.SetMode(targetMode)

		if wasRunning {
			if err := eng.Start(); err != nil {
				// 切换后启动新模式失败：必须回滚模式，并尝试把原模式重新拉起来！
				eng.SetMode(prevMode)
				_ = eng.Start()

				st := eng.GetState()
				UpdateTrayIcon(st.Mode, st.Connected)

				var conflictErr *client.ErrConflictingTUN
				if errors.As(err, &conflictErr) {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"status": "error",
						"code":   "CONFLICT_TUN",
						"vpn":    conflictErr.VPNName,
						"error":  err.Error(),
						"mode":   prevMode,
					})
					return
				}
				if errors.Is(err, client.ErrUDPUnavailable) || strings.Contains(err.Error(), "UDP_UNAVAILABLE") {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"status": "error",
						"code":   "UDP_UNAVAILABLE",
						"error":  "UDP_UNAVAILABLE",
						"msg":    "UDP/443 (QUIC/HTTP/3) 拨号失败，已降级防御：未开启全局 TUN，55555 代理端口照常监听",
						"mode":   prevMode,
					})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"error":  err.Error(),
					"mode":   prevMode,
				})
				return
			}
		}

		st := eng.GetState()
		UpdateTrayIcon(st.Mode, st.Connected)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "mode": targetMode})
	})

	// 5. 启动隧道连接
	mux.HandleFunc("/api/v1/connect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !connectLimiter.Allow() {
			http.Error(w, `{"status":"error","code":"RATE_LIMITED","msg":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		if err := eng.Start(); err != nil {
			var conflictErr *client.ErrConflictingTUN
			if errors.As(err, &conflictErr) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"code":   "CONFLICT_TUN",
					"vpn":    conflictErr.VPNName,
					"error":  err.Error(),
				})
				return
			}
			if errors.Is(err, client.ErrUDPUnavailable) || strings.Contains(err.Error(), "UDP_UNAVAILABLE") {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "error",
					"code":   "UDP_UNAVAILABLE",
					"error":  "UDP_UNAVAILABLE",
					"msg":    "UDP/443 (QUIC/HTTP/3) 拨号失败，已降级防御：未开启全局 TUN，55555 代理端口照常监听",
				})
				return
			}
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
		if !connectLimiter.Allow() {
			http.Error(w, `{"status":"error","code":"RATE_LIMITED","msg":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		_ = eng.Stop()
		st := eng.GetState()
		UpdateTrayIcon(st.Mode, st.Connected)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	})

	// 7. 快速连通性探针 (真实度量，消灭假数据)
	mux.HandleFunc("/api/v1/probe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !probeLimiter.Allow() {
			http.Error(w, `{"status":"error","code":"RATE_LIMITED","msg":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		st := eng.GetState()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": st.Connected && st.RttMs > 0,
			"ms": st.RttMs,
		})
	})

	// 8. 真实链路延迟二测探针
	mux.HandleFunc("/api/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !probeLimiter.Allow() {
			http.Error(w, `{"status":"error","code":"RATE_LIMITED","msg":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
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

	// 10. 供应商线路节点列表
	mux.HandleFunc("/api/v1/nodes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		nodes := eng.GetNodes()
		if nodes == nil {
			nodes = []client.NodeInfo{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"nodes":  nodes,
		})
	})

	// 11. 供应商线路并发测速
	mux.HandleFunc("/api/v1/nodes/probe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !probeLimiter.Allow() {
			http.Error(w, `{"status":"error","code":"RATE_LIMITED","msg":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		nodes := eng.ProbeAllNodes(ctx)
		if nodes == nil {
			nodes = []client.NodeInfo{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"nodes":  nodes,
		})
	})

	// 12. 切换激活节点 (无感热切线)
	mux.HandleFunc("/api/v1/nodes/select", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Address string `json:"address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Address == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": "invalid address"})
			return
		}
		if err := eng.SwitchActiveNode(req.Address); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": err.Error()})
			return
		}
		st := eng.GetState()
		UpdateTrayIcon(st.Mode, st.Connected)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"active": req.Address,
		})
	})

	// 13. 嵌入 Web 前端静态资源
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

	htmlUI := getClientHTMLUI(uiFS)
	if *headless {
		runHeadless(shutdown)
	} else {
		runClientWindow(htmlUI, mux, shutdown)
	}
}

func getClientHTMLUI(uiFS fs.FS) string {
	indexBytes, err := fs.ReadFile(uiFS, "index.html")
	if err != nil {
		return "<html><body><h3>Failed to load UI</h3></body></html>"
	}
	html := string(indexBytes)

	if cssBytes, err := fs.ReadFile(uiFS, "style.css"); err == nil {
		cssTag := fmt.Sprintf("<style>\n%s\n</style>", string(cssBytes))
		html = strings.Replace(html, `<link rel="stylesheet" href="style.css" />`, cssTag, 1)
	}
	if jsqrBytes, err := fs.ReadFile(uiFS, "jsqr.js"); err == nil {
		tag := fmt.Sprintf("<script>\n%s\n</script>", string(jsqrBytes))
		html = strings.Replace(html, `<script src="jsqr.js"></script>`, tag, 1)
	}
	if i18nBytes, err := fs.ReadFile(uiFS, "i18n.js"); err == nil {
		tag := fmt.Sprintf("<script>\n%s\n</script>", string(i18nBytes))
		html = strings.Replace(html, `<script src="i18n.js"></script>`, tag, 1)
	}
	if appBytes, err := fs.ReadFile(uiFS, "app.js"); err == nil {
		tag := fmt.Sprintf("<script>\n%s\n</script>", string(appBytes))
		html = strings.Replace(html, `<script src="app.js"></script>`, tag, 1)
	}

	return html
}

func runHeadless(shutdown func()) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	shutdown()
}
