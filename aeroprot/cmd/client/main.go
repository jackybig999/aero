// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"github.com/aero-protocol/aero/aeroprot/internal/client"
)

var (
	connectLimiter = rate.NewLimiter(rate.Every(100*time.Millisecond), 10) // 10 burst, 10 RPS on localhost
	probeLimiter   = rate.NewLimiter(rate.Every(100*time.Millisecond), 10) // 10 burst
)

//go:embed ui/*
var uiEmbed embed.FS

func main() {
	showVer := flag.Bool("version", false, "print version and exit")
	listenAddr := flag.String("listen", "127.0.0.1:55555", "mixed proxy address (SOCKS5/HTTP CONNECT)")
	apiAddr := flag.String("api", "127.0.0.1:19877", "client control API and UI address")
	subURL := flag.String("sub", "", "subscription URL or file")
	mode := flag.String("mode", "tun", "operating mode: tun | socks")
	headless := flag.Bool("headless", false, "run in headless mode without GUI window")
	flag.Parse()

	if *showVer {
		fmt.Printf("aero-client %s (protocol=%s)\n", client.ClientVersion, client.Protocol)
		return
	}

	log.Printf("[CLIENT] initializing AERO client v%s (api=%s, listen=%s, mode=%s)...", client.ClientVersion, *apiAddr, *listenAddr, *mode)

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

	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	sessionToken := hex.EncodeToString(tokenBytes)

	mux := http.NewServeMux()

	// 1. 探活与健康检查白名单 (Rule P6 & U8: 双路由兼容)
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("OK\n"))
	}
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/health", healthHandler)

	// 2. 状态查询 (SEC-03: 白名单脱敏输出)
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		st := eng.GetState()
		resp := map[string]any{
			"connected":      st.Connected,
			"starting":       st.Starting,
			"stopping":       st.Stopping,
			"last_error":     st.LastError,
			"error_code":     st.ErrorCode,
			"conflict_vpn":   st.ConflictVPN,
			"mode":           st.Mode,
			"listen":         st.Listen,
			"active_node":    st.ActiveNode,
			"active_sni":     st.ActiveSNI,
			"actual_port":    st.ActualPort,
			"nodes_count":    st.NodesCount,
			"version":        st.Version,
			"node":           st.Node,
			"sni":            st.SNI,
			"isp":            st.ISP,
			"isp_name":       st.ISPName,
			"rtt_ms":         st.RttMs,
			"probe_ok":       st.ProbeOk,
			"probe_ms":       st.ProbeMs,
			"geo_rule_count": st.GeoRuleCount,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 2b. TUN 虚拟网卡冲撞状态检查 (前置防呆与弹窗指引)
	mux.HandleFunc("/api/v1/tun/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		conflict, vpnName, err := client.DetectThirdPartyTUN()
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":   "ok",
			"conflict": conflict,
			"vpn":      vpnName,
			"error":    errMsg,
			"mode":     eng.GetMode(),
		})
	})

	// 2c. 链式代理配置 (静态住宅出口净化)
	mux.HandleFunc("/api/v1/chain/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			var cfg client.ChainProxyConfig
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, `{"status":"error","error":"invalid json body"}`, http.StatusBadRequest)
				return
			}
			if err := eng.SetChainProxyConfig(cfg); err != nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "config": eng.GetChainProxyConfig()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "config": eng.GetChainProxyConfig()})
	})

	// 2d. 本机 ISP 特化与优选伪装 SNI 查询
	mux.HandleFunc("/api/v1/sni/profile", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		prof := client.LoadSNIProfile()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":   "ok",
			"profile":  prof,
			"top_snis": client.GetOptimalSNIs(),
		})
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

		curSt := eng.GetState()
		if (curSt.Connected || curSt.Starting) && targetMode == "tun" {
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

		needRestart, ticket := eng.PrepareModeSwitch(targetMode)
		if !needRestart {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "mode": targetMode})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"status": "switching", "mode": targetMode})
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[CLIENT] recover mode switch panic: %v", rec)
				}
			}()
			err := eng.Restart(ticket)
			if err != nil && !errors.Is(err, client.ErrStartAborted) && !errors.Is(err, context.Canceled) {
				log.Printf("[CLIENT] mode switch failed: %v, rolling back to %s", err, prevMode)
				eng.SetMode(prevMode)
				t2 := eng.RequestStart()
				_ = eng.StartWith(t2)
			}
			st := eng.GetState()
			UpdateTrayIcon(st.Mode, st.Connected)
		}()
	})

	// 5. 启动隧道连接 (非阻塞异步启动，彻底保障 Win32 UI 消息泵 0ms 阻塞)
	mux.HandleFunc("/api/v1/connect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !connectLimiter.Allow() {
			http.Error(w, `{"status":"error","code":"RATE_LIMITED","msg":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		st := eng.GetState()
		if st.Connected {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":      "ok",
				"active_node": st.ActiveNode,
				"actual_port": st.ActualPort,
			})
			return
		}
		if st.Starting {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "starting",
			})
			return
		}

		ticket := eng.RequestStart()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "starting",
		})

		// 异步启动引擎，保证 Win32 UI 消息泵 0ms 阻塞，界面随时可响应拖动与中断
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[CLIENT] recover connect panic: %v", r)
				}
			}()

			if eng.IsStopping() {
				deadline := time.Now().Add(28 * time.Second)
				for eng.IsStopping() {
					if time.Now().After(deadline) {
						eng.ClearStartPending(ticket)
						eng.SetLastError("timeout waiting for previous stop to finish")
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
			}

			if err := eng.StartWith(ticket); err != nil && !errors.Is(err, client.ErrStartAborted) && !errors.Is(err, context.Canceled) {
				log.Printf("[CLIENT] background connect finished with err: %v", err)
			}
			curSt := eng.GetState()
			UpdateTrayIcon(curSt.Mode, curSt.Connected)
		}()
	})

	// 5b. 中断/取消正在进行的启动流程
	mux.HandleFunc("/api/v1/cancel", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		wasActive := eng.BeginStop()
		if wasActive || eng.IsStopping() {
			go func() {
				defer func() {
					if rec := recover(); rec != nil {
						log.Printf("[CLIENT] recover cancel panic: %v", rec)
					}
				}()
				_ = eng.Stop()
				st := eng.GetState()
				UpdateTrayIcon(st.Mode, st.Connected)
			}()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "state": "stopping"})
	})

	// 6. 断开隧道连接 (非阻塞异步停止，Win32 UI 消息泵 0ms 阻塞)
	mux.HandleFunc("/api/v1/disconnect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !connectLimiter.Allow() {
			http.Error(w, `{"status":"error","code":"RATE_LIMITED","msg":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		wasActive := eng.BeginStop()
		if wasActive || eng.IsStopping() {
			go func() {
				defer func() {
					if rec := recover(); rec != nil {
						log.Printf("[CLIENT] recover disconnect panic: %v", rec)
					}
				}()
				_ = eng.Stop()
				st := eng.GetState()
				UpdateTrayIcon(st.Mode, st.Connected)
			}()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "state": "stopping"})
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

	apiHandler := csrfProtectMiddleware(sessionToken, mux)

	apiServer := &http.Server{
		Addr:    *apiAddr,
		Handler: apiHandler,
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
		runClientWindow(htmlUI, apiHandler, shutdown)
	}
}

// csrfProtectMiddleware 防范跨站 CSRF 攻击与未授权控制
func csrfProtectMiddleware(sessionToken string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/health" ||
			(r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/")) {
			next.ServeHTTP(w, r)
			return
		}

		// 1. 拦截浏览器内核级跨站标记
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs == "cross-site" {
			http.Error(w, `{"status":"error","code":"CSRF_CROSS_SITE_BLOCKED"}`, http.StatusForbidden)
			return
		}

		// 2. 敏感写操作强校验
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			tok := r.Header.Get("X-Aero-Client-Token")
			if tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(sessionToken)) == 1 {
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")
			if origin == "" {
				ref := r.Header.Get("Referer")
				if !isAllowedLocalURL(ref) {
					http.Error(w, `{"status":"error","code":"CSRF_ORIGIN_REQUIRED"}`, http.StatusForbidden)
					return
				}
			} else if !isAllowedLocalURL(origin) {
				http.Error(w, `{"status":"error","code":"CSRF_INVALID_ORIGIN"}`, http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func isAllowedLocalURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "127.0.0.1" || h == "localhost"
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
