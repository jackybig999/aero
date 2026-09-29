package public

import (
	"fmt"
	"github.com/aero-protocol/aero-ech/internal/api"
	appruntime "github.com/aero-protocol/aero-ech/internal/runtime"
	"github.com/aero-protocol/aero-ech/internal/split"
	"github.com/aero-protocol/aero-ech/internal/sub"
	"github.com/aero-protocol/aero-ech/internal/transport"
	"log"
	"strings"
	"sync"
	"sync/atomic"
)

// -----------------------------------------------------------------------------
// Source: runtime_ctl.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// enginePaused 为 true 时拒绝新的 SOCKS 隧道（API disconnect）
var enginePaused atomic.Bool

// sessionOn is the power-button session (sysproxy/TUN/socks intent).
// Mixed 55555 stays up after Disconnect so fingerprint Desktop can still fill the port.
var sessionOn atomic.Bool

var (
	modeMu      sync.RWMutex
	clientMode  = "tun"
	sysProxyOn  bool
	osRuntime   appruntime.Interface
	cleanupOnce sync.Once
)

// apiRuntime 实现 api.Runtime
type apiRuntime struct{}

func ensureOSRuntime() (appruntime.Interface, error) {
	if osRuntime != nil {
		return osRuntime, nil
	}
	cfg := appruntime.DefaultConfig()
	if listenAddr != nil {
		cfg.ProxyAddr = *listenAddr
	}
	rt, err := appruntime.New(cfg)
	if err != nil {
		return nil, err
	}
	osRuntime = rt
	return rt, nil
}

func (apiRuntime) Connect() error {
	if raw := sub.LoadLastBody(); len(raw) > 0 {
		if s, err := sub.ParseBytes(raw); err == nil && s != nil {
			if s.IsExpired() {
				return fmt.Errorf("当前订阅已到期或已被中台关闭，请续费或联系管理员重新开启")
			}
		}
	}
	if err := startMixedListen(); err != nil {
		return fmt.Errorf("混合口监听失败: %w", err)
	}
	wasPaused := enginePaused.Swap(false)
	if wasPaused {
		transport.GlobalSessionPool.Reset()
	}
	log.Printf("[API] connect: accepting tunnels")
	modeMu.RLock()
	m := clientMode
	modeMu.RUnlock()
	switch m {
	case "tun":
		clearSysProxySafe()
		if err := startTUNIfPossible(); err != nil {
			log.Printf("[API] TUN unavailable (%v); not falling back to sysproxy", err)
			return err
		}
		log.Printf("[API] TUN up, system proxy OFF (127.0.0.1:55555 resident in background)")
	case "sysproxy":
		stopTUN()
		if err := enableSystemProxy(); err != nil {
			return fmt.Errorf("系统代理接管失败: %w", err)
		}
	default:
		clearSysProxySafe()
		if err := startTUNIfPossible(); err != nil {
			log.Printf("[API] TUN unavailable (%v)", err)
			return err
		}
		log.Printf("[API] TUN up, system proxy OFF (127.0.0.1:55555 resident in background)")
	}
	sessionOn.Store(true)
	return nil
}

func (apiRuntime) Disconnect() error {
	sessionOn.Store(false)
	stopTUN()
	clearSysProxySafe()
	// 本地模式常驻：保持 127.0.0.1:55555 混合口后台常开，供指纹浏览器/应用随时连接
	transport.GlobalSessionPool.Reset()
	log.Printf("[API] disconnect: TUN/sysproxy stopped, mixed port 55555 resident, session pool reset")
	return nil
}

// enableSystemProxy points Windows IE/WinHTTP proxy at local mixed port.
func enableSystemProxy() error {
	addr := (apiRuntime{}).ListenAddr()
	rt, err := ensureOSRuntime()
	if err != nil {
		return err
	}
	// Always re-apply. Skipping when sysProxyOn was already true (TUN also
	// writes WinINET) meant tun→sysproxy never refreshed Chrome's proxy cache
	// or QUIC policy.
	if err := rt.SetSystemProxy(addr); err != nil {
		return err
	}
	sysProxyOn = true
	modeMu.RLock()
	lockQUIC := clientMode == "sysproxy"
	modeMu.RUnlock()
	hint := appruntime.ApplyBrowserLockOn(lockQUIC, addr)
	startCrashGuard()
	if hint != "" {
		if srv := getAPIServer(); srv != nil {
			srv.UpdateState(func(st *api.AppState) {
				st.Hint = hint
				if strings.Contains(hint, "管理员") {
					st.LastError = hint
				}
			})
		}
	}
	log.Printf("[API] system proxy ON -> %s (disconnect/exit will release)", addr)
	return nil
}

// clearSysProxySafe restores / clears system proxy set by us (and AERO leftovers).
func clearSysProxySafe() {
	if rt, err := ensureOSRuntime(); err == nil {
		if err := rt.ClearSystemProxy(); err != nil {
			log.Printf("[API] ClearSystemProxy: %v", err)
		}
	} else {
		appruntime.ForceClearSystemProxy()
	}
	sysProxyOn = false
	log.Printf("[API] system proxy OFF (released)")
}

// cleanupOnExit is registered for SIGINT/SIGTERM and process exit.
func cleanupOnExit() {
	cleanupOnce.Do(func() {
		clearSysProxySafe()
		appruntime.ForceClearSystemProxy()
		stopTUN()
		stopMixedListen()
		transport.GlobalSessionPool.Reset()
		log.Printf("[EXIT] system proxy / TUN / mixed / sessions released")
	})
}

func (apiRuntime) IsRunning() bool {
	return sessionOn.Load()
}

func (apiRuntime) ActiveNode() string {
	if edgeAddr == nil {
		return ""
	}
	return *edgeAddr
}

func (apiRuntime) Nodes() []api.NodeInfo {
	if edgePool == nil {
		return nil
	}
	active := ""
	if edgeAddr != nil {
		active = *edgeAddr
	}
	snap := edgePool.Snapshot()
	out := make([]api.NodeInfo, 0, len(snap))
	for _, n := range snap {
		name := n.Name
		if name == "" {
			name = n.Address
		}
		out = append(out, api.NodeInfo{
			Name:      name,
			Address:   n.Address,
			Reachable: n.Reachable,
			RTTMs:     n.RTT.Milliseconds(),
			Active:    n.Address == active,
		})
	}
	return out
}

func (apiRuntime) ImportSub(src string) error {
	src = strings.TrimSpace(src)
	if src != "" && subURL != nil {
		*subURL = src
	}
	app, err := loadAndApplySubscription(src)
	if err != nil {
		return err
	}
	if edgePool != nil {
		best := edgePool.Best()
		if best == nil || !best.Reachable {
			return fmt.Errorf("no reachable edge after import")
		}
	}
	startSubRefreshLoop(src, app)
	go runISPAndPathProbe()
	log.Printf("[API] import sub ok, edge=%s", app.EdgeAddresses)
	return nil
}

func (apiRuntime) AIStats() map[string]interface{} {
	s := aimetrics.Default.Snapshot()
	// 转为 map 便于 JSON 扩展
	return map[string]interface{}{
		"ai_sessions":   s.AISessions,
		"ftl_count":     s.FTLCount,
		"ftl_avg_ms":    s.FTLAvgMs,
		"ftl_last_ms":   s.FTLLastMs,
		"ftl_p50_ms":    s.FTLP50Ms,
		"ftl_p95_ms":    s.FTLP95Ms,
		"bytes_sent_ai": s.BytesSentAI,
		"bytes_recv_ai": s.BytesRecvAI,
		"last_host":     s.LastHost,
		"last_model":    s.LastModel,
		"last_at_unix":  s.LastAtUnix,
		"recent_ftl_ms": s.RecentFTLMs,
		"note":          s.Note,
	}
}

func (apiRuntime) SwitchNode(addr string) error {
	if addr == "" {
		return fmt.Errorf("empty node")
	}
	if edgePool != nil && !edgePool.HasAddress(addr) {
		// 允许切到池内配置地址；若池为空则仍允许显式地址（单节点手动模式）
		if edgePool.Count() > 0 {
			return fmt.Errorf("node %s not in pool", addr)
		}
	}
	switchActiveNodeByAddr(addr)
	log.Printf("[API] switch node -> %s", addr)
	return nil
}

func (apiRuntime) Mode() string {
	modeMu.RLock()
	defer modeMu.RUnlock()
	return clientMode
}

func (apiRuntime) ListenAddr() string {
	if listenAddr == nil {
		return "127.0.0.1:55555"
	}
	return *listenAddr
}

func (apiRuntime) SubSource() string {
	if subURL == nil {
		return ""
	}
	return *subURL
}

// Probe runs a live Google check through local mixed port.
func (apiRuntime) Probe() map[string]interface{} {
	listen := "127.0.0.1:55555"
	if listenAddr != nil && *listenAddr != "" {
		listen = *listenAddr
	}
	r := probeThroughLocalProxy(listen)
	return map[string]interface{}{
		"ok":        r.OK,
		"ms":        r.MS,
		"http_code": r.Code,
		"target":    r.Target,
		"via":       r.Via,
		"error":     r.Error,
		"detail":    r.Detail,
		"engine":    !enginePaused.Load(),
		"mode":      (apiRuntime{}).Mode(),
		"listen":    listen,
		"node":      (apiRuntime{}).ActiveNode(),
	}
}

func (apiRuntime) ISPInfo() (string, string) {
	if detectedISP == 0 {
		return "unknown", "自动探测中"
	}
	switch detectedISP {
	case split.ChinaTelecom:
		return "china_telecom", "中国电信 (China Telecom)"
	case split.ChinaUnicom:
		return "china_unicom", "中国联通 (China Unicom)"
	case split.ChinaMobile:
		return "china_mobile", "中国移动 (China Mobile)"
	case split.ChinaBroadcast:
		return "china_broadcast", "中国广电 (China Broadcast)"
	default:
		return detectedISP.String(), detectedISP.String()
	}
}

func (apiRuntime) ActiveSNI() string {
	return currentEdgeSNI()
}

var setModeMu sync.Mutex

func (apiRuntime) SetMode(mode string) error {
	setModeMu.Lock()
	defer setModeMu.Unlock()
	mode = strings.ToLower(strings.TrimSpace(mode))
	// Modes:
	//   sysproxy — local mixed + Windows system proxy (default product path)
	//   socks    — local mixed only (manual app proxy)
	//   tun      — optional global capture (admin + wintun)
	switch mode {
	case "sysproxy", "system", "auto":
		mode = "sysproxy"
	case "socks", "local", "mixed":
		mode = "socks"
	case "tun":
		// ok
	default:
		return fmt.Errorf("mode must be sysproxy|socks|tun")
	}
	if err := startMixedListen(); err != nil {
		return fmt.Errorf("混合口监听失败: %w", err)
	}
	// Commit mode BEFORE proxy/TUN so QUIC lock matches the target
	// (tun→sysproxy used to keep lockQUIC=false and delete the Chrome UDP/443 rule).
	modeMu.Lock()
	prevMode := clientMode
	clientMode = mode
	modeMu.Unlock()
	if mode != "tun" {
		stopTUN()
	}
	if (mode == "socks" || mode == "tun") && sysProxyOn {
		clearSysProxySafe()
	}
	switch mode {
	case "sysproxy":
		if sessionOn.Load() {
			if err := enableSystemProxy(); err != nil {
				return err
			}
			log.Printf("[API] mode sysproxy: mixed %v + system proxy", listenAddr)
		} else {
			log.Printf("[API] mode sysproxy selected (will apply when connected)")
		}
	case "socks":
		appruntime.ApplySocksPrivacy()
		log.Printf("[API] mode socks: local mixed only %v (zero system modification)", listenAddr)
	case "tun":
		if sessionOn.Load() {
			if err := startTUNIfPossible(); err != nil {
				modeMu.Lock()
				clientMode = prevMode
				modeMu.Unlock()
				if prevMode == "sysproxy" && sessionOn.Load() {
					if e2 := enableSystemProxy(); e2 != nil {
						log.Printf("[API] TUN fail, restore sysproxy: %v", e2)
					}
				}
				return err
			}
			if sysProxyOn {
				clearSysProxySafe()
			}
			log.Printf("[API] mode tun: global capture, mixed %v, no system proxy", listenAddr)
		} else {
			log.Printf("[API] mode tun selected (will apply when connected)")
		}
	}
	log.Printf("[API] mode -> %s", mode)
	return nil
}

// -----------------------------------------------------------------------------
// Source: api_state.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

var (
	apiMu  sync.RWMutex
	apiSrv *api.Server
)

func setAPIServer(s *api.Server) {
	apiMu.Lock()
	apiSrv = s
	apiMu.Unlock()
}

func getAPIServer() *api.Server {
	apiMu.RLock()
	defer apiMu.RUnlock()
	return apiSrv
}

// reportTunnelUp 隧道建立成功时更新 API 状态（供 UI 轮询）
func reportTunnelUp(node, proto string) {
	apiMu.RLock()
	s := apiSrv
	apiMu.RUnlock()
	if s == nil {
		return
	}
	s.UpdateState(func(st *api.AppState) {
		st.Connected = sessionOn.Load()
		st.Node = node
		st.Protocol = proto
	})
}

// reportAIFTL 刷新 API 中的 FTL 展示字段
func reportAIFTL(ms uint64) {
	apiMu.RLock()
	s := apiSrv
	apiMu.RUnlock()
	if s == nil {
		return
	}
	s.UpdateState(func(st *api.AppState) {
		st.FTLAvgMs = ms // 瞬时展示；完整统计见 /api/v1/ai/stats
	})
}

// reportTraffic 累加全局流量到 API 状态
func reportTraffic(sent, recv uint64) {
	apiMu.RLock()
	s := apiSrv
	apiMu.RUnlock()
	if s == nil {
		return
	}
	s.UpdateState(func(st *api.AppState) {
		st.BytesSent += sent
		st.BytesRecv += recv
	})
}
