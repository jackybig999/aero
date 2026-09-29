package public

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aero-protocol/aero-ech/internal/config"
	"github.com/aero-protocol/aero-ech/internal/edgepool"
	"github.com/aero-protocol/aero-ech/internal/split"
	"github.com/aero-protocol/aero-ech/internal/sub"
	"github.com/aero-protocol/aero-ech/internal/transport"
	"github.com/aero-protocol/aero-ech/internal/tun"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// -----------------------------------------------------------------------------
// Source: main.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// CLI flags
var (
	listenAddr   = flag.String("listen", "127.0.0.1:55555", "mixed proxy: HTTP+HTTPS CONNECT+SOCKS5 (one port)")
	edgeAddr     = flag.String("edge", "", "AERO edge server address(es)")
	token        = flag.String("token", "", "auth token")
	publicName   = flag.String("sni", "cdn-aero.com", "pseudo SNI for ECH")
	subURL       = flag.String("sub", "", "subscription URL or file")
	subServer    = flag.String("server", "", "subscription platform server URL (e.g. http://127.0.0.1:18080)")
	subUser      = flag.String("user", "", "subscription account username")
	subPass      = flag.String("pass", "", "subscription account password")
	subInterval  = flag.Duration("sub-interval", 30*time.Minute, "subscription refresh interval (0=disable)")
	fingerprint  = flag.String("fingerprint", "std", "TLS fingerprint: std|chrome|firefox|safari|random (std=compatible)")
	enableSplit  = flag.Bool("split", true, "enable smart traffic splitting")
	echConfigB64 = flag.String("ech", "", "base64-encoded ECH config list")
	caCertPath   = flag.String("ca-cert", "", "CA certificate file for Edge server verification")
	tlsInsecure  = flag.Bool("insecure", false, "skip TLS certificate verify (dev/self-signed only)")
	configPath   = flag.String("config", "", "path to AERO config YAML/JSON file")
	simOnly      = flag.Bool("sim", false, "simulate data plane (TCP/UDP/gVisor) and exit; no proxy, no wintun")
	initMode     = flag.String("mode", "", "startup mode: tun|sysproxy|socks (empty = tun, or sysproxy if other global)")
)

var edgeAddrMu sync.RWMutex

func getEdgeAddr() string {
	edgeAddrMu.RLock()
	defer edgeAddrMu.RUnlock()
	if edgeAddr == nil {
		return ""
	}
	return *edgeAddr
}

func switchActiveNode(srv *edgepool.Server) {
	if srv == nil || srv.Address == "" {
		return
	}
	edgeAddrMu.Lock()
	if edgeAddr != nil {
		*edgeAddr = srv.Address
	}
	if srv.Token != "" && token != nil {
		*token = srv.Token
	}
	sni := srv.SNI
	if srv.Address != "" {
		host, _, err := net.SplitHostPort(srv.Address)
		if err == nil && net.ParseIP(host) == nil && host != "" {
			if sni == "" || sni == "cdn-aero.com" || sni == "edge.microsoft.com" || sni == "azureedge.net" || sni == "cloudflare.com" {
				sni = host
			}
		}
	}
	if sni != "" && publicName != nil {
		*publicName = sni
	}
	if len(srv.PinSPKI) > 0 {
		certloader.AddPins(srv.PinSPKI)
	}
	curEdge := ""
	curSNI := ""
	if edgeAddr != nil {
		curEdge = *edgeAddr
	}
	if publicName != nil {
		curSNI = *publicName
	}
	edgeAddrMu.Unlock()

	transport.GlobalSessionPool.Reset()
	log.Printf("[NODE] active node switched to %s (sni=%s)", curEdge, curSNI)
}

func switchActiveNodeByAddr(addr string) {
	if addr == "" {
		return
	}
	if edgePool != nil {
		if srv := edgePool.FindServer(addr); srv != nil {
			switchActiveNode(srv)
			return
		}
	}
	edgeAddrMu.Lock()
	if edgeAddr != nil {
		*edgeAddr = addr
	}
	sni := ""
	host, _, err := net.SplitHostPort(addr)
	if err == nil && net.ParseIP(host) == nil && host != "" {
		sni = host
	}
	if sni != "" && publicName != nil {
		*publicName = sni
	}
	curSNI := ""
	if publicName != nil {
		curSNI = *publicName
	}
	edgeAddrMu.Unlock()
	transport.GlobalSessionPool.Reset()
	log.Printf("[NODE] active node switched to %s (sni=%s fallback)", addr, curSNI)
}

func setEdgeAddr(addr string) {
	switchActiveNodeByAddr(addr)
}

// process-wide engine state
var (
	splitEngine      *split.Engine
	detectedISP      split.ISPType
	testedPorts      []uint32
	udpAvailable     bool
	switchEngine     *edgepool.SwitchEngine
	edgePool         *edgepool.Pool
	contextIDCounter atomic.Uint64
	aiContextSent    sync.Map
)

func stripProcessProxyEnv() {
	// Never let our own process use HTTP_PROXY=127.0.0.1:55555 (set for AI tools).
	// That makes subscription fetch loop into a dead mixed port and look like a crash.
	for _, k := range []string{
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY",
		"http_proxy", "https_proxy", "all_proxy", "ftp_proxy",
	} {
		_ = os.Unsetenv(k)
	}
}

type lastAccount struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func saveLastAccount(server, user, pass string) {
	acc := lastAccount{Server: server, Username: user, Password: pass}
	b, err := json.Marshal(acc)
	if err != nil {
		return
	}
	var paths []string
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), ".last-sub-acc"))
	}
	if wd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(wd, ".last-sub-acc"))
	}
	for _, p := range paths {
		_ = os.WriteFile(p, b, 0o600)
	}
}

func loadLastAccount() *lastAccount {
	var cands []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		cands = append(cands,
			filepath.Join(dir, ".last-sub-acc"),
			filepath.Join(dir, "..", ".last-sub-acc"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		cands = append(cands, filepath.Join(wd, ".last-sub-acc"))
	}
	for _, p := range cands {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var acc lastAccount
		if err := json.Unmarshal(b, &acc); err == nil && acc.Server != "" && acc.Username != "" && acc.Password != "" {
			return &acc
		}
	}
	return nil
}

var logFile *os.File

func setupFileLog() {
	dir := ""
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	if dir == "" {
		dir, _ = os.Getwd()
	}
	name := "aero-ech.log"
	if exe, err := os.Executable(); err == nil {
		base := strings.TrimSuffix(filepath.Base(exe), filepath.Ext(exe))
		if base != "" {
			name = base + ".log"
		}
	}
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("[LOG] open %s: %v", path, err)
		return
	}
	logFile = f
	log.SetOutput(io.MultiWriter(f, os.Stderr))
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("[LOG] ===== session start pid=%d file=%s =====", os.Getpid(), path)
}

func healLeftoverAeroDNS() {
	show := exec.Command("netsh", "interface", "show", "interface")
	hideConsole(show)
	out, err := show.Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "Connected") && !strings.Contains(line, "已连接") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := strings.Join(fields[3:], " ")
		low := strings.ToLower(name)
		if strings.Contains(low, "sing") || strings.Contains(low, "loopback") || strings.Contains(low, "meta") || strings.Contains(low, "clash") {
			continue
		}
		dnsCmd := exec.Command("netsh", "interface", "ip", "show", "dns", "name="+name)
		hideConsole(dnsCmd)
		cfg, err := dnsCmd.Output()
		if err != nil || !strings.Contains(string(cfg), "10.88.0.2") {
			continue
		}
		dhcp := exec.Command("netsh", "interface", "ip", "set", "dns", "name="+name, "dhcp")
		hideConsole(dhcp)
		_ = dhcp.Run()
		log.Printf("[NET] restored DHCP DNS on %s (cleared leftover 10.88.0.2)", name)
	}
}

func acceptMixed(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(30 * time.Second)
		}
		go handleMixedClient(conn)
	}
}

// applyConfig 灏嗛厤缃枃浠剁殑鍊艰鐩栧埌鏈樉寮忚缃殑 flag 涓?// 鍘熷垯锛氬懡浠よ flag 鏄惧紡璁剧疆鐨勫€间紭鍏堜簬閰嶇疆鏂囦欢
func applyConfig(cfg *config.AeroConfig) {
	c := &cfg.Client

	// flag 涓洪粯璁ゅ€兼椂锛岀敤閰嶇疆鏂囦欢瑕嗙洊
	if (*listenAddr == "127.0.0.1:1080" || *listenAddr == "127.0.0.1:55555") && c.Listen.SOCKS5 != "" {
		*listenAddr = c.Listen.SOCKS5
	}
	if *publicName == "cdn-aero.com" && c.Edge.Transport.ECH.Enabled {
		// SNI 淇濇寔 flag 榛樿鎴栦粠绗竴涓?edge 鑺傜偣璇诲彇
	}
	if *fingerprint == "chrome" && c.Edge.Transport.Fingerprint != "" {
		*fingerprint = c.Edge.Transport.Fingerprint
	}

	// Edge 鑺傜偣锛氶厤缃枃浠朵腑鐨勭涓€涓妭鐐逛綔涓?-edge
	if *edgeAddr == "" && len(c.Edge.Pool) > 0 {
		*edgeAddr = c.Edge.Pool[0].Address
	}
	if *token == "" && len(c.Edge.Pool) > 0 && c.Edge.Pool[0].Token != "" {
		*token = c.Edge.Pool[0].Token
	}

	// 澶氳妭鐐癸細鏋勫缓閫楀彿鍒嗛殧鐨勫湴鍧€鍒楄〃
	if len(c.Edge.Pool) > 1 && !strings.Contains(*edgeAddr, ",") {
		addrs := make([]string, len(c.Edge.Pool))
		for i, n := range c.Edge.Pool {
			addrs[i] = n.Address
		}
		*edgeAddr = strings.Join(addrs, ",")
	}

	// Split
	if c.Split.Enabled {
		*enableSplit = true
	}

	// ECH
	if c.Edge.Transport.ECH.Enabled && c.Edge.Transport.ECH.ConfigB64 != "" {
		*echConfigB64 = c.Edge.Transport.ECH.ConfigB64
	}

	// CA cert
	if *caCertPath == "" && len(c.Edge.Pool) > 0 && c.Edge.Pool[0].CACert != "" {
		*caCertPath = c.Edge.Pool[0].CACert
	}
}

func Version() string {
	return "aerosys v1.0.0"
}

// startTUN 鍚姩 TUN 妯″紡寮曟搸
func startTUN(cfg *config.AeroConfig) {
	c := &cfg.Client
	log.Printf("[TUN] Starting TUN mode: device=%s mtu=%d ipv4=%s",
		c.TUN.Device, c.TUN.MTU, c.TUN.IPv4)

	dev, err := tun.NewDevice(c.TUN.Device, c.TUN.MTU)
	if err != nil {
		log.Printf("[TUN] Failed to create device: %v", err)
		return
	}
	defer dev.Close()

	// 閰嶇疆绯荤粺璺敱
	if err := tun.SetupRoutes(dev.Name(), c.TUN.IPv4, c.TUN.IPv6, c.TUN.Routes); err != nil {
		log.Printf("[TUN] Failed to setup routes: %v", err)
		return
	}
	defer tun.TeardownRoutes(dev.Name())

	// 閰嶇疆 DNS
	tun.SetupDNS(c.TUN.DNS.Servers)
	defer tun.TeardownDNS()

	// 鍒涘缓寮曟搸
	engineCfg := tun.Config{
		MTU:          c.TUN.MTU,
		IPv4:         c.TUN.IPv4,
		IPv6:         c.TUN.IPv6,
		Routes:       c.TUN.Routes,
		DNSServers:   c.TUN.DNS.Servers,
		FakeIPRange:  c.TUN.DNS.FakeIP.Range,
		FakeIPEnable: c.TUN.DNS.FakeIP.Enabled,
	}

	splitDecider := &tunSplitAdapter{engine: splitEngine}
	dialer := &tunDialAdapter{edgeAddr: edgeAddr, token: token, publicName: publicName, fingerprint: fingerprint}

	engine := tun.New(dev, engineCfg, splitDecider, dialer)
	if err := engine.Start(); err != nil {
		log.Printf("[TUN] Engine error: %v", err)
	}
}

// tunSplitAdapter 閫傞厤 split.Engine 鈫?tun.SplitDecider
type tunSplitAdapter struct {
	engine *split.Engine
}

func (a *tunSplitAdapter) Decide(domain string) string {
	if a.engine == nil {
		return "proxy"
	}
	return a.engine.MatchDomain(domain).String()
}

// tunDialAdapter kept for config-path startTUN; prefers AERO path.
type tunDialAdapter struct {
	edgeAddr    *string
	token       *string
	publicName  *string
	fingerprint *string
}

func (a *tunDialAdapter) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return (&tunAERODialer{}).DialTCP(ctx, addr)
}

func (a *tunDialAdapter) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return (&tunAERODialer{}).DialUDP(ctx, addr)
}

func init() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
}

// -----------------------------------------------------------------------------
// Source: engine_bg.go
// -----------------------------------------------------------------------------
var (
	subLoopMu     sync.Mutex
	subLoopCancel context.CancelFunc
	bgOnce        sync.Once
)

func startBackgroundServices() {
	bgOnce.Do(func() {
		switchEngine = edgepool.NewSwitchEngine(edgepool.DefaultSwitchConfig())
		go switchEngine.StartMonitor(context.Background())
		log.Printf("[SWITCHER] Engine started")

		netMonitor := monitor.New(func(ev Event) {
			log.Printf("[MONITOR] Network change: %s", ev.String())
			scheduleTUNRefresh(ev.String())
			if edgePool != nil {
				go func() {
					edgePool.ProbeAll(0)
					best := edgePool.Best()
					current := getEdgeAddr()
					if best != nil && best.Reachable && best.Address != "" && best.Address != current {
						log.Printf("[MONITOR] Best Edge server changed: %s -> %s", current, best.Address)
						setEdgeAddr(best.Address)
					}
				}()
			}
		})
		netMonitor.Start()
		netMonitor.StartPlatformMonitor()
		log.Printf("[MONITOR] Network monitor started")

		// 睡眠/唤醒时钟跳变感知器：休眠唤醒后 5 秒以上时间跳跃立即触发会话重置与 TUN 路由原子重迁
		go func() {
			lastTick := time.Now()
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for t := range ticker.C {
				if t.Sub(lastTick) > 5*time.Second {
					log.Printf("[MONITOR] Clock jump detected (%v elapsed) - system woke from sleep/suspend", t.Sub(lastTick))
					transport.GlobalSessionPool.Reset()
					scheduleTUNRefresh("wake_from_sleep")
				}
				lastTick = t
			}
		}()

		go runISPAndPathProbe()
	})
}

func startSubRefreshLoop(src string, initial *sub.Applied) {
	src = strings.TrimSpace(src)
	subLoopMu.Lock()
	defer subLoopMu.Unlock()
	if subLoopCancel != nil {
		subLoopCancel()
		subLoopCancel = nil
	}
	if src == "" || subInterval == nil || *subInterval <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	subLoopCancel = cancel
	ispHint := ""
	if detectedISP != 0 {
		ispHint = detectedISP.String()
	}
	loop := sub.NewLoop(sub.LoopConfig{
		Source:   src,
		Interval: *subInterval,
		Fetch: sub.FetchOptions{
			InsecureSkipVerify: certloader.ShouldSkipVerify(),
			ISPHint:            ispHint,
		},
		OnChange: func(app *sub.Applied) error {
			return applySubscription(app)
		},
	})
	if initial != nil {
		loop.SetLastKey(initial.SnapshotKey())
	}
	go loop.Run(ctx)
	log.Printf("[SUB] refresh every %s from %s", *subInterval, src)
}

func runISPAndPathProbe() {
	if edgePool == nil {
		return
	}
	detector := split.NewISPDetector()
	gotISP, ispResults := detector.Detect()
	detectedISP = gotISP
	log.Printf("[ISP] %s", split.ISPReport(gotISP, ispResults))

	edgePool.ProbeAll(0)
	log.Printf("[POOL] Edge nodes: %v", edgePool.AllAddresses())
	bestServer := edgePool.Best()
	if bestServer == nil || !bestServer.Reachable {
		log.Printf("[PROBE] edge not reachable yet; mixed/API stay up")
		return
	}
	if edgeAddr != nil {
		setEdgeAddr(bestServer.Address)
	}
	for _, s := range edgePool.AllAddresses() {
		host, portStr, _ := net.SplitHostPort(s)
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		pr := edgepool.NewProbeWithPreferredPort(host, port)
		res := pr.Run()
		for _, r := range res {
			if r.Reachable {
				testedPorts = append(testedPorts, uint32(r.Path.Port))
			}
		}
	}
	selectedEdge := getEdgeAddr()
	if selectedEdge == "" {
		return
	}
	host, portStr, _ := net.SplitHostPort(selectedEdge)
	var preferredPort int
	fmt.Sscanf(portStr, "%d", &preferredPort)
	udpAvailable = probeUDP(host, preferredPort)
	log.Printf("[UDP] available=%v", udpAvailable)
	log.Printf("[PROBE] Selected best server: %s", selectedEdge)
}

// -----------------------------------------------------------------------------
// Source: subscription.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// loadSubscription 拉取订阅并写入全局 edge/token/sni（不重建 pool）
func loadSubscription(src string) (*sub.Applied, error) {
	ispHint := ""
	if detectedISP != 0 {
		ispHint = detectedISP.String()
	}
	doc, err := sub.Fetch(src, sub.FetchOptions{
		InsecureSkipVerify: certloader.ShouldSkipVerify(),
		ISPHint:            ispHint,
	})
	if err != nil {
		if raw := sub.LoadLastBody(); len(raw) > 0 {
			cached, perr := sub.ParseBytes(raw)
			if perr == nil {
				log.Printf("[SUB] fetch failed (%v); using last cached subscription", err)
				doc, err = cached, nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if doc.IsExpired() {
		sub.ClearLastBody()
		return nil, fmt.Errorf("subscription expired or switch disabled")
	}
	if len(doc.Servers) == 0 {
		return nil, fmt.Errorf("no servers")
	}
	if doc.Signature != "" {
		if !sub.Verify(doc, []byte(doc.Servers[0].Token)) {
			return nil, fmt.Errorf("subscription signature invalid")
		}
	} else if len(doc.Servers[0].PinSPKI) > 0 {
		log.Printf("[SUB] verified via SPKI pin transport anchor")
	} else {
		log.Printf("[SUB] verified via TLS transport channel (no payload signature)")
	}
	app, err := sub.Apply(doc)
	if err != nil {
		return nil, err
	}
	*edgeAddr = app.EdgeAddresses
	*token = app.PrimaryToken
	if app.PrimarySNI != "" {
		*publicName = app.PrimarySNI
	}
	if len(app.AllPins) > 0 {
		certloader.AddPins(app.AllPins)
		log.Printf("[SUB] SPKI pin(s) loaded: %d", len(app.AllPins))
	} else if len(app.PrimaryPins) > 0 {
		certloader.AddPins(app.PrimaryPins)
		log.Printf("[SUB] SPKI pin(s) loaded: %d", len(app.PrimaryPins))
	}
	log.Printf("[SUB] loaded %d server(s), primary=%s", len(doc.Servers), doc.Servers[0].Address)
	return app, nil
}

// -----------------------------------------------------------------------------
// Source: sub_reload.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// applySubscription 将 Applied 写入全局并重建 edgePool
func applySubscription(app *sub.Applied) error {
	if app == nil {
		return fmt.Errorf("nil applied")
	}
	if len(app.AllPins) > 0 {
		certloader.AddPins(app.AllPins)
	} else if len(app.PrimaryPins) > 0 {
		certloader.AddPins(app.PrimaryPins)
	}
	var pool *edgepool.Pool
	var err error
	if len(app.Servers) > 0 {
		epServers := make([]edgepool.ServerConfig, 0, len(app.Servers))
		for _, s := range app.Servers {
			epServers = append(epServers, edgepool.ServerConfig{
				Name:     s.Name,
				Address:  s.Address,
				Token:    s.Token,
				SNI:      s.SNI,
				Protocol: s.Protocol,
				PinSPKI:  s.PinSPKI,
			})
		}
		pool, err = edgepool.NewFromServers(epServers)
	} else {
		pool, err = edgepool.New(app.EdgeAddresses)
	}
	if err != nil {
		return err
	}
	pool.ProbeAll(0)
	edgePool = pool
	best := pool.Best()
	if best != nil && best.Address != "" {
		switchActiveNode(best)
	} else if len(app.Servers) > 0 {
		switchActiveNode(&edgepool.Server{
			Address: app.Servers[0].Address,
			Token:   app.Servers[0].Token,
			SNI:     app.Servers[0].SNI,
			PinSPKI: app.Servers[0].PinSPKI,
		})
	} else {
		switchActiveNodeByAddr(app.EdgeAddresses)
	}
	log.Printf("[SUB] applied %d edges, active=%s", pool.Count(), getEdgeAddr())
	return nil
}

// loadAndApplySubscription 拉取 + 建池（启动 / API import）
func loadAndApplySubscription(src string) (*sub.Applied, error) {
	app, err := loadSubscription(src)
	if err != nil {
		return nil, err
	}
	if err := applySubscription(app); err != nil {
		return nil, err
	}
	return app, nil
}

// loadPrivateSubscription 使用中台账号密码无感获取鉴权订阅并解析生效
func loadPrivateSubscription(server, username, password string) (*sub.Applied, error) {
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if server == "" {
		return nil, fmt.Errorf("empty subscription server")
	}

	// 1. 登录中台获取 JWT Bearer Token
	loginURL := server + "/api/v1/auth/login/"
	loginPayload, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
		"portal":   "client",
	})
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: certloader.ShouldSkipVerify()},
		DialContext:     (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	resp, err := client.Post(loginURL, "application/json", bytes.NewReader(loginPayload))
	if err != nil {
		if raw := sub.LoadLastBody(); len(raw) > 0 {
			if cached, perr := sub.ParseBytes(raw); perr == nil {
				log.Printf("[SUB] private auth failed (%v); using last cached subscription", err)
				return sub.Apply(cached)
			}
		}
		return nil, fmt.Errorf("login subscription platform failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var loginRes struct {
		Code int `json:"code"`
		Data struct {
			Token    string `json:"token"`
			Username string `json:"username"`
			SubSlug  string `json:"sub_slug"`
		} `json:"data"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginRes); err != nil {
		return nil, fmt.Errorf("parse login response failed: %w", err)
	}
	if loginRes.Data.Token == "" {
		return nil, fmt.Errorf("login failed: token missing (%s)", loginRes.Message)
	}

	// 2. 带 Bearer Token 访问私有鉴权订阅接口拉取节点
	ispHint := ""
	if detectedISP != 0 {
		ispHint = detectedISP.String()
	}
	subEndpoint := fmt.Sprintf("%s/api/v1/user/subscription", server)
	if ispHint != "" {
		subEndpoint += "?isp=" + url.QueryEscape(ispHint)
	}

	req, err := http.NewRequest("GET", subEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+loginRes.Data.Token)
	req.Header.Set("User-Agent", "AERO-Client/2.0")

	subResp, err := client.Do(req)
	if err != nil {
		if raw := sub.LoadLastBody(); len(raw) > 0 {
			if cached, perr := sub.ParseBytes(raw); perr == nil {
				log.Printf("[SUB] fetch private sub failed (%v); using last cached subscription", err)
				return sub.Apply(cached)
			}
		}
		return nil, fmt.Errorf("fetch private subscription failed: %w", err)
	}
	defer subResp.Body.Close()

	if subResp.StatusCode != http.StatusOK {
		if subResp.StatusCode == http.StatusForbidden || subResp.StatusCode == http.StatusNotFound {
			sub.ClearLastBody()
		}
		body, _ := io.ReadAll(subResp.Body)
		return nil, fmt.Errorf("fetch private subscription failed (HTTP %d): %s", subResp.StatusCode, strings.TrimSpace(string(body)))
	}

	bodyBytes, err := io.ReadAll(subResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read subscription body failed: %w", err)
	}

	doc, err := sub.ParseBytes(bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private subscription json failed: %w", err)
	}
	if doc.IsExpired() {
		sub.ClearLastBody()
		return nil, fmt.Errorf("subscription expired or switch disabled")
	}
	if len(doc.Servers) == 0 {
		return nil, fmt.Errorf("no servers in subscription")
	}

	sub.SaveLastBody(bodyBytes)
	saveLastAccount(server, username, password)

	app, err := sub.Apply(doc)
	if err != nil {
		return nil, err
	}
	*edgeAddr = app.EdgeAddresses
	*token = app.PrimaryToken
	if app.PrimarySNI != "" {
		*publicName = app.PrimarySNI
	}
	if len(app.AllPins) > 0 {
		certloader.AddPins(app.AllPins)
		log.Printf("[SUB] SPKI pin(s) loaded: %d", len(app.AllPins))
	} else if len(app.PrimaryPins) > 0 {
		certloader.AddPins(app.PrimaryPins)
		log.Printf("[SUB] SPKI pin(s) loaded: %d", len(app.PrimaryPins))
	}
	log.Printf("[SUB] (Private Auth) successfully loaded %d server(s) for user %s, primary=%s", len(doc.Servers), username, doc.Servers[0].Address)
	return app, nil
}

// loadAndApplyPrivateSubscription 登录拉取鉴权订阅 + 建池生效
func loadAndApplyPrivateSubscription(server, user, pass string) (*sub.Applied, error) {
	app, err := loadPrivateSubscription(server, user, pass)
	if err != nil {
		return nil, err
	}
	if err := applySubscription(app); err != nil {
		return nil, err
	}
	return app, nil
}

// startPrivateSubRefreshLoop 启动基于账号密码的后台定时无感同步
func startPrivateSubRefreshLoop(server, user, pass string, initial *sub.Applied) {
	server = strings.TrimSpace(server)
	user = strings.TrimSpace(user)
	pass = strings.TrimSpace(pass)
	subLoopMu.Lock()
	defer subLoopMu.Unlock()
	if subLoopCancel != nil {
		subLoopCancel()
		subLoopCancel = nil
	}
	if server == "" || user == "" || pass == "" || subInterval == nil || *subInterval <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	subLoopCancel = cancel
	go func() {
		ticker := time.NewTicker(*subInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				app, err := loadPrivateSubscription(server, user, pass)
				if err != nil {
					log.Printf("[SUB] private sub background refresh failed: %v", err)
				} else if app != nil {
					if err := applySubscription(app); err != nil {
						log.Printf("[SUB] apply refreshed private sub failed: %v", err)
					}
				}
			}
		}
	}()
	log.Printf("[SUB] private auth refresh every %s for user %s from %s", *subInterval, user, server)
}

// -----------------------------------------------------------------------------
// Source: ai_traffic.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// defaultAIDomains 权威 AI 服务域名列表（包级静态声明，消除热路径堆分配）
var defaultAIDomains = []string{
	"openai.com", "api.openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
	"anthropic.com", "claude.ai", "api.anthropic.com",
	"gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
	"copilot.microsoft.com",
	"api.groq.com", "groq.com", "api.perplexity.ai", "perplexity.ai", "api.cohere.ai", "cohere.com",
	"api.together.xyz", "together.xyz", "together.ai", "api.mistral.ai", "mistral.ai", "api.replicate.com", "replicate.com",
	"api.deepseek.com", "deepseek.com", "platform.moonshot.cn", "api.siliconflow.cn", "siliconflow.cn",
	"api.qwen.ai", "api.baichuan-ai.com", "api.minimax.chat",
	"api.sparkdesk.cn", "huggingface.co", "api-inference.huggingface.co",
	"openrouter.ai", "api.fireworks.ai", "fireworks.ai",
	"cursor.com", "cursor.sh", "poe.com", "midjourney.com",
}

// isAITraffic 检查目标域名是否为 AI 服务
func isAITraffic(host string) bool {
	hostLower := strings.ToLower(host)
	for _, d := range defaultAIDomains {
		if strings.HasSuffix(hostLower, d) || hostLower == d || strings.Contains(hostLower, d) {
			return true
		}
	}
	return false
}

// inferModelName 根据目标 host 推断 AI 模型服务名称
func inferModelName(host string) string {
	switch {
	case strings.Contains(host, "openai.com") || strings.Contains(host, "chatgpt.com"):
		return "openai-gpt"
	case strings.Contains(host, "anthropic.com") || strings.Contains(host, "claude.ai"):
		return "anthropic-claude"
	case strings.Contains(host, "gemini.google.com") || strings.Contains(host, "generativelanguage"):
		return "google-gemini"
	case strings.Contains(host, "groq.com"):
		return "groq-llama"
	case strings.Contains(host, "deepseek.com"):
		return "deepseek-chat"
	case strings.Contains(host, "cursor"):
		return "cursor-ai"
	case strings.Contains(host, "perplexity"):
		return "perplexity"
	default:
		return "ai-service"
	}
}

// generateAIContextID 为 AI 流生成 5 分钟对齐窗口的上下文标识
func generateAIContextID(host string) string {
	window := time.Now().Unix() / 300
	return fmt.Sprintf("ai_%s_%d", host, window)
}
