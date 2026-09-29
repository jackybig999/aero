package public

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/aero-protocol/aero-ech/internal/split"
	"github.com/aero-protocol/aero-ech/internal/transport"
	"github.com/aero-protocol/aero-ech/internal/tun"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// -----------------------------------------------------------------------------
// Source: tun_runtime.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

var routeCIDRRe = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)/(\d+)`)

// vpnAdapterKeys: adapter *names* that mean the other tool opened TUN.
// Process presence (sing-box.exe / clash / v2ray) is NOT global.
var vpnAdapterKeys = []string{
	"singbox_tun", "sing-box", "singbox",
	"mihomo", "clash", "meta",
	"wireguard", "nordlynx", "cloudflarewarp",
	"tun2socks", "tap-windows", "openvpn", "protonvpn",
}

var (
	tunMu       sync.Mutex
	tunEngine   *tun.Engine
	tunDev      tun.Device
	tunRunning  bool
	tunEdgeIP   string
	lastRouteGW string
	lastRouteIF string
)

func getEdgeRealIP() net.IP {
	tunMu.Lock()
	defer tunMu.Unlock()
	if tunEdgeIP != "" {
		return net.ParseIP(tunEdgeIP)
	}
	return nil
}

// startTUNIfPossible starts Wintun global capture (admin + wintun.dll next to exe).
// Protect the Edge host route BEFORE catch-all routes or the tunnel blackholes itself.

// otherVPNActive reports another tool's *global capture* (catch-all/wide public routes).
// Inactive adapters or resident box/Clash/v2ray using only their own mixed ports,
// or WinINET system proxy alone, is not a conflict.
func otherVPNActive() string {
	routesCmd := exec.Command("netsh", "interface", "ipv4", "show", "route")
	hideConsole(routesCmd)
	routes, _ := routesCmd.Output()
	if who := otherGlobalFromRoutes(string(routes)); who != "" {
		return who
	}
	return ""
}

func ifaceIsConnected(state string) bool {
	s := strings.ToLower(strings.TrimSpace(state))
	if strings.Contains(s, "disconnect") || strings.Contains(s, "已断开") {
		return false
	}
	return s == "connected" || strings.Contains(s, "已连接")
}

func isAEROHop(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "aero0") || strings.Contains(l, "10.88.0.")
}

func isVPNAdapterName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || n == "aero0" || strings.HasPrefix(n, "aero") {
		return false
	}
	for _, k := range vpnAdapterKeys {
		if n == k || strings.Contains(n, k) {
			return true
		}
	}
	return false
}

func otherGlobalFromIfaces(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue
		}
		if !ifaceIsConnected(fields[3]) {
			continue
		}
		name := strings.Join(fields[4:], " ")
		if isAEROHop(name) {
			continue
		}
		if isVPNAdapterName(name) {
			return name
		}
	}
	return ""
}

func otherGlobalFromRoutes(out string) string {
	for _, line := range strings.Split(out, "\n") {
		low := strings.ToLower(line)
		if strings.Contains(low, "system") || strings.Contains(line, "系统") {
			continue
		}
		if isAEROHop(line) {
			continue
		}
		m := routeCIDRRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		dest := m[1]
		plen, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		// Classic TUN split-default, or sing-box auto_route carving 0.0.0.0/5 etc.
		if dest == "0.0.0.0" && plen >= 1 && plen <= 8 {
			return dest + "/" + m[2]
		}
		if dest == "128.0.0.0" && plen == 1 {
			return dest + "/1"
		}
	}
	return ""
}

func startTUNIfPossible() error {
	tunMu.Lock()
	if tunRunning && tunEngine != nil {
		tunMu.Unlock()
		return nil
	}
	defer tunMu.Unlock()
	if who := otherVPNActive(); who != "" {
		return fmt.Errorf("检测到其它工具已开全局（%s）。请先关掉对方的 TUN/全局，再开 AERO TUN。仅启动 box/Clash/v2ray 或只开系统代理不会冲突", who)
	}

	ensureWintun()
	if exe, err := os.Executable(); err == nil {
		dll := filepath.Join(filepath.Dir(exe), "wintun.dll")
		if _, err := os.Stat(dll); err != nil {
			return fmt.Errorf("缺少 wintun.dll（需与 aero-ech.exe 同目录）: %w", err)
		}
		log.Printf("[TUN] wintun.dll OK: %s", dll)
	}

	edgeHost := ""
	if edgeAddr != nil && *edgeAddr != "" {
		h, _, err := net.SplitHostPort(*edgeAddr)
		if err != nil {
			h = *edgeAddr
		}
		edgeHost = h
	}
	var edgeRealIP net.IP
	if edgeHost != "" {
		if ip := net.ParseIP(edgeHost); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				tunEdgeIP = v4.String()
				edgeRealIP = v4
			}
		} else if ips, err := net.LookupIP(edgeHost); err == nil {
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					tunEdgeIP = v4.String()
					edgeRealIP = v4
					break
				}
			}
		}
		if tunEdgeIP != "" {
			if gw, idx, err := tun.PhysicalDefaultGateway(); err == nil {
				lastRouteGW, lastRouteIF = gw, idx
			}
			if err := tun.ProtectHostRoute(tunEdgeIP); err != nil {
				log.Printf("[TUN] warn protect edge %s: %v", tunEdgeIP, err)
			}
		} else {
			log.Printf("[TUN] warn: could not resolve edge host %s", edgeHost)
		}
	}
	// 保护上游极速 DNS，防止国内直连域名解析死循环进入 aero0
	_ = tun.ProtectHostRoute("223.5.5.5")

	// Force IPv4 through TUN: block global IPv6 so Google Happy-Eyeballs
	// cannot skip the adapter (needs admin, same as wintun).
	quietFirewall("add", "AERO-NoIPv6", "dir=out", "action=block", "protocol=any", "remoteip=2000::/3")
	// WebRTC STUN 物理防泄露装甲：阻止出站 STUN 探针绕过隧道直接从物理网卡泄露真实 IP
	quietFirewall("add", "AERO-WebRTC-Shield", "dir=out", "action=block", "protocol=UDP", "remoteport=3478,19302,5349")

	name := "aero0"
	mtu := 1420
	dev, err := tun.NewDevice(name, mtu)
	if err != nil {
		if tunEdgeIP != "" {
			tun.UnprotectHostRoute(tunEdgeIP)
			tunEdgeIP = ""
		}
		tun.UnprotectHostRoute("223.5.5.5")
		return fmt.Errorf("create TUN (需管理员运行): %w", err)
	}

	ipv4 := "10.88.0.2/24"
	routes := []string{"0.0.0.0/1", "128.0.0.0/1"}
	if err := tun.SetupRoutes(dev.Name(), ipv4, "", routes); err != nil {
		_ = dev.Close()
		if tunEdgeIP != "" {
			tun.UnprotectHostRoute(tunEdgeIP)
			tunEdgeIP = ""
		}
		tun.UnprotectHostRoute("223.5.5.5")
		return fmt.Errorf("setup routes: %w", err)
	}
	tun.SetupDNS([]string{"223.5.5.5", "119.29.29.29"})

	cfg := tun.Config{
		MTU: mtu, IPv4: ipv4, Routes: routes,
		DNSServers:   []string{"223.5.5.5", "119.29.29.29"},
		FakeIPRange:  "198.18.0.0/15",
		FakeIPEnable: true, // 启用本地 Fake-IP 0ms 响应，根治浏览器卡死与公网 DNS 污染
	}
	if splitEngine == nil {
		splitEngine = split.NewEngine()
	}
	eng := tun.New(dev, cfg, &tunSplitAdapter{engine: splitEngine}, &tunAERODialer{})
	if edgeHost != "" && edgeRealIP != nil {
		eng.SetEdge(edgeHost, edgeRealIP)
	}
	transport.SetPacketConnFactory(tun.ListenPhysicalPacket)
	tunDev = dev
	tunEngine = eng
	tunRunning = true

	go func() {
		log.Printf("[TUN] GLOBAL on %s edgeProtect=%s", name, tunEdgeIP)
		_ = eng.Start()
	}()
	time.Sleep(300 * time.Millisecond)
	modeMu.RLock()
	stillTUN := clientMode == "tun"
	modeMu.RUnlock()
	if !stillTUN {
		log.Printf("[TUN] mode no longer tun; leftover adapter will be torn down")
		go func() {
			time.Sleep(20 * time.Millisecond)
			stopTUN()
		}()
		return fmt.Errorf("mode switched away from TUN during start")
	}
	startCrashGuard()
	log.Printf("[TUN] mode ready")
	return nil
}

var (
	netChangeMu    sync.Mutex
	netChangeTimer *time.Timer
)

func scheduleTUNRefresh(reason string) {
	tun.InvalidatePhysicalDefault()
	netChangeMu.Lock()
	defer netChangeMu.Unlock()
	if netChangeTimer != nil {
		netChangeTimer.Stop()
	}
	netChangeTimer = time.AfterFunc(300*time.Millisecond, func() {
		refreshTUNAfterNetChange(reason)
	})
}

func refreshTUNAfterNetChange(reason string) {
	tunMu.Lock()
	running := tunRunning
	eip := tunEdgeIP
	devName := "aero0"
	if tunDev != nil {
		devName = tunDev.Name()
	}
	tunMu.Unlock()
	if !running {
		transport.GlobalSessionPool.Reset()
		if edgePool != nil {
			go edgePool.ProbeAll(0)
		}
		return
	}

	var gw, idx string
	var err error
	// Wi-Fi 漫游 / 休眠唤醒后 DHCP 分配通常需要 300ms~1.5s，进行最多 8 次自适应轮询
	for attempt := 1; attempt <= 8; attempt++ {
		tun.InvalidatePhysicalDefault()
		gw, idx, err = tun.PhysicalDefaultGateway()
		if err == nil && gw != "" && idx != "" {
			break
		}
		if attempt < 8 {
			time.Sleep(300 * time.Millisecond)
		}
	}
	if err != nil || gw == "" {
		log.Printf("[TUN] network change (%s): no physical gw after retries (%v)", reason, err)
		return
	}

	tunMu.Lock()
	same := lastRouteGW == gw && lastRouteIF == idx && lastRouteGW != ""
	tunMu.Unlock()
	if same && reason != "wake_from_sleep" {
		log.Printf("[TUN] network event ignored (gw %s if=%s unchanged)", gw, idx)
		return
	}
	log.Printf("[TUN] network change (%s): refresh edge protect via %s if=%s (aero0)", reason, gw, idx)
	if eip != "" {
		if err := tun.ProtectHostRoute(eip); err != nil {
			log.Printf("[TUN] protect after net change: %v", err)
			return
		}
	}
	// 原子同步保护国内 DNS，防止 Wi-Fi 切换后 DNS 死在旧网关上
	_ = tun.ProtectHostRoute("223.5.5.5")

	if err := tun.EnsureCatchAll(devName); err != nil {
		log.Printf("[TUN] ensure catch-all: %v", err)
	}
	tunMu.Lock()
	lastRouteGW, lastRouteIF = gw, idx
	tunMu.Unlock()
	// 休眠唤醒与网络切换后旧 TCP/QUIC 套接字已被系统内核切断，强制清空会话池使后续请求极速新建活跃长连接
	transport.GlobalSessionPool.Reset()
	if edgePool != nil {
		go edgePool.ProbeAll(0)
	}
}

func stopTUN() {
	tunMu.Lock()
	eng := tunEngine
	dev := tunDev
	eip := tunEdgeIP
	running := tunRunning
	tunEngine = nil
	tunDev = nil
	tunRunning = false
	tunEdgeIP = ""
	lastRouteGW = ""
	lastRouteIF = ""
	tunMu.Unlock()

	if !running && eng == nil && dev == nil {
		return
	}
	// Routes first so Chrome/Google get a real default immediately.
	if dev != nil {
		tun.TeardownRoutes(dev.Name())
	} else {
		tun.TeardownRoutes("aero0")
	}
	if eip != "" {
		tun.UnprotectHostRoute(eip)
	}
	tun.UnprotectHostRoute("223.5.5.5")

	if eng != nil {
		eng.Stop()
	}
	tun.TeardownDNS()
	if dev != nil {
		_ = dev.Close()
	}
	quietFirewall("delete", "AERO-NoIPv6")
	quietFirewall("delete", "AERO-WebRTC-Shield")
	transport.SetPacketConnFactory(nil)
	log.Printf("[TUN] stopped cleanly, zero residual")
}

type tunAERODialer struct{}

func (d *tunAERODialer) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = ""
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			var dialer net.Dialer
			dialer.Timeout = 10 * time.Second
			return dialer.DialContext(ctx, "tcp", addr)
		}
		// Fake-IP (198.18.0.0/15) 内存 0ms 反查还原为真实域名
		if v4 := ip.To4(); v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			if domain, ok := tun.DefaultFakeIPTable.Lookup(ip); ok {
				if port != "" {
					addr = net.JoinHostPort(domain, port)
				} else {
					addr = domain
				}
				if splitEngine != nil && splitEngine.MatchDomain(domain) == split.DIRECT {
					return tun.DialPhysicalDirect(ctx, "tcp", addr)
				}
			} else {
				return nil, fmt.Errorf("unknown fake-ip %s", addr)
			}
		} else {
			// Real IP (direct traffic from domestic DNS pass-through)
			if splitEngine != nil && splitEngine.MatchIP(ip) == split.DIRECT {
				return tun.DialPhysicalDirect(ctx, "tcp", addr)
			}
		}
	}
	return openAEROStream(addr)
}

func (d *tunAERODialer) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = ""
	}
	if ip := net.ParseIP(host); ip != nil {
		// Fake-IP (198.18.0.0/15) 内存 0ms 反查还原
		if v4 := ip.To4(); v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			if domain, ok := tun.DefaultFakeIPTable.Lookup(ip); ok {
				if port != "" {
					addr = net.JoinHostPort(domain, port)
				} else {
					addr = domain
				}
				if splitEngine != nil && splitEngine.MatchDomain(domain) == split.DIRECT {
					return tun.DialPhysicalDirect(ctx, "udp", addr)
				}
			}
		} else {
			// Real IP direct
			if splitEngine != nil && splitEngine.MatchIP(ip) == split.DIRECT {
				return tun.DialPhysicalDirect(ctx, "udp", addr)
			}
		}
	}
	return openAEROUDP(addr)
}

func quietFirewall(action string, args ...string) {
	var cmdArgs []string
	if action == "delete" {
		name := "AERO-NoIPv6"
		if len(args) > 0 {
			name = args[0]
		}
		cmdArgs = []string{"advfirewall", "firewall", "delete", "rule", "name=" + name}
	} else {
		cmdArgs = append([]string{"advfirewall", "firewall", "add", "rule", "name=" + args[0]}, args[1:]...)
	}
	cmd := exec.Command("netsh", cmdArgs...)
	hideConsole(cmd)
	_ = cmd.Run()
}

// -----------------------------------------------------------------------------
// Source: sim.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors

// runDataPlaneSim exercises the same path TUN/gVisor uses (openAEROStream /
// openAEROUDP) plus a gVisor SYN→DialTCP check. No wintun, no system proxy.
func runDataPlaneSim() int {
	enginePaused.Store(false)
	fails := 0
	check := func(name string, err error) {
		if err != nil {
			log.Printf("[SIM] FAIL %s: %v", name, err)
			fails++
			return
		}
		log.Printf("[SIM] PASS %s", name)
	}

	check("tcp-google-204", simHTTPS204("www.google.com"))
	check("tcp-grok-proxy-tls", simTLS("cli-chat-proxy.grok.com"))
	check("udp-dns-google", simDNS("www.google.com"))
	check("udp-dns-cloudflare", simDNSTo("1.1.1.1:53", "www.google.com"))
	check("gvisor-syn-forward", simGvisorSYN())
	check("gvisor-udp-forward", simGvisorUDP())

	if fails > 0 {
		log.Printf("[SIM] %d check(s) failed", fails)
		return 1
	}
	log.Printf("[SIM] all checks passed (AERO TCP+UDP + gVisor forwarder)")
	return 0
}

func simHTTPS204(host string) error {
	raw, err := openAEROStream(net.JoinHostPort(host, "443"))
	if err != nil {
		return fmt.Errorf("aero dial: %w", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
	tconn := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tconn.Handshake(); err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	defer tconn.Close()
	req := "GET /generate_204 HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tconn, req); err != nil {
		return err
	}
	br := bufio.NewReader(tconn)
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, "204") && !strings.Contains(line, "301") && !strings.Contains(line, "302") && !strings.Contains(line, "200") {
		return fmt.Errorf("status %q", strings.TrimSpace(line))
	}
	log.Printf("[SIM] %s HTTP %s", host, strings.TrimSpace(line))
	return nil
}

func simTLS(host string) error {
	raw, err := openAEROStream(net.JoinHostPort(host, "443"))
	if err != nil {
		return fmt.Errorf("aero dial: %w", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
	tconn := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tconn.Handshake(); err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	_ = tconn.Close()
	log.Printf("[SIM] %s TLS handshake ok", host)
	return nil
}

func simDNS(name string) error {
	return simDNSTo("8.8.8.8:53", name)
}

func simDNSTo(dnsAddr, name string) error {
	c, err := openAEROUDP(dnsAddr)
	if err != nil {
		return fmt.Errorf("aero udp: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(12 * time.Second))
	q := buildDNSQuery(name)
	if _, err := c.Write(q); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if n < 12 {
		return fmt.Errorf("short dns %d", n)
	}
	if buf[0] != q[0] || buf[1] != q[1] {
		return fmt.Errorf("txid mismatch")
	}
	if buf[3]&0x0F != 0 {
		return fmt.Errorf("rcode %d", buf[3]&0x0F)
	}
	log.Printf("[SIM] dns %s via %s answers (%d bytes)", name, dnsAddr, n)
	return nil
}

func simGvisorUDP() error {
	dev := tun.NewMemDevice()
	got := make(chan string, 2)
	d := &simRecordDial{got: got}
	eng := tun.New(dev, tun.Config{MTU: 1420, IPv4: "10.88.0.2/24"}, nil, d)
	done := make(chan error, 1)
	go func() { done <- eng.Start() }()
	defer func() {
		eng.Stop()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()
	time.Sleep(80 * time.Millisecond)
	dev.Inject(tun.BuildUDPv4(net.IPv4(10, 88, 0, 10), net.IPv4(1, 1, 1, 1), 50001, 53, []byte{9, 9, 9, 9}))
	select {
	case addr := <-got:
		if addr != "1.1.1.1:53" {
			return fmt.Errorf("udp dest %s", addr)
		}
		return nil
	case <-time.After(3 * time.Second):
		return fmt.Errorf("gVisor did not forward UDP")
	}
}

func buildDNSQuery(name string) []byte {
	q := make([]byte, 12)
	q[0], q[1] = 0x12, 0x34
	q[2] = 0x01
	q[5] = 1
	for _, lab := range strings.Split(name, ".") {
		q = append(q, byte(len(lab)))
		q = append(q, lab...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	return q
}

func simGvisorSYN() error {
	dev := tun.NewMemDevice()
	got := make(chan string, 2)
	d := &simRecordDial{got: got}
	eng := tun.New(dev, tun.Config{MTU: 1420, IPv4: "10.88.0.2/24"}, nil, d)
	done := make(chan error, 1)
	go func() { done <- eng.Start() }()
	defer func() {
		eng.Stop()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()
	time.Sleep(100 * time.Millisecond)
	src := net.IPv4(10, 88, 0, 10)
	dst := net.IPv4(1, 1, 1, 1)
	dev.Inject(tun.BuildIPv4TCPSYN(src, dst, 40000, 443))
	var synack []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && synack == nil {
		for _, p := range dev.Outbound() {
			if _, _, flags, ok := tun.ParseTCPSeqAck(p); ok && flags&0x12 == 0x12 {
				synack = p
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if synack == nil {
		return fmt.Errorf("gVisor did not reply SYN-ACK")
	}
	seq, ack, _, _ := tun.ParseTCPSeqAck(synack)
	dev.Inject(tun.BuildIPv4TCPACK(src, dst, 40000, 443, ack, seq+1))
	select {
	case addr := <-got:
		if addr != "1.1.1.1:443" {
			return fmt.Errorf("forward dest %s", addr)
		}
		return nil
	case <-time.After(3 * time.Second):
		return fmt.Errorf("handshake ok but DialTCP not called")
	}
}

type simRecordDial struct {
	got chan string
}

func (d *simRecordDial) DialTCP(_ context.Context, addr string) (net.Conn, error) {
	return d.dial(addr)
}

func (d *simRecordDial) DialUDP(_ context.Context, addr string) (net.Conn, error) {
	return d.dial(addr)
}

func (d *simRecordDial) dial(addr string) (net.Conn, error) {
	select {
	case d.got <- addr:
	default:
	}
	a, b := net.Pipe()
	go func() { _ = a.Close() }()
	return b, nil
}
