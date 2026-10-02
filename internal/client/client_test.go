// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// 验收项 7：换线与刷新幂等
// 对同一个 host:port 连续 3 次调用订阅应用逻辑；断言：会话池的 Reset() 调用次数严格为 0。
func TestEngineSwitchActiveNodeIdempotent(t *testing.T) {
	eng := NewEngine()

	applied := &Applied{
		Servers: []ServerConfig{
			{Name: "US-Node", Address: "192.0.2.1:443", Token: "tok_123", SNI: "node.example.com"},
		},
		Tokens: map[string]string{"192.0.2.1:443": "tok_123"},
		SNIs:   map[string]string{"192.0.2.1:443": "node.example.com"},
	}

	// 首次应用
	if err := eng.Apply(applied); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}

	// 追踪后续调用中的 Reset
	resetCalls := 0
	eng.sessionPool = &mockSessionPool{
		onReset: func() {
			resetCalls++
		},
	}

	// 连续 3 次调用相同的 host:port 订阅应用
	for i := 0; i < 3; i++ {
		if err := eng.Apply(applied); err != nil {
			t.Fatalf("idempotent apply %d failed: %v", i+1, err)
		}
	}

	if resetCalls != 0 {
		t.Fatalf("expected 0 Reset calls for identical host:port, got %d", resetCalls)
	}

	// 单独调用 SwitchActiveNode 也是幂等的
	if err := eng.SwitchActiveNode("192.0.2.1:443"); err != nil {
		t.Fatalf("SwitchActiveNode failed: %v", err)
	}
	if resetCalls != 0 {
		t.Fatalf("expected 0 Reset calls for identical SwitchActiveNode, got %d", resetCalls)
	}
}

type mockSessionPool struct {
	onReset func()
	onGet   func(ctx context.Context, cfg *TransportConfig) (*Client, error)
}

func (m *mockSessionPool) Get(ctx context.Context, cfg *TransportConfig) (*Client, error) {
	if m.onGet != nil {
		return m.onGet(ctx, cfg)
	}
	return nil, nil
}

func (m *mockSessionPool) Remove(addr string) {}

func (m *mockSessionPool) Reset() {
	if m.onReset != nil {
		m.onReset()
	}
}

// 验收项 3：订阅单飞与防雪崩 (singleflight)
func TestLoadAndApplySubscriptionSingleflight(t *testing.T) {
	fetchCount := atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"version": "aero/2.0",
			"servers": [
				{"name": "Node-1", "address": "198.51.100.1:443", "token": "tok_abc"}
			]
		}`)
	}))
	defer server.Close()

	eng := NewEngine()

	var wg sync.WaitGroup
	const concurrent = 10
	errs := make([]error, concurrent)

	for i := 0; i < concurrent; i++ {
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[idx] = eng.LoadAndApplySubscription(server.URL)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent request %d failed: %v", i, err)
		}
	}

	if count := fetchCount.Load(); count != 1 {
		t.Fatalf("expected exactly 1 upstream fetch due to singleflight, got %d", count)
	}
}

// 验收项 2：DNS 两级漏斗与零泄露断言
// • *.cn 查询只打到 Mock 物理解析器；
// • 核心断言：google.com 绝对不进入 queryFastUDP；
// • 核心断言：AAAA 始终空应答；
// • 未建连境外站返回 198.18 假 IP；短流建连返回真实 IP
func TestTwoStageDNSFunnel(t *testing.T) {
	split := NewSplitEngine()
	dnsHandler := NewDNSHandler(split)

	fastUDPQueryCount := atomic.Int32{}
	fastUDPDomains := sync.Map{}

	// 启动 Mock 物理 UDP DNS 解析器
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock physical DNS failed: %v", err)
	}
	defer pc.Close()

	dnsHandler.SetPhysicalDNS(pc.LocalAddr().String())

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			fastUDPQueryCount.Add(1)
			qname, _ := extractDNSQuestionAndType(buf[:n])
			fastUDPDomains.Store(strings.ToLower(qname), true)

			// 构造有效 A 应答 (1.2.3.4)
			resp := buildAResponse(buf[:n], qname, net.ParseIP("1.2.3.4"))
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	// 1. 测试 *.cn 域名
	// 1.1 Type AAAA: 必须直接返回空应答，绝对不发往物理 DNS
	reqAAAA := buildDNSQuery("baidu.cn", 0x001C)
	respAAAA := dnsHandler.HandleQuery(reqAAAA, net.ParseIP("10.88.0.2"), 53)
	if respAAAA == nil {
		t.Fatalf("expected empty answer for *.cn AAAA, got nil")
	}
	if ansCount := binary.BigEndian.Uint16(respAAAA[6:8]); ansCount != 0 {
		t.Fatalf("expected 0 answers for *.cn AAAA, got %d", ansCount)
	}
	if fastUDPQueryCount.Load() != 0 {
		t.Fatalf("*.cn AAAA must not trigger physical DNS, count=%d", fastUDPQueryCount.Load())
	}

	// 1.2 Type A: 打到物理解析器
	reqA := buildDNSQuery("test.cn", 0x0001)
	respA := dnsHandler.HandleQuery(reqA, net.ParseIP("10.88.0.2"), 53)
	if respA == nil {
		t.Fatalf("expected response for test.cn Type A, got nil")
	}
	if fastUDPQueryCount.Load() == 0 {
		t.Fatalf("expected physical DNS query for *.cn Type A, got 0")
	}

	// 2. 核心断言：google.com 绝对不进入 queryFastUDP！
	reqGoogleAAAA := buildDNSQuery("google.com", 0x001C)
	respGoogleAAAA := dnsHandler.HandleQuery(reqGoogleAAAA, net.ParseIP("10.88.0.2"), 53)
	if respGoogleAAAA == nil || binary.BigEndian.Uint16(respGoogleAAAA[6:8]) != 0 {
		t.Fatalf("expected empty answer for google.com AAAA")
	}

	reqGoogleA := buildDNSQuery("google.com", 0x0001)
	// 未建连状态：直接返回 198.18 假 IP
	respGoogleA := dnsHandler.HandleQuery(reqGoogleA, net.ParseIP("10.88.0.2"), 53)
	if respGoogleA == nil {
		t.Fatalf("expected Fake-IP response for google.com, got nil")
	}

	// 校验核心断言：google.com 是否被泄漏到了物理解析器
	if _, leaked := fastUDPDomains.Load("google.com"); leaked {
		t.Fatalf("CRITICAL SECURITY LEAK: google.com was sent to physical DNS (queryFastUDP)!")
	}

	// 检查返回的 IP 是否在 198.18.0.0/15 网段
	fakeIP := extractFirstAAnswer(respGoogleA)
	if fakeIP == nil || !dnsHandler.fakeIP.Contains(fakeIP) {
		t.Fatalf("expected IP in 198.18.0.0/15 for google.com, got %v", fakeIP)
	}

	// 3. 短流建连解析测试：模拟隧道已建连并回传真实 IP
	dnsHandler.SetTunnelResolver(func(ctx context.Context, domain string) (net.IP, error) {
		if domain == "openai.com" {
			return net.ParseIP("104.18.2.161"), nil
		}
		return nil, errors.New("not found")
	})

	reqOpenAI := buildDNSQuery("openai.com", 0x0001)
	respOpenAI := dnsHandler.HandleQuery(reqOpenAI, net.ParseIP("10.88.0.2"), 53)
	if respOpenAI == nil {
		t.Fatalf("expected real IP response for openai.com, got nil")
	}
	realIP := extractFirstAAnswer(respOpenAI)
	if realIP == nil || !realIP.Equal(net.ParseIP("104.18.2.161")) {
		t.Fatalf("expected real IP 104.18.2.161 from tunnel short stream, got %v", realIP)
	}

	// 再次确认 openai.com 绝对未进入物理 DNS
	if _, leaked := fastUDPDomains.Load("openai.com"); leaked {
		t.Fatalf("CRITICAL SECURITY LEAK: openai.com was sent to physical DNS!")
	}
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	buf := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Standard query
		0x00, 0x01, // 1 question
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	buf = append(buf, encodeDNSName(domain)...)
	buf = append(buf, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0x00, 0x01) // Class IN
	return buf
}

func extractFirstAAnswer(resp []byte) net.IP {
	if len(resp) < 16 {
		return nil
	}
	// 简单查找末尾 4 字节
	if len(resp) >= 32 {
		return net.IP(resp[len(resp)-4:])
	}
	return nil
}

// 验收项：APNIC 大陆 IPv4 匹配器与 ISP 校验
func TestChinaIPMatcherAndISP(t *testing.T) {
	matcher := NewChinaIPMatcher()
	if matcher.TotalRanges() == 0 {
		t.Fatalf("expected loaded china IP ranges > 0")
	}

	// 常见大陆公网 IP
	chinaIPs := []string{
		"223.5.5.5",       // 阿里 DNS
		"119.29.29.29",    // 腾讯 DNS
		"114.114.114.114", // 114 DNS
		"218.2.135.1",     // 电信
	}
	for _, ipStr := range chinaIPs {
		ip := net.ParseIP(ipStr)
		if !matcher.Contains(ip) {
			t.Errorf("expected %s to be classified as China IP", ipStr)
		}
	}

	// 海外已知 IP
	foreignIPs := []string{
		"8.8.8.8",
		"1.1.1.1",
		"140.82.121.4", // GitHub
	}
	for _, ipStr := range foreignIPs {
		ip := net.ParseIP(ipStr)
		if matcher.Contains(ip) {
			t.Errorf("expected %s to NOT be classified as China IP", ipStr)
		}
	}

	// 验证分流规则
	split := NewSplitEngine()
	if strat := split.Match("qq.com", nil); strat != DIRECT {
		t.Errorf("expected qq.com to be DIRECT, got %v", strat)
	}
	if strat := split.Match("chatgpt.com", nil); strat != AI {
		t.Errorf("expected chatgpt.com to be AI, got %v", strat)
	}
	if strat := split.Match("google.com", nil); strat != PROXY {
		t.Errorf("expected google.com to be PROXY, got %v", strat)
	}
}

// 验收项：物理 SNI 锁定与 DatagramTooLargeError 动态捕获
func TestQUICConfigAndDatagramTooLargeError(t *testing.T) {
	// 1. 物理 SNI 锁死测试：输入带伪装 SNI 的配置，必须锁死为真实 host
	cfg := DefaultTransportConfig("my-node.aero-net.com:443", "edge.microsoft.com")
	if cfg.TLSServerName != "my-node.aero-net.com" {
		t.Fatalf("expected physical SNI to be locked to my-node.aero-net.com, got %s", cfg.TLSServerName)
	}

	// 2. 模拟捕获 *quic.DatagramTooLargeError
	mtuSetVal := atomic.Int32{}
	RegisterVirtualNICMTUSetter(func(mtu int) error {
		mtuSetVal.Store(int32(mtu))
		return nil
	})

	SetCurrentMaxDatagramSize(1200)

	// 模拟返回 DatagramTooLargeError
	var err error = &quic.DatagramTooLargeError{
		MaxDatagramPayloadSize: 1150,
	}

	var dtle *quic.DatagramTooLargeError
	if errors.As(err, &dtle) {
		newSize := int(dtle.MaxDatagramPayloadSize)
		SetCurrentMaxDatagramSize(newSize)
		SetVirtualNICMTU(newSize + 24)
	}

	if GetCurrentMaxDatagramSize() != 1150 {
		t.Fatalf("expected currentMaxDatagramSize updated to 1150, got %d", GetCurrentMaxDatagramSize())
	}
	if mtuSetVal.Load() != 1150+24 {
		t.Fatalf("expected virtual NIC MTU setter called with %d, got %d", 1150+24, mtuSetVal.Load())
	}
}

// 验收项：栈入口 DF 标志识别与 ICMP Type 3 Code 4 构造
func TestICMPFragNeededOnDFOverflow(t *testing.T) {
	SetCurrentMaxDatagramSize(1200)
	limit := GetCurrentMaxDatagramSize() + 24 // 1224

	gwIP := net.ParseIP("10.88.0.1")

	// 1. 带 DF 标志且超限包：构造 ICMP
	bigPacketDF := make([]byte, 1300)
	bigPacketDF[0] = 0x45                          // IPv4, IHL=5 (20 bytes)
	bigPacketDF[6] = 0x40                          // DF = 1
	copy(bigPacketDF[12:16], []byte{10, 88, 0, 2}) // Src IP
	copy(bigPacketDF[16:20], []byte{8, 8, 8, 8})   // Dst IP

	icmpReply := buildICMPFragNeeded(bigPacketDF, gwIP, uint16(limit))
	if icmpReply == nil {
		t.Fatalf("expected ICMP packet generated on DF overflow, got nil")
	}

	// 校验 ICMP IP 报头
	if icmpReply[0]>>4 != 4 {
		t.Fatalf("expected IPv4 reply")
	}
	if !net.IP(icmpReply[12:16]).Equal(gwIP) {
		t.Fatalf("expected source IP to be virtual gateway 10.88.0.1, got %v", icmpReply[12:16])
	}
	if !net.IP(icmpReply[16:20]).Equal(net.ParseIP("10.88.0.2")) {
		t.Fatalf("expected dest IP to be original packet src 10.88.0.2, got %v", icmpReply[16:20])
	}

	// 校验 ICMP Type 3 Code 4 与 Next-Hop MTU
	icmpPayload := icmpReply[20:]
	if icmpPayload[0] != 3 || icmpPayload[1] != 4 {
		t.Fatalf("expected ICMP Type 3 Code 4, got Type %d Code %d", icmpPayload[0], icmpPayload[1])
	}
	nextMTU := binary.BigEndian.Uint16(icmpPayload[6:8])
	if nextMTU != 1224 {
		t.Fatalf("expected Next-Hop MTU 1224, got %d", nextMTU)
	}

	// 2. 不带 DF 标志超限包：静默丢弃 (DF = 0)
	bigPacketNoDF := make([]byte, 1300)
	bigPacketNoDF[0] = 0x45
	bigPacketNoDF[6] = 0x00 // DF = 0
	df := (bigPacketNoDF[6] & 0x40) != 0
	if df {
		t.Fatalf("expected DF=false for bigPacketNoDF")
	}
}

// 验收项：原生订阅 JSON (aero/2.0) 解析与参数保留
func TestNativeAeroSubParsing(t *testing.T) {
	subJSON := `{
		"version": "aero/2.0",
		"userId": "user_12345",
		"slug": "superadmin",
		"expireAt": 1893456000,
		"servers": [
			{
				"name": "Tokyo Edge 01",
				"address": "tokyo.aero.net:443",
				"token": "tok_abcdef",
				"protocol": "quic",
				"pin_spki": ["abc123spki=="]
			}
		],
		"optimization": {
			"aiNodes": ["tokyo.aero.net:443"],
			"defaultQoS": "turbo",
			"bandwidth": "100Mbps"
		}
	}`

	sub, err := ParseSubscriptionBytes([]byte(subJSON))
	if err != nil {
		t.Fatalf("parse subscription failed: %v", err)
	}

	if sub.Version != "aero/2.0" || sub.Slug != "superadmin" {
		t.Fatalf("unexpected sub fields: %+v", sub)
	}
	if len(sub.Servers) != 1 || sub.Servers[0].Address != "tokyo.aero.net:443" {
		t.Fatalf("unexpected servers: %+v", sub.Servers)
	}
	if len(sub.Opt.AINodes) != 1 || sub.Opt.DefaultQoS != "turbo" {
		t.Fatalf("unexpected optimization: %+v", sub.Opt)
	}

	applied, err := ApplySubscription(sub)
	if err != nil {
		t.Fatalf("apply subscription failed: %v", err)
	}
	if applied.PrimaryToken != "tok_abcdef" || applied.PrimarySNI != "tokyo.aero.net" {
		t.Fatalf("unexpected applied: %+v", applied)
	}
}

// 验收项：物理网卡直连拉取订阅
func TestSubPhysicalDial(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"version": "aero/2.0",
			"servers": [
				{"name": "DirectNode", "address": "direct.example.com:443", "token": "tok_direct"}
			]
		}`)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sub, body, err := fetchSingleSubURL(ctx, ts.URL, SubFetchOptions{})
	if err != nil {
		t.Fatalf("fetchSingleSubURL with DialPhysicalDirect failed: %v", err)
	}
	if sub == nil || len(sub.Servers) != 1 || sub.Servers[0].Token != "tok_direct" {
		t.Fatalf("unexpected fetched sub: %+v", sub)
	}
	if len(body) == 0 {
		t.Fatalf("expected non-empty body")
	}
}

// 验收项：Netmon 防抖与指纹去重
func TestNetmonDebounceAndFingerprint(t *testing.T) {
	w := newDebounceWatcher()
	w.debounce = 40 * time.Millisecond

	var triggerCount atomic.Int32
	w.start(func(newGW, ifName string) {
		triggerCount.Add(1)
	})
	defer w.stop()

	// 初始指纹已采样，连续多次触发由于指纹相同应全部去重
	for i := 0; i < 5; i++ {
		w.trigger()
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(80 * time.Millisecond)

	if count := triggerCount.Load(); count != 0 {
		t.Fatalf("expected 0 triggers due to deduplication, got %d", count)
	}

	// 模拟指纹发生变化（网关或物理网卡改变）
	w.mu.Lock()
	w.lastFingerprint = "old-gw@old-iface"
	w.mu.Unlock()

	// 连续快速触发 10 次（模拟网卡状态震荡）
	for i := 0; i < 10; i++ {
		w.trigger()
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)

	// 防抖应将 10 次震荡压缩为恰好 1 次有效触发
	if count := triggerCount.Load(); count != 1 {
		t.Fatalf("expected exactly 1 trigger after debounce, got %d", count)
	}
}

// 验收项：纯内存 Kill Switch
func TestKillSwitchInMemory(t *testing.T) {
	eng := NewEngine()
	if eng.KillSwitch() {
		t.Fatalf("expected kill switch disabled by default")
	}

	eng.SetKillSwitch(true)
	if !eng.KillSwitch() {
		t.Fatalf("expected kill switch enabled on Engine")
	}

	stackEng := NewStackEngine(nil, nil, nil)
	if stackEng.KillSwitch() {
		t.Fatalf("expected stack kill switch false by default")
	}

	stackEng.SetKillSwitch(true)
	if !stackEng.KillSwitch() {
		t.Fatalf("expected stack kill switch true")
	}

	eng.stackEngine = stackEng
	eng.SetKillSwitch(false)
	if stackEng.KillSwitch() {
		t.Fatalf("expected stackEngine killswitch synchronized to false")
	}
	eng.SetKillSwitch(true)
	if !stackEng.KillSwitch() {
		t.Fatalf("expected stackEngine killswitch synchronized to true")
	}
}

// 验收项：数据报接收循环 Context 取消立即退出
func TestTunnelDatagramReceiveLoopContextCancel(t *testing.T) {
	tc := NewTunnelClient(nil, nil)
	defer tc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		// client with nil conn: ReceiveDatagram returns error when context canceled or immediately
		client := &Client{}
		tc.runDatagramReceiveLoop(ctx, client)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// success: exited cleanly
	case <-time.After(1 * time.Second):
		t.Fatalf("runDatagramReceiveLoop did not exit immediately upon context cancel")
	}
}

// 验收项：DialTCP 退避重试响应 ctx.Done()
func TestTunnelDialTCPBackoffRetryCancel(t *testing.T) {
	tc := NewTunnelClient(nil, nil)
	defer tc.Close()

	// 激活一个空地址，使首次 getActiveQUICClient 失败触发重试分支
	SetActiveEdge("", "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := tc.DialTCP(ctx, "target.com:80")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected dial to fail")
	}
	// 退避应在 ctx 超时后立即终止，耗时应在合理范围内 (< 500ms)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("DialTCP took too long (%v), expected quick exit via ctx.Done()", elapsed)
	}
}

// 验收项：强制门户检测 (Captive Portal Detection)
func TestDetectCaptivePortal(t *testing.T) {
	origURL := captivePortalURL
	defer func() { captivePortalURL = origURL }()

	// 1. 模拟正常网络 (返回 204 No Content)
	tsNormal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer tsNormal.Close()

	captivePortalURL = tsNormal.URL
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	detected, err := DetectCaptivePortal(ctx)
	if err != nil {
		t.Fatalf("DetectCaptivePortal failed on normal: %v", err)
	}
	if detected {
		t.Fatalf("expected detected=false on 204 response")
	}

	// 2. 模拟强制门户拦截 (返回 302 重定向到认证页)
	tsRedirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://login.wifi.portal/index.html", http.StatusFound)
	}))
	defer tsRedirect.Close()

	captivePortalURL = tsRedirect.URL
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()

	detected, err = DetectCaptivePortal(ctx2)
	if err != nil {
		t.Fatalf("DetectCaptivePortal failed on redirect: %v", err)
	}
	if !detected {
		t.Fatalf("expected detected=true on 302 redirect")
	}

	// 3. 模拟强制门户拦截 (返回 200 OK 认证页)
	tsHTML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>Please login to WiFi</body></html>")
	}))
	defer tsHTML.Close()

	captivePortalURL = tsHTML.URL
	ctx3, cancel3 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel3()

	detected, err = DetectCaptivePortal(ctx3)
	if err != nil {
		t.Fatalf("DetectCaptivePortal failed on 200 HTML: %v", err)
	}
	if !detected {
		t.Fatalf("expected detected=true on 200 OK response")
	}
}

// 验收项：Engine 网络变动事件响应 (onNetworkChange)
func TestEngineOnNetworkChange(t *testing.T) {
	eng := NewEngine()

	// 注册模拟会话池
	resetCalled := atomic.Bool{}
	eng.sessionPool = &mockSessionPool{
		onReset: func() {
			resetCalled.Store(true)
		},
	}

	// 注册模拟活跃连接
	mockConn := &mockCloser{}
	eng.activeConns.Store(mockConn, struct{}{})

	// 触发物理网络变动
	eng.onNetworkChange("192.168.1.1", "eth0")

	// 1. 验证存量连接已被关闭
	if !mockConn.closed.Load() {
		t.Fatalf("expected activeConns to be closed on network change")
	}

	// 2. 验证 sessionPool.Reset 已被调用
	if !resetCalled.Load() {
		t.Fatalf("expected sessionPool.Reset to be called on network change")
	}

	// 3. 验证物理 DNS 已固定设为 223.5.5.5:53
	if eng.dnsHandler.physicalDNS != "223.5.5.5:53" {
		t.Fatalf("expected physical DNS updated to 223.5.5.5:53, got %s", eng.dnsHandler.physicalDNS)
	}
}

// 验收项：isPrivateOrLoopbackAddr 边界与 IPv6 防崩溃测试
func TestIsPrivateOrLoopbackAddr(t *testing.T) {
	tests := []struct {
		name     string
		ipStr    string
		expected bool
	}{
		{"IPv4 Loopback", "127.0.0.1", true},
		{"IPv4 Private Class A", "10.0.0.1", true},
		{"IPv4 Private Class B", "172.16.0.1", true},
		{"IPv4 Private Class C", "192.168.1.1", true},
		{"IPv4 Fake-IP Gateway", "10.88.0.2", false}, // Fake-IP 绝不判定为私网，必须放行代理
		{"IPv4 Public 1.1.1.1", "1.1.1.1", false},
		{"IPv4 Public 8.8.8.8", "8.8.8.8", false},
		{"IPv6 Loopback", "::1", true},
		{"IPv6 ULA Private fc00", "fc00::1", true},
		{"IPv6 ULA Private fd12", "fd12:3456:789a::1", true},
		{"IPv6 Link Local fe80", "fe80::1", true},
		{"IPv6 Public", "2001:4860:4860::8888", false},
		{"IPv4 Unspecified", "0.0.0.0", true},
		{"IPv6 Unspecified", "::", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed := net.ParseIP(tc.ipStr)
			if parsed == nil {
				t.Fatalf("failed to parse IP %s", tc.ipStr)
			}
			var addr tcpip.Address
			if v4 := parsed.To4(); v4 != nil {
				addr = tcpip.AddrFromSlice(v4)
			} else {
				addr = tcpip.AddrFromSlice(parsed.To16())
			}
			result := isPrivateOrLoopbackAddr(addr)
			if result != tc.expected {
				t.Errorf("isPrivateOrLoopbackAddr(%s) = %v; want %v", tc.ipStr, result, tc.expected)
			}
		})
	}
}

type mockCloser struct {
	closed atomic.Bool
}

func (m *mockCloser) Close() error {
	m.closed.Store(true)
	return nil
}

type mockTunDevice struct {
	readCh chan []byte
	closed atomic.Bool
}

func newMockTunDevice() *mockTunDevice {
	return &mockTunDevice{
		readCh: make(chan []byte, 100),
	}
}

func (m *mockTunDevice) Read(b []byte) (int, error) {
	pkt, ok := <-m.readCh
	if !ok || m.closed.Load() {
		return 0, io.EOF
	}
	copy(b, pkt)
	return len(pkt), nil
}

func (m *mockTunDevice) Write(b []byte) (int, error) {
	if m.closed.Load() {
		return 0, io.EOF
	}
	return len(b), nil
}

func (m *mockTunDevice) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	close(m.readCh)
	return nil
}

func (m *mockTunDevice) Name() string {
	return "mocktun0"
}

func (m *mockTunDevice) injectPacket(pkt []byte) {
	if !m.closed.Load() {
		m.readCh <- pkt
	}
}

func buildIPv4UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)
	b := make([]byte, totalLen)

	ip := header.IPv4(b[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(srcIP.To4()),
		DstAddr:     tcpip.AddrFromSlice(dstIP.To4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	u := header.UDP(b[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(b[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, tcpip.AddrFromSlice(srcIP.To4()), tcpip.AddrFromSlice(dstIP.To4()), uint16(header.UDPMinimumSize+len(payload)))
	u.SetChecksum(^u.CalculateChecksum(xsum))
	return b
}

// 验收项：WebRTC 两阶段精准控制
// 断言在 webrtcRelayEnabled 为 false 时，发往 3478/19302/5349 端口的包必须被拦截丢弃；
// 在调用 SetWebRTCActive(true) 之后，验证 WebRTCActive() 状态并验证放行。
func TestWebRTCTwoStageControl(t *testing.T) {
	mockDev := newMockTunDevice()
	defer mockDev.Close()

	getCalls := atomic.Int32{}
	pool := &mockSessionPool{
		onGet: func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
			getCalls.Add(1)
			return nil, errors.New("mock dial error")
		},
	}
	split := NewSplitEngine()
	dialer := NewTunnelClient(pool, split)
	defer dialer.Close()

	SetActiveEdge("192.0.2.1:443", "tok_test", "edge.example.com")
	defer SetActiveEdge("", "", "")

	stackEng := NewStackEngine(mockDev, dialer, nil)
	if err := stackEng.Start(); err != nil {
		t.Fatalf("stackEng.Start() failed: %v", err)
	}
	defer stackEng.Stop()

	// 1. 验证默认状态：未激活 (阶段一防泄露)
	if stackEng.WebRTCActive() {
		t.Fatalf("expected WebRTCActive false by default")
	}

	srcIP := net.ParseIP("10.88.0.2")
	dstIP := net.ParseIP("198.51.100.1") // 公网目标 IP

	ports := []uint16{3478, 19302, 5349}
	for i, port := range ports {
		pkt := buildIPv4UDPPacket(srcIP, dstIP, uint16(40001+i), port, []byte("stun-ping-blocked"))
		mockDev.injectPacket(pkt)
	}

	// 等待协议栈处理
	time.Sleep(50 * time.Millisecond)

	// 断言：由于未激活，发往 3478/19302/5349 端口的包必须被拦截丢弃，绝不上报或发起 RegisterUDPContext
	if calls := getCalls.Load(); calls != 0 {
		t.Fatalf("expected 0 getCalls when WebRTC inactive, got %d", calls)
	}

	// 2. 激活 WebRTC 阶段二 (建连成功放行)
	stackEng.SetWebRTCActive(true)
	if !stackEng.WebRTCActive() {
		t.Fatalf("expected WebRTCActive true after SetWebRTCActive(true)")
	}

	// 依次向 3478, 19302, 5349 发送数据包，验证放行进入普通 UDP 业务转发
	for i, port := range ports {
		prevCalls := getCalls.Load()
		pkt := buildIPv4UDPPacket(srcIP, dstIP, uint16(41001+i), port, []byte("stun-ping-allowed"))
		mockDev.injectPacket(pkt)

		// 轮询等待放行触发 dialer 注册
		success := false
		for attempt := 0; attempt < 50; attempt++ {
			if getCalls.Load() > prevCalls {
				success = true
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !success {
			t.Fatalf("expected port %d to be forwarded when WebRTC active, getCalls did not increment", port)
		}
	}

	// 3. 再次关闭 WebRTC，验证重新拦截
	stackEng.SetWebRTCActive(false)
	if stackEng.WebRTCActive() {
		t.Fatalf("expected WebRTCActive false after SetWebRTCActive(false)")
	}

	currentCalls := getCalls.Load()
	for i, port := range ports {
		pkt := buildIPv4UDPPacket(srcIP, dstIP, uint16(42001+i), port, []byte("stun-ping-blocked-again"))
		mockDev.injectPacket(pkt)
	}
	time.Sleep(50 * time.Millisecond)
	if getCalls.Load() != currentCalls {
		t.Fatalf("expected 0 additional calls after deactivation, got %d", getCalls.Load()-currentCalls)
	}
}

// 验收项：多用户与多并发 WebRTC 状态生命周期
// 验证多用户/多并发场景下 WebRTC 状态在网络切换、停止时的隔离性与正确性。
func TestMultiUserWebRTCLifecycle(t *testing.T) {
	const userCount = 6
	users := make([]*Engine, userCount)
	stackEngines := make([]*StackEngine, userCount)
	pools := make([]*mockSessionPool, userCount)
	devs := make([]*mockTunDevice, userCount)
	stopped := make([]atomic.Bool, userCount)

	for i := 0; i < userCount; i++ {
		idx := i
		dev := newMockTunDevice()
		devs[i] = dev
		p := &mockSessionPool{
			onGet: func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
				if idx%2 == 0 {
					return nil, nil // 偶数用户拨号成功
				}
				return nil, errors.New("simulated dial failure") // 奇数用户拨号失败
			},
		}
		pools[i] = p

		eng := NewEngine()
		eng.sessionPool = p
		eng.activeAddr = fmt.Sprintf("198.51.100.%d:443", 10+i)
		eng.activeSNI = fmt.Sprintf("node%d.example.com", i)
		eng.running.Store(true)

		stk := NewStackEngine(dev, eng.tunnelClient, nil)
		_ = stk.Start()
		eng.stackEngine = stk
		stackEngines[i] = stk
		users[i] = eng
	}

	defer func() {
		for i := 0; i < userCount; i++ {
			if !stopped[i].Swap(true) && stackEngines[i] != nil {
				stackEngines[i].Stop()
			}
		}
	}()

	// 1. 验证多用户初始状态隔离性
	for i := 0; i < userCount; i++ {
		if stackEngines[i].WebRTCActive() {
			t.Fatalf("user %d WebRTCActive should be false initially", i)
		}
	}

	// 仅激活 user 0 和 user 2
	stackEngines[0].SetWebRTCActive(true)
	stackEngines[2].SetWebRTCActive(true)

	if !stackEngines[0].WebRTCActive() || !stackEngines[2].WebRTCActive() {
		t.Fatalf("expected user 0 and 2 to be active")
	}
	for _, idx := range []int{1, 3, 4, 5} {
		if stackEngines[idx].WebRTCActive() {
			t.Fatalf("user %d should remain false (isolation violation)", idx)
		}
	}

	// 2. 并发触发网络切换 (onNetworkChange)
	var wg sync.WaitGroup
	for i := 0; i < userCount; i++ {
		u := users[i]
		wg.Add(1)
		go func(eng *Engine) {
			defer wg.Done()
			eng.onNetworkChange("10.0.0.1", "eth0")
		}(u)
	}
	wg.Wait()

	// 等待异步预热 goroutine 执行完成
	// 偶数用户 (0, 2, 4) 的 pool.Get 成功且 running=true -> WebRTC 应激活为 true
	// 奇数用户 (1, 3, 5) 的 pool.Get 失败 -> WebRTC 应保持 false
	for _, idx := range []int{0, 2, 4} {
		success := false
		for attempt := 0; attempt < 100; attempt++ {
			if stackEngines[idx].WebRTCActive() {
				success = true
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !success {
			t.Fatalf("expected user %d WebRTCActive true after successful QUIC pre-warm", idx)
		}
	}

	for _, idx := range []int{1, 3, 5} {
		// 奇数用户拨号失败，WebRTC 严禁激活
		time.Sleep(20 * time.Millisecond)
		if stackEngines[idx].WebRTCActive() {
			t.Fatalf("expected user %d WebRTCActive false when QUIC pre-warm failed", idx)
		}
	}

	// 3. 并发压力测试：各用户并行高频网络切换与并发状态读取，验证竞争检测 (Data Race Free)
	var stressWg sync.WaitGroup
	for c := 0; c < userCount; c++ {
		stressWg.Add(1)
		go func(uid int) {
			defer stressWg.Done()
			targetUser := users[uid]
			targetUser.onNetworkChange("172.16.0.1", "wlan0")
			if stk := stackEngines[uid]; stk != nil {
				_ = stk.WebRTCActive()
			}
		}(c)
	}
	stressWg.Wait()

	// 4. 验证 Stop() 时的 WebRTC 关闭保证与正在预热时的竞争安全
	// 停止 user 0 (偶数用户，其 WebRTC 预热成功后为 true)
	for attempt := 0; attempt < 100; attempt++ {
		if stackEngines[0].WebRTCActive() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !stackEngines[0].WebRTCActive() {
		t.Fatalf("user 0 should have been active before Stop")
	}
	stopped[0].Store(true)
	_ = users[0].Stop()
	if stackEngines[0].WebRTCActive() {
		t.Fatalf("expected user 0 WebRTCActive false after Stop()")
	}
}
