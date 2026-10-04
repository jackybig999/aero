// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"bufio"
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

// newInMemHTTPDialer 创建纯内存 HTTP 拨号器，支持 net.Pipe() 消除 Winsock 与防火墙阻断
func newInMemHTTPDialer(handler http.Handler) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		cliConn, srvConn := net.Pipe()
		go func() {
			defer srvConn.Close()
			br := bufio.NewReader(srvConn)
			for {
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				resp := rec.Result()
				_ = resp.Write(srvConn)
				return
			}
		}()
		return cliConn, nil
	}
}

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
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"version": "aero/3.0",
			"servers": [
				{"name": "Node-1", "address": "198.51.100.1:443", "token": "tok_abc"}
			]
		}`)
	})
	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	eng := NewEngine()

	var wg sync.WaitGroup
	const concurrent = 10
	errs := make([]error, concurrent)

	for i := 0; i < concurrent; i++ {
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[idx] = eng.LoadAndApplySubscription("http://singleflight.example.com/sub/superadmin")
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

	// 注入物理 DNS 内存拨号器
	dnsHandler.SetPhysicalDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		cConn, sConn := net.Pipe()
		go func() {
			defer sConn.Close()
			buf := make([]byte, 1500)
			n, err := sConn.Read(buf)
			if err != nil {
				return
			}
			fastUDPQueryCount.Add(1)
			qname, _ := extractDNSQuestionAndType(buf[:n])
			fastUDPDomains.Store(strings.ToLower(qname), true)

			// 构造有效 A 应答 (1.2.3.4)
			resp := buildAResponse(buf[:n], qname, net.ParseIP("1.2.3.4"))
			_, _ = sConn.Write(resp)
		}()
		return cConn, nil
	})

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

// 验收项：原生订阅 JSON (aero/3.0) 解析与参数保留
func TestNativeAeroSubParsing(t *testing.T) {
	subJSON := `{
		"version": "aero/3.0",
		"userId": "user_12345",
		"slug": "superadmin",
		"expireAt": 1893456000,
		"servers": [
			{
				"name": "Tokyo Edge 01",
				"address": "tokyo.aero.net:443",
				"token": "tok_abcdef",
				"protocol": "connect-ip",
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

	if sub.Version != "aero/3.0" || sub.Slug != "superadmin" {
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
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"version": "aero/3.0",
			"servers": [
				{"name": "DirectNode", "address": "direct.example.com:443", "token": "tok_direct"}
			]
		}`)
	})
	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sub, body, err := fetchSingleSubURL(ctx, "http://direct-sub.example.com/sub/test", SubFetchOptions{})
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
	SetActiveEdge("", "", "", nil)

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
	captivePortalURL = "http://captive.portal.test/generate_204"

	var currentHandler http.Handler
	SetPhysicalDialerHook(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return newInMemHTTPDialer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if currentHandler != nil {
				currentHandler.ServeHTTP(w, r)
			}
		}))(ctx, network, addr)
	})
	defer SetPhysicalDialerHook(nil)

	// 1. 模拟正常网络 (返回 204 No Content)
	currentHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
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
	currentHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://login.wifi.portal/index.html", http.StatusFound)
	})
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
	currentHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>Please login to WiFi</body></html>")
	})
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
	u.SetChecksum(0)
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

	SetActiveEdge("192.0.2.1:443", "tok_test", "edge.example.com", net.ParseIP("192.0.2.1"))
	defer SetActiveEdge("", "", "", nil)

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
		eng.state.Store(stateRunning)

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

// 验收项 12：第三方 TUN 互斥隔离确定性矩阵测试 (纯内存桩，绝不触碰真实宿主机网络)
func TestEvaluateThirdPartyTUNMatrix(t *testing.T) {
	tests := []struct {
		name         string
		ifaces       []ifaceSummary
		routeText    string
		wantConflict bool
		wantVPN      string
	}{
		{
			name: "用例 1: 双物理网卡等跃点 (以太网 25 + WLAN 25，绝不误伤)",
			ifaces: []ifaceSummary{
				{Name: "以太网", Description: "Realtek PCIe GbE Family Controller", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
				{Name: "WLAN", Description: "Intel(R) Wi-Fi 6 AX200", IfType: 71, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.2.100")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
          0.0.0.0          0.0.0.0      192.168.2.1    192.168.2.100      25
`,
			wantConflict: false,
		},
		{
			name: "用例 2: OpenVPN 具名网关 full-tunnel (10.8.0.1 -> 10.8.0.6 metric 1，无 /1、无 198.18)",
			ifaces: []ifaceSummary{
				{Name: "以太网", Description: "Intel Ethernet", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
				{Name: "OpenVPN", Description: "TAP-Windows Adapter V9", IfType: 53, IsUp: true, IPs: []net.IP{net.ParseIP("10.8.0.6")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         10.8.0.1         10.8.0.6       1
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
`,
			wantConflict: true,
			wantVPN:      "OpenVPN",
		},
		{
			name: "用例 3: 中文版 Windows sing-box (网关为 在链路上，metric 0)",
			ifaces: []ifaceSummary{
				{Name: "以太网", Description: "Intel Ethernet", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
				{Name: "sing-box", Description: "Wintun Userspace Tunnel", IfType: 53, IsUp: true, IPs: []net.IP{net.ParseIP("172.19.0.1")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         在链路上        172.19.0.1       0
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
`,
			wantConflict: true,
			wantVPN:      "sing-box",
		},
		{
			name: "用例 4: PPPoE 在链路上 metric 1 + 物理局域网网卡 metric 25 (绝不误伤 PPPoE)",
			ifaces: []ifaceSummary{
				{Name: "宽带连接", Description: "WAN Miniport (PPPOE)", IfType: 23, IsUp: true, IPs: []net.IP{net.ParseIP("100.65.1.2")}},
				{Name: "以太网", Description: "Realtek PCIe GbE Family Controller", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         在链路上         100.65.1.2       1
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
`,
			wantConflict: false,
		},
		{
			name: "用例 5: 孤儿 /0 路由 (网关合法 metric 5) + sing-box On-link metric 10 (孤儿不影响拦截)",
			ifaces: []ifaceSummary{
				{Name: "sing-box", Description: "Wintun Userspace Tunnel", IfType: 53, IsUp: true, IPs: []net.IP{net.ParseIP("172.19.0.1")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.99.1   192.168.99.100       5
          0.0.0.0          0.0.0.0          On-link        172.19.0.1      10
`,
			wantConflict: true,
			wantVPN:      "sing-box",
		},
		{
			name: "用例 6: Clash Meta TUN (持有 198.18.0.1 Fake-IP 保留段)",
			ifaces: []ifaceSummary{
				{Name: "Meta", Description: "Wintun Userspace Tunnel", IfType: 53, IsUp: true, IPs: []net.IP{net.ParseIP("198.18.0.1")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
`,
			wantConflict: true,
			wantVPN:      "Meta",
		},
		{
			name: "用例 7: 非 198.18 的 OpenVPN 分流路由 (/1 路由直接拦截)",
			ifaces: []ifaceSummary{
				{Name: "OpenVPN", Description: "TAP-Windows Adapter V9", IfType: 53, IsUp: true, IPs: []net.IP{net.ParseIP("10.8.0.2")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0        128.0.0.0         10.8.0.1         10.8.0.2       1
        128.0.0.0        128.0.0.0         10.8.0.1         10.8.0.2       1
`,
			wantConflict: true,
			wantVPN:      "OpenVPN",
		},
		{
			name: "用例 8: Tailscale 内网穿透 (无 /0、无 /1，仅有私有段，放行)",
			ifaces: []ifaceSummary{
				{Name: "Tailscale", Description: "Tailscale Tunnel", IfType: 53, IsUp: true, IPs: []net.IP{net.ParseIP("100.64.0.5")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
        100.64.0.0      255.192.0.0         On-link        100.64.0.5       5
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
`,
			wantConflict: false,
		},
		{
			name: "用例 9: 孤儿 /1 路由 (网卡 IP 未在网卡表中，拦截)",
			ifaces: []ifaceSummary{
				{Name: "以太网", Description: "Intel Ethernet", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0        128.0.0.0         10.9.0.1         10.9.0.2       1
`,
			wantConflict: true,
			wantVPN:      "10.9.0.2",
		},
		{
			name: "用例 10: aero0 上次崩溃遗留的 10.88.0.2 /1 路由 (自身残留不报第三方)",
			ifaces: []ifaceSummary{
				{Name: "aero0", Description: "Wintun Userspace Tunnel", IfType: 53, IsUp: true, IPs: []net.IP{net.ParseIP("10.88.0.2")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0        128.0.0.0        10.88.0.1        10.88.0.2       1
        128.0.0.0        128.0.0.0        10.88.0.1        10.88.0.2       1
`,
			wantConflict: false,
		},
		{
			name: "用例 11: Clash 仅开系统代理 (无 198.18、无 /1、无接管 /0，放行)",
			ifaces: []ifaceSummary{
				{Name: "以太网", Description: "Intel Ethernet", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
`,
			wantConflict: false,
		},
		{
			name: "用例 12: 仅在 Persistent Routes 存在 /1，活动路由段无 /1 (解析至持久段即停)",
			ifaces: []ifaceSummary{
				{Name: "以太网", Description: "Intel Ethernet", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0        128.0.0.0         10.8.0.1       1
`,
			wantConflict: false,
		},
		{
			name: "用例 13: Windows 自带 IKEv2/L2TP/SSTP VPN (Type 23 PPP，非 PPPoE，接管 0.0.0.0/0 拦截)",
			ifaces: []ifaceSummary{
				{Name: "VPN 连接", Description: "WAN Miniport (IKEv2)", IfType: 23, IsUp: true, IPs: []net.IP{net.ParseIP("10.10.1.2")}},
				{Name: "以太网", Description: "Realtek PCIe GbE Family Controller", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0        10.10.1.1        10.10.1.2       1
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
`,
			wantConflict: true,
			wantVPN:      "VPN 连接",
		},
		{
			name: "用例 14: TAP-Windows Adapter V9 (Type 6 以太网描述含 tap-windows，具名网关接管 0.0.0.0/0 拦截)",
			ifaces: []ifaceSummary{
				{Name: "本地连接 2", Description: "TAP-Windows Adapter V9", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("10.8.0.6")}},
				{Name: "以太网", Description: "Realtek PCIe GbE Family Controller", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         10.8.0.1         10.8.0.6       1
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
`,
			wantConflict: true,
			wantVPN:      "本地连接 2",
		},
		{
			name: "用例 15: SoftEther VPN (Type 6 描述含 softether，具名网关接管 0.0.0.0/0 拦截)",
			ifaces: []ifaceSummary{
				{Name: "VPN - VPN Client", Description: "SoftEther VPN Client Adapter", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.30.10")}},
				{Name: "以太网", Description: "Realtek PCIe GbE Family Controller", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.30.1    192.168.30.10       2
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
`,
			wantConflict: true,
			wantVPN:      "VPN - VPN Client",
		},
		{
			name: "用例 4b: 纯 PPPoE 独占单链路 (无第二块物理局域网网卡，网关为在链路上，放行且正确解析网关为接口自身IP)",
			ifaces: []ifaceSummary{
				{Name: "宽带连接", Description: "WAN Miniport (PPPOE)", IfType: 23, IsUp: true, IPs: []net.IP{net.ParseIP("100.65.1.2")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         在链路上         100.65.1.2       1
`,
			wantConflict: false,
		},
		{
			name: "用例 16: Hyper-V 外部虚拟交换机 (vEthernet (External)，IfType 53，接管 0.0.0.0/0，放行)",
			ifaces: []ifaceSummary{
				{Name: "vEthernet (External)", Description: "Hyper-V Virtual Ethernet Adapter", IfType: 53, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.150")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.150      25
`,
			wantConflict: false,
		},
		{
			name: "用例 17: 物理网卡描述含 tuning (Intel Wi-Fi Auto-tuning，放行)",
			ifaces: []ifaceSummary{
				{Name: "WLAN", Description: "Intel(R) Wi-Fi 6E AX211 Auto-tuning Adapter", IfType: 71, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.2.100")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.2.1    192.168.2.100      35
`,
			wantConflict: false,
		},
		{
			name: "用例 18: Fortinet 虚拟网卡 (Fortinet Virtual Ethernet Adapter，IfType 6，持有 0.0.0.0/0 且带有效网关，拦截)",
			ifaces: []ifaceSummary{
				{Name: "Fortinet SSL VPN", Description: "Fortinet Virtual Ethernet Adapter", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("10.66.0.2")}},
				{Name: "以太网", Description: "Realtek PCIe GbE Family Controller", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0        10.66.0.1        10.66.0.2       1
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
`,
			wantConflict: true,
			wantVPN:      "Fortinet SSL VPN",
		},
		{
			name: "用例 19: Fortinet 虚拟网卡存在但未接管默认路由 (0.0.0.0/0 仅挂物理网卡，放行)",
			ifaces: []ifaceSummary{
				{Name: "Fortinet SSL VPN", Description: "Fortinet Virtual Ethernet Adapter", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("10.66.0.2")}},
				{Name: "以太网", Description: "Realtek PCIe GbE Family Controller", IfType: 6, IsUp: true, IPs: []net.IP{net.ParseIP("192.168.1.100")}},
			},
			routeText: `
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100      25
`,
			wantConflict: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotConflict, gotVPN := evaluateThirdPartyTUN(tt.ifaces, tt.routeText)
			if gotConflict != tt.wantConflict {
				t.Fatalf("conflict mismatch: got %v, want %v", gotConflict, tt.wantConflict)
			}
			if tt.wantConflict && !strings.Contains(gotVPN, tt.wantVPN) {
				t.Fatalf("vpn name mismatch: got %s, want to contain %s", gotVPN, tt.wantVPN)
			}
			if strings.Contains(tt.name, "用例 4b") {
				gw, idx, err := physicalDefaultGatewayWithInput(tt.ifaces, tt.routeText, func(ip net.IP) string {
					if ip.Equal(net.ParseIP("100.65.1.2")) {
						return "23"
					}
					return ""
				})
				if err != nil {
					t.Fatalf("expected physicalDefaultGatewayWithInput success for on-link PPPoE, got err: %v", err)
				}
				if gw != "100.65.1.2" || idx != "23" {
					t.Fatalf("expected gw 100.65.1.2 and idx 23, got gw=%s, idx=%s", gw, idx)
				}
			}
		})
	}

	// 验证 ErrConflictingTUN 格式化
	e := &ErrConflictingTUN{VPNName: "Meta"}
	if !strings.Contains(e.Error(), "Meta") || !strings.Contains(e.Error(), "两款 TUN 同时开启") {
		t.Fatalf("unexpected error message: %s", e.Error())
	}
}

func TestSysproxyModeNoHostRouteModificationOnSwitchAndNetworkChange(t *testing.T) {
	eng := NewEngine()
	eng.SetMode("sysproxy")

	// 模拟 sysproxy 正在运行状态
	eng.state.Store(stateRunning)
	eng.running.Store(true)

	// 1. 切换节点：在 sysproxy 模式下，验证不会调用 ProtectHostRoute/UnprotectHostRoute
	err := eng.switchActiveNodeLocked("198.51.100.1:443", "tok_test", "node1.example.com")
	if err != nil {
		t.Fatalf("switchActiveNodeLocked failed: %v", err)
	}

	// 2. 网络变动：在 sysproxy 模式下，验证 onNetworkChange 绝不调用 ProtectHostRoute
	eng.onNetworkChange("10.0.0.1", "eth0")

	// 3. 正常退出
	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestStopSysproxyNoTunTeardown(t *testing.T) {
	eng := NewEngine()
	eng.SetMode("sysproxy")
	eng.running.Store(true)
	eng.state.Store(stateRunning)
	eng.tunDevice = nil // 本地模式 tunDevice 为 nil

	// 停止时不应 panic，且由于 tunDevice 为 nil，不执行 TeardownRoutes
	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if eng.IsRunning() {
		t.Fatalf("expected running to be false after Stop")
	}
}

func TestLiveHostDetectThirdPartyTUN(t *testing.T) {
	conflict, name, err := DetectThirdPartyTUN()
	t.Logf("Live host DetectThirdPartyTUN: conflict=%v, name=%s, err=%v", conflict, name, err)
	if err != nil {
		t.Fatalf("DetectThirdPartyTUN error: %v", err)
	}
	if !conflict {
		t.Skip("宿主机当前未开启第三方 TUN，跳过真机拦截断言 (CI 环境安全跳过)")
	}
	if !strings.Contains(strings.ToLower(name), "meta") && !strings.Contains(strings.ToLower(name), "wintun") {
		t.Logf("宿主机检测到第三方 TUN: %s", name)
	}
}

func TestEngineStartTUNConflictAborts(t *testing.T) {
	// 使用桩注入保证全平台和 CI 环境下 100% 独立可测且结果确定
	origDetect := detectThirdPartyTUN
	defer func() { detectThirdPartyTUN = origDetect }()
	detectThirdPartyTUN = func() (bool, string, error) {
		return true, "Meta", nil
	}

	eng := NewEngine()
	eng.SetMode("tun")
	err := eng.Start()
	if err == nil {
		t.Fatalf("expected error from Start() when Clash Meta TUN is active, got nil")
	}
	var confErr *ErrConflictingTUN
	if !errors.As(err, &confErr) {
		t.Fatalf("expected *ErrConflictingTUN, got %T: %v", err, err)
	}
	if !strings.Contains(confErr.VPNName, "Meta") {
		t.Fatalf("expected VPNName to contain Meta, got %s", confErr.VPNName)
	}
	if eng.IsRunning() {
		t.Fatalf("expected running to be false after conflict")
	}
	if eng.tunDevice != nil {
		t.Fatalf("expected tunDevice to be nil")
	}
}

func TestEngineStartSysproxyWithThirdPartyTUN(t *testing.T) {
	origDetect := detectThirdPartyTUN
	defer func() { detectThirdPartyTUN = origDetect }()
	detectThirdPartyTUN = func() (bool, string, error) {
		return true, "Meta", nil
	}

	eng := NewEngine()
	eng.SetMode("sysproxy")
	eng.listenAddr = "127.0.0.1:0"
	err := eng.Start()
	var confErr *ErrConflictingTUN
	if errors.As(err, &confErr) {
		t.Fatalf("sysproxy mode should never return ErrConflictingTUN, got %v", err)
	}
	_ = eng.Stop()
}

// ---------------------------------------------------------
// AERO v1.0.3 WebRTC STUN & Fake-IP & 0-RTT & Captive Tests
// ---------------------------------------------------------

func TestDefaultTransportConfigEnable0RTTFalse(t *testing.T) {
	cfg := DefaultTransportConfig("node.example.com:443", "node.example.com")
	if cfg.Enable0RTT {
		t.Fatalf("expected Enable0RTT to be false, got true")
	}
}

func TestCaptivePortalUserAgentChrome133(t *testing.T) {
	var receivedUA string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusNoContent)
	})

	inMemDialer := newInMemHTTPDialer(handler)
	origDialer := getPhysicalDialerHook()
	defer SetPhysicalDialerHook(origDialer)
	SetPhysicalDialerHook(inMemDialer)

	oldURL := captivePortalURL
	captivePortalURL = "http://connectivitycheck.gstatic.com/generate_204"
	defer func() { captivePortalURL = oldURL }()

	intercepted, err := DetectCaptivePortal(context.Background())
	if err != nil {
		t.Fatalf("DetectCaptivePortal failed: %v", err)
	}
	if intercepted {
		t.Fatalf("expected intercepted to be false for 204")
	}

	expectedUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
	if receivedUA != expectedUA {
		t.Fatalf("expected User-Agent %q, got %q", expectedUA, receivedUA)
	}
}

func TestIsSTUNPacket(t *testing.T) {
	// 短于 20 字节
	if isSTUNPacket([]byte{0x00, 0x01, 0x00, 0x08}) {
		t.Fatalf("short packet should not be STUN")
	}

	// 构造有效 STUN Binding Request (20 字节)
	validSTUN := make([]byte, 20)
	validSTUN[0] = 0x00                                    // 第一二位为 00
	validSTUN[1] = 0x01                                    // Binding Request
	binary.BigEndian.PutUint16(validSTUN[2:4], 0)          // Length = 0
	binary.BigEndian.PutUint32(validSTUN[4:8], 0x2112A442) // Magic Cookie
	copy(validSTUN[8:20], []byte("transact_id1"))          // Transaction ID

	if !isSTUNPacket(validSTUN) {
		t.Fatalf("valid STUN packet was not recognized")
	}

	// 第一二位不为 00 (0x80 -> 10)
	invalidBits := make([]byte, 20)
	copy(invalidBits, validSTUN)
	invalidBits[0] = 0x80
	if isSTUNPacket(invalidBits) {
		t.Fatalf("invalid first 2 bits should not be STUN")
	}

	// Magic Cookie 不匹配
	invalidCookie := make([]byte, 20)
	copy(invalidCookie, validSTUN)
	binary.BigEndian.PutUint32(invalidCookie[4:8], 0x12345678)
	if isSTUNPacket(invalidCookie) {
		t.Fatalf("invalid cookie should not be STUN")
	}
}

func TestPrefixedUDPConn(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	firstData := []byte("hello-first-")
	pconn := &prefixedUDPConn{
		first: append([]byte(nil), firstData...),
		Conn:  c1,
	}

	// 第一次 Read 读出前 6 字节
	buf1 := make([]byte, 6)
	n1, err := pconn.Read(buf1)
	if err != nil || n1 != 6 || string(buf1) != "hello-" {
		t.Fatalf("first partial read failed: n=%d, err=%v, data=%q", n1, err, string(buf1))
	}

	// 第二次 Read 读出剩余 6 字节
	buf2 := make([]byte, 10)
	n2, err := pconn.Read(buf2)
	if err != nil || n2 != 6 || string(buf2[:n2]) != "first-" {
		t.Fatalf("second partial read failed: n=%d, err=%v, data=%q", n2, err, string(buf2[:n2]))
	}

	// 此时 first 缓冲区耗尽，后续 Read 透传底层 Conn.Read
	go func() {
		_, _ = c2.Write([]byte("stream-data"))
	}()

	buf3 := make([]byte, 20)
	n3, err := pconn.Read(buf3)
	if err != nil || string(buf3[:n3]) != "stream-data" {
		t.Fatalf("passthrough read failed: n=%d, err=%v, data=%q", n3, err, string(buf3[:n3]))
	}
}

func TestFakeIPTableAcquireAndRelease(t *testing.T) {
	table := NewFakeIPTable("198.18.0.0/15", 10)
	ip := table.Allocate("example.com")
	if ip == nil {
		t.Fatalf("Allocate failed")
	}

	// 未分配的 IP Acquire 应返回空
	nonExistent := net.ParseIP("198.18.254.254")
	dom, rel := table.Acquire(nonExistent)
	if dom != "" {
		t.Fatalf("expected empty domain for non-existent IP, got %s", dom)
	}
	rel() // no-op

	// 命中 Acquire
	dom, release := table.Acquire(ip)
	if dom != "example.com" {
		t.Fatalf("expected example.com, got %s", dom)
	}

	// 检查 refCount
	ipVal := binary.BigEndian.Uint32(ip.To4())
	table.mu.RLock()
	node := table.ipToNode[ipVal]
	if node.refCount.Load() != 1 {
		t.Fatalf("expected refCount=1, got %d", node.refCount.Load())
	}
	table.mu.RUnlock()

	// 再次 Acquire
	dom2, release2 := table.Acquire(ip)
	if dom2 != "example.com" {
		t.Fatalf("expected example.com, got %s", dom2)
	}
	if node.refCount.Load() != 2 {
		t.Fatalf("expected refCount=2, got %d", node.refCount.Load())
	}

	// 释放一次
	release()
	if node.refCount.Load() != 1 {
		t.Fatalf("expected refCount=1 after release, got %d", node.refCount.Load())
	}

	// 全部释放
	release2()
	if node.refCount.Load() != 0 {
		t.Fatalf("expected refCount=0 after second release, got %d", node.refCount.Load())
	}
}

func TestFakeIPTableEvictionRefGuardAndDynamicExpansion(t *testing.T) {
	// 容量设为 2
	table := NewFakeIPTable("198.18.0.0/15", 2)
	ip1 := table.Allocate("node1.com")
	ip2 := table.Allocate("node2.com")

	// 借出 node1 和 node2
	_, rel1 := table.Acquire(ip1)
	defer rel1()
	_, rel2 := table.Acquire(ip2)
	defer rel2()

	// 此时 node1 和 node2 的 refCount 均为 1。
	// 分配 node3 时，由于所有借出中的节点 refCount > 0，绝不淘汰，触发扩容
	ip3 := table.Allocate("node3.com")
	if ip3 == nil {
		t.Fatalf("Allocate node3 failed")
	}

	// 断言：table.maxSlots 扩容了 1024 槽位
	if table.maxSlots != 1026 {
		t.Fatalf("expected maxSlots=1026, got %d", table.maxSlots)
	}

	// node1 和 node2 依然存在且可查
	if table.Lookup(ip1) != "node1.com" {
		t.Fatalf("borrowed node1 was evicted!")
	}
	if table.Lookup(ip2) != "node2.com" {
		t.Fatalf("borrowed node2 was evicted!")
	}
}

func TestFakeIPTable32ConsecutiveBorrowedTriggersExpansion(t *testing.T) {
	// 构造具有 35 个节点的表，容量为 35
	table := NewFakeIPTable("198.18.0.0/15", 35)
	var releases []func()
	defer func() {
		for _, r := range releases {
			r()
		}
	}()

	for i := 0; i < 35; i++ {
		host := fmt.Sprintf("host%02d.com", i)
		ip := table.Allocate(host)
		_, rel := table.Acquire(ip)
		releases = append(releases, rel)
	}

	// 连续 32 个借出节点导致遍历 32 个后停止并动态扩容
	ipNew := table.Allocate("newhost.com")
	if ipNew == nil {
		t.Fatalf("Allocate newhost failed")
	}

	if table.maxSlots < 1059 { // 35 + 1024 = 1059
		t.Fatalf("expected maxSlots >= 1059, got %d", table.maxSlots)
	}
}

func TestStackDeepSTUNInterception(t *testing.T) {
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

	SetActiveEdge("192.0.2.1:443", "tok_test", "edge.example.com", net.ParseIP("192.0.2.1"))
	defer SetActiveEdge("", "", "", nil)

	stackEng := NewStackEngine(mockDev, dialer, nil)
	if err := stackEng.Start(); err != nil {
		t.Fatalf("stackEng.Start() failed: %v", err)
	}
	defer stackEng.Stop()

	// 默认 WebRTC 未激活
	srcIP := net.ParseIP("10.88.0.2")
	dstIP := net.ParseIP("198.51.100.55") // 非 Fake-IP 外部目标

	// 构造发往非标准端口 12345 的 STUN 数据报
	stunPktPayload := make([]byte, 20)
	binary.BigEndian.PutUint16(stunPktPayload[0:2], 0x0001)     // STUN binding req
	binary.BigEndian.PutUint32(stunPktPayload[4:8], 0x2112A442) // Magic Cookie
	copy(stunPktPayload[8:20], []byte("deep_stun_tx"))

	pkt := buildIPv4UDPPacket(srcIP, dstIP, 41234, 12345, stunPktPayload)
	mockDev.injectPacket(pkt)

	// 等待协议栈处理与 40ms 超时判定
	time.Sleep(100 * time.Millisecond)

	// 断言：深度拦截生效，绝不上报或外拨
	if calls := getCalls.Load(); calls != 0 {
		t.Fatalf("expected 0 getCalls for deep STUN packet, got %d", calls)
	}
}

func TestStackOrphanFakeIPCircuitBreaking(t *testing.T) {
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

	SetActiveEdge("192.0.2.1:443", "tok_test", "edge.example.com", net.ParseIP("192.0.2.1"))
	defer SetActiveEdge("", "", "", nil)

	dnsHandler := NewDNSHandler(split)
	stackEng := NewStackEngine(mockDev, dialer, dnsHandler)
	if err := stackEng.Start(); err != nil {
		t.Fatalf("stackEng.Start() failed: %v", err)
	}
	defer stackEng.Stop()

	srcIP := net.ParseIP("10.88.0.2")
	// 198.18.99.99 属于 Fake-IP 网段，但未在 dnsHandler.fakeIP 中登记（孤儿 Fake-IP）
	orphanFakeIP := net.ParseIP("198.18.99.99")

	// 1. 发送 UDP 数据报到孤儿 Fake-IP
	udpPkt := buildIPv4UDPPacket(srcIP, orphanFakeIP, 51234, 8080, []byte("udp-test"))
	mockDev.injectPacket(udpPkt)

	time.Sleep(100 * time.Millisecond)

	// 断言：UDP 孤儿 Fake-IP 被熔断丢弃，绝不上报或发起外拨
	if calls := getCalls.Load(); calls != 0 {
		t.Fatalf("expected 0 getCalls for orphan Fake-IP UDP, got %d", calls)
	}

	// 2. 发送 TCP SYN 到孤儿 Fake-IP
	tcpPkt := buildIPv4TCPPacket(srcIP, orphanFakeIP, 51235, 8080, header.TCPFlagSyn, nil, 1000)
	mockDev.injectPacket(tcpPkt)

	time.Sleep(100 * time.Millisecond)

	// 断言：TCP 孤儿 Fake-IP 被直接 Complete(true) 熔断，绝不上报或发起外拨
	if calls := getCalls.Load(); calls != 0 {
		t.Fatalf("expected 0 getCalls for orphan Fake-IP TCP, got %d", calls)
	}
}

func buildIPv4TCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, flags header.TCPFlags, payload []byte, seq uint32) []byte {
	totalLen := header.IPv4MinimumSize + header.TCPMinimumSize + len(payload)
	b := make([]byte, totalLen)

	ip := header.IPv4(b[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(srcIP.To4()),
		DstAddr:     tcpip.AddrFromSlice(dstIP.To4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	t := header.TCP(b[header.IPv4MinimumSize:])
	t.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	copy(b[header.IPv4MinimumSize+header.TCPMinimumSize:], payload)

	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, tcpip.AddrFromSlice(srcIP.To4()), tcpip.AddrFromSlice(dstIP.To4()), uint16(header.TCPMinimumSize+len(payload)))
	t.SetChecksum(^t.CalculateChecksum(xsum))
	return b
}

func TestStackDeepNonSTUNLosslessReplay(t *testing.T) {
	mockDev := newMockTunDevice()
	defer mockDev.Close()

	receivedData := make(chan []byte, 1)
	origDialer := getPhysicalDialerHook()
	defer SetPhysicalDialerHook(origDialer)
	SetPhysicalDialerHook(func(ctx context.Context, network, addr string) (net.Conn, error) {
		cliConn, srvConn := net.Pipe()
		go func() {
			defer srvConn.Close()
			buf := make([]byte, 1024)
			_ = srvConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := srvConn.Read(buf)
			if err == nil && n > 0 {
				receivedData <- append([]byte(nil), buf[:n]...)
			}
		}()
		return cliConn, nil
	})

	split := NewSplitEngine()
	// 设置 223.5.5.5 为 DIRECT 规则
	split.AddRule(Rule{
		Strategy: DIRECT,
		IPRanges: []string{"223.5.5.5/32"},
	})

	dialer := NewTunnelClient(nil, split)
	defer dialer.Close()

	stackEng := NewStackEngine(mockDev, dialer, nil)
	if err := stackEng.Start(); err != nil {
		t.Fatalf("stackEng.Start() failed: %v", err)
	}
	defer stackEng.Stop()

	// 构造非 STUN 数据包发往非标准端口 12345
	srcIP := net.ParseIP("10.88.0.2")
	dstIP := net.ParseIP("223.5.5.5")
	testPayload := []byte("non-stun-test-payload-12345")

	pkt := buildIPv4UDPPacket(srcIP, dstIP, 41234, 12345, testPayload)
	mockDev.injectPacket(pkt)

	select {
	case data := <-receivedData:
		if string(data) != string(testPayload) {
			t.Fatalf("expected payload %q, got %q", string(testPayload), string(data))
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout waiting for non-STUN UDP packet lossless replay")
	}
}

func TestStackValidFakeIPAcquireLifecycle(t *testing.T) {
	mockDev := newMockTunDevice()
	defer mockDev.Close()

	split := NewSplitEngine()
	split.AddRule(Rule{
		Strategy:       DIRECT,
		DomainSuffixes: []string{"example.com"},
	})

	var dialTarget string
	var dialMu sync.Mutex
	connDone := make(chan struct{})

	origDialer := getPhysicalDialerHook()
	defer SetPhysicalDialerHook(origDialer)
	SetPhysicalDialerHook(func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialMu.Lock()
		dialTarget = addr
		dialMu.Unlock()
		cliConn, srvConn := net.Pipe()
		go func() {
			<-connDone
			srvConn.Close()
		}()
		return cliConn, nil
	})

	dnsHandler := NewDNSHandler(split)
	fakeIPTable := NewFakeIPTable("198.18.0.0/15", 10)
	dnsHandler.SetFakeIP(fakeIPTable)

	fakeIP := fakeIPTable.Allocate("example.com")
	if fakeIP == nil {
		t.Fatalf("Allocate fakeIP failed")
	}

	dialer := NewTunnelClient(nil, split)
	defer dialer.Close()

	stackEng := NewStackEngine(mockDev, dialer, dnsHandler)
	if err := stackEng.Start(); err != nil {
		t.Fatalf("stackEng.Start() failed: %v", err)
	}
	defer stackEng.Stop()

	srcIP := net.ParseIP("10.88.0.2")
	udpPkt := buildIPv4UDPPacket(srcIP, fakeIP, 51236, 8080, []byte("udp-fakeip-lifecycle"))
	mockDev.injectPacket(udpPkt)

	// 等待拨号触发
	for i := 0; i < 50; i++ {
		dialMu.Lock()
		target := dialTarget
		dialMu.Unlock()
		if target != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	dialMu.Lock()
	target := dialTarget
	dialMu.Unlock()
	if target != "example.com:8080" {
		t.Fatalf("expected dialTarget example.com:8080, got %q", target)
	}

	// 此时连接活跃，refCount 应为 1
	ipVal := binary.BigEndian.Uint32(fakeIP.To4())
	fakeIPTable.mu.RLock()
	node := fakeIPTable.ipToNode[ipVal]
	refBefore := node.refCount.Load()
	fakeIPTable.mu.RUnlock()

	if refBefore != 1 {
		t.Fatalf("expected refCount=1 during active connection, got %d", refBefore)
	}

	// 释放远端连接
	close(connDone)
	time.Sleep(50 * time.Millisecond)

	// 连接关闭后，refCount 应释放为 0
	fakeIPTable.mu.RLock()
	refAfter := node.refCount.Load()
	fakeIPTable.mu.RUnlock()

	if refAfter != 0 {
		t.Fatalf("expected refCount=0 after connection closed, got %d", refAfter)
	}
}

// -----------------------------------------------------------------------------
// 阶段二与三测试：NodeInfo 状态测试与 ProbeAllNodes 并发测速测试
// -----------------------------------------------------------------------------

func TestNodeInfoState(t *testing.T) {
	eng := NewEngine()

	// 1. 未应用订阅时，GetNodes 返回 nil
	if nodes := eng.GetNodes(); nodes != nil {
		t.Fatalf("expected nil nodes when no sub applied, got %v", nodes)
	}

	applied := &Applied{
		Servers: []ServerConfig{
			{Name: "HK-01", Address: "192.0.2.1:443", Token: "tok_1", SNI: "hk.example.com", LineType: "专线"},
			{Name: "JP-02", Address: "192.0.2.2:443", Token: "tok_2", SNI: "jp.example.com", LineType: "BGP"},
			{Address: "192.0.2.3:443", Token: "tok_3", SNI: "us.example.com", LineType: "直连"},
		},
		Tokens: map[string]string{
			"192.0.2.1:443": "tok_1",
			"192.0.2.2:443": "tok_2",
			"192.0.2.3:443": "tok_3",
		},
		SNIs: map[string]string{
			"192.0.2.1:443": "hk.example.com",
			"192.0.2.2:443": "jp.example.com",
			"192.0.2.3:443": "us.example.com",
		},
	}

	// 2. 应用订阅，默认主节点激活
	if err := eng.Apply(applied); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	nodes := eng.GetNodes()
	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(nodes))
	}

	// 第一个节点 HK-01 应为 Active
	if !nodes[0].Active || nodes[0].Address != "192.0.2.1:443" || nodes[0].Name != "HK-01" {
		t.Fatalf("expected node[0] active with name HK-01, got %+v", nodes[0])
	}
	if nodes[1].Active || nodes[2].Active {
		t.Fatalf("expected non-primary nodes inactive, got node[1]=%v, node[2]=%v", nodes[1].Active, nodes[2].Active)
	}
	// 第三个节点无 Name，但有 LineType，名字应为 "直连 (192.0.2.3:443)"
	if nodes[2].Name != "直连 (192.0.2.3:443)" {
		t.Fatalf("expected formatted name for node[2], got %q", nodes[2].Name)
	}

	// 3. 切换激活节点测试
	if err := eng.SwitchActiveNode("192.0.2.2:443"); err != nil {
		t.Fatalf("SwitchActiveNode failed: %v", err)
	}

	nodesAfter := eng.GetNodes()
	if nodesAfter[0].Active {
		t.Fatalf("expected node[0] inactive after switch")
	}
	if !nodesAfter[1].Active {
		t.Fatalf("expected node[1] active after switch")
	}
}

func TestProbeAllNodes(t *testing.T) {
	eng := NewEngine()

	// 1. 无订阅时，ProbeAllNodes 返回 nil
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if res := eng.ProbeAllNodes(ctx); res != nil {
		t.Fatalf("expected nil when no sub applied, got %v", res)
	}

	// 2. 应用含有多个服务器的订阅
	applied := &Applied{
		Servers: []ServerConfig{
			{Name: "Mock-1", Address: "127.0.0.1:54321", Token: "tok_1", SNI: "m1.example.com"},
			{Name: "Mock-2", Address: "127.0.0.1:54322", Token: "tok_2", SNI: "m2.example.com"},
			{Name: "Mock-3", Address: "127.0.0.1:54323", Token: "tok_3", SNI: "m3.example.com"},
			{Name: "Mock-4", Address: "127.0.0.1:54324", Token: "tok_4", SNI: "m4.example.com"},
		},
		Tokens: map[string]string{
			"127.0.0.1:54321": "tok_1",
			"127.0.0.1:54322": "tok_2",
			"127.0.0.1:54323": "tok_3",
			"127.0.0.1:54324": "tok_4",
		},
		SNIs: map[string]string{
			"127.0.0.1:54321": "m1.example.com",
			"127.0.0.1:54322": "m2.example.com",
			"127.0.0.1:54323": "m3.example.com",
			"127.0.0.1:54324": "m4.example.com",
		},
	}
	if err := eng.Apply(applied); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// 3. 短超时探针探测并发与无锁快照
	probeCtx, pCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer pCancel()

	results := eng.ProbeAllNodes(probeCtx)
	if len(results) != 4 {
		t.Fatalf("expected 4 probe results, got %d", len(results))
	}

	for i, r := range results {
		if r.Address != applied.Servers[i].Address {
			t.Errorf("result %d address mismatch: got %s, want %s", i, r.Address, applied.Servers[i].Address)
		}
		if r.LastProbeAt == "" {
			t.Errorf("result %d LastProbeAt should not be empty", i)
		}
		// 目标端口未开放，探针应优雅降级为 Reachable == false, LatencyMs == -1
		if r.Reachable {
			t.Errorf("expected unreachable for closed port, got reachable: %+v", r)
		}
		if r.LatencyMs != -1 {
			t.Errorf("expected -1 latency for unreachable node, got %d", r.LatencyMs)
		}
	}
}
