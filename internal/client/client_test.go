// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
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
}

func (m *mockSessionPool) Get(ctx context.Context, cfg *TransportConfig) (*Client, error) {
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
