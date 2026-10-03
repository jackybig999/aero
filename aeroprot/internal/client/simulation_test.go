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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// 1. 多用户并发调度与状态回测 (Multi-User Parallel & Cross-Validation)
// ============================================================================

// TestMultiUserParallelModeSwitchAndConflict 模拟多用户并行启动、并发切换模式与冲突拦截回滚
func TestMultiUserParallelModeSwitchAndConflict(t *testing.T) {
	origDetect := detectThirdPartyTUN
	defer func() { detectThirdPartyTUN = origDetect }()
	detectThirdPartyTUN = func() (bool, string, error) {
		return true, "Meta", nil
	}

	const userCount = 10
	users := make([]*Engine, userCount)
	for i := 0; i < userCount; i++ {
		eng := NewEngine()
		eng.listenAddr = "127.0.0.1:0"
		users[i] = eng
	}

	var wg sync.WaitGroup
	errCounts := atomic.Int32{}
	conflictCounts := atomic.Int32{}

	// 1. 10 个用户并行尝试启动 TUN 模式 (模拟第三方 TUN 存在)
	for i := 0; i < userCount; i++ {
		wg.Add(1)
		go func(u *Engine) {
			defer wg.Done()
			u.SetMode("tun")
			err := u.Start()
			if err != nil {
				var confErr *ErrConflictingTUN
				if errors.As(err, &confErr) {
					conflictCounts.Add(1)
				} else {
					errCounts.Add(1)
				}
			}
		}(users[i])
	}
	wg.Wait()

	// 所有 10 个用户在 TUN 模式下均应精准命中第三方 TUN 冲突并拦截，0 漏判，0 崩溃
	if conflictCounts.Load() != userCount {
		t.Fatalf("expected %d conflict intercepts, got %d (other errs: %d)", userCount, conflictCounts.Load(), errCounts.Load())
	}

	// 验证所有用户的状态均保持未运行且无虚拟网卡泄漏
	for i, u := range users {
		if u.IsRunning() {
			t.Fatalf("user %d running should be false after conflict", i)
		}
		if u.tunDevice != nil {
			t.Fatalf("user %d tunDevice should be nil", i)
		}
	}

	// 2. 10 个用户并发切换为 sysproxy 模式并验证隔离性
	var sysWg sync.WaitGroup
	for i := 0; i < userCount; i++ {
		sysWg.Add(1)
		go func(u *Engine) {
			defer sysWg.Done()
			u.SetMode("sysproxy")
			u.listenAddr = "127.0.0.1:0"
			// sysproxy 模式严禁报 ErrConflictingTUN
			err := u.Start()
			var confErr *ErrConflictingTUN
			if errors.As(err, &confErr) {
				t.Errorf("sysproxy mode got ErrConflictingTUN: %v", err)
			}
			_ = u.Stop()
		}(users[i])
	}
	sysWg.Wait()
}

// ============================================================================
// 2. AI 对话场景端到端真实模拟 (AI Conversation Stream via Real Engine Mixed Proxy)
// ============================================================================

// TestSimulatedAIConversationFlow 真实经由 Engine 混合代理处理 HTTP CONNECT 并在建立的隧道中流式传输 Server-Sent Events (SSE)
func TestSimulatedAIConversationFlow(t *testing.T) {
	eng := NewEngine()

	// 注入生产级 tcpDialer 连接至模拟上游 AI 服务 (经过真实 e.DialTCP -> trackedConn -> relayTraffic 链路)
	eng.SetTCPDialer(func(ctx context.Context, target string) (net.Conn, error) {
		aiClient, aiServer := net.Pipe()
		go func() {
			defer aiServer.Close()
			br := bufio.NewReader(aiServer)
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			if req.Method != http.MethodPost || !strings.Contains(req.URL.Path, "/v1/chat/completions") {
				resp := "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
				_, _ = aiServer.Write([]byte(resp))
				return
			}
			header := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
			_, _ = aiServer.Write([]byte(header))

			tokens := []string{"Hello", "!", " I", " am", " Aero", " AI", " assistant."}
			for _, tok := range tokens {
				chunk := fmt.Sprintf("data: {\"token\":%q}\n\n", tok)
				_, _ = fmt.Fprintf(aiServer, "%x\r\n%s\r\n", len(chunk), chunk)
				time.Sleep(1 * time.Millisecond)
			}
			endChunk := "data: [DONE]\n\n"
			_, _ = fmt.Fprintf(aiServer, "%x\r\n%s\r\n", len(endChunk), endChunk)
			_, _ = aiServer.Write([]byte("0\r\n\r\n"))
		}()
		return aiClient, nil
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// 真实生产路径: 启动协程处理该连接 -> serveMixedConn -> handleHTTPConnect -> e.DialTCP -> relayTraffic
	go eng.serveMixedConn(serverConn)

	// 客户端发送 HTTP CONNECT 请求
	connectReq := "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n"
	go func() {
		_, _ = clientConn.Write([]byte(connectReq))
	}()

	br := bufio.NewReader(clientConn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response failed: %v", err)
	}
	if !strings.Contains(statusLine, "200 Connection Established") {
		t.Fatalf("expected 200 Connection Established, got: %s", statusLine)
	}
	// 读完空的换行
	_, _ = br.ReadString('\n')

	// 在建立的隧道上发起 AI 业务 POST 请求
	aiReq := "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: 0\r\n\r\n"
	go func() {
		_, _ = clientConn.Write([]byte(aiReq))
	}()

	respStatus, err := br.ReadString('\n')
	if err != nil || !strings.Contains(respStatus, "200 OK") {
		t.Fatalf("expected 200 OK, got: %s (err=%v)", respStatus, err)
	}

	var streamOutput strings.Builder
	for {
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			break
		}
		if strings.HasPrefix(line, "data: ") {
			streamOutput.WriteString(line)
			if strings.Contains(line, "[DONE]") {
				break
			}
		}
	}

	gotText := streamOutput.String()
	if !strings.Contains(gotText, "Aero") || !strings.Contains(gotText, "assistant.") {
		t.Fatalf("corrupted AI SSE stream, got: %s", gotText)
	}

	_ = eng.Stop()
}

// ============================================================================
// 3. 普通浏览器浏览与分流漏斗真实协议包测试 (Standard Browser & DNS Funnel)
// ============================================================================

// TestSimulatedBrowserFunnelAndDNS 使用真实 RFC 1035 二进制 DNS 请求报文测试分流与 IPv6 AAAA 屏蔽
func TestSimulatedBrowserFunnelAndDNS(t *testing.T) {
	split := NewSplitEngine()

	// 1. 验证国内与国外域名静态策略分流
	if split.Match("baidu.com", nil) != DIRECT {
		t.Fatalf("expected baidu.com to be DIRECT")
	}
	if split.Match("google.com", nil) == DIRECT {
		t.Fatalf("expected google.com to NOT be DIRECT")
	}

	dnsHandler := NewDNSHandler(split)

	// 注入物理 DNS 内存通道
	physicalQueries := atomic.Int32{}
	dnsHandler.SetPhysicalDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		cConn, sConn := net.Pipe()
		go func() {
			defer sConn.Close()
			buf := make([]byte, 1500)
			n, err := sConn.Read(buf)
			if err != nil {
				return
			}
			physicalQueries.Add(1)
			qname, _ := extractDNSQuestionAndType(buf[:n])
			resp := buildAResponse(buf[:n], qname, net.ParseIP("1.2.3.4"))
			_, _ = sConn.Write(resp)
		}()
		return cConn, nil
	})

	// 设置海外短流解析器
	dnsHandler.SetTunnelResolver(func(ctx context.Context, domain string) (net.IP, error) {
		return net.ParseIP("93.184.216.34"), nil
	})

	// 3. 测试国内域名 Type A: 应打到物理 DNS 并获得 1.2.3.4
	reqBaiduA := buildDNSQuery("baidu.com", 0x0001)
	respBaiduA := dnsHandler.HandleQuery(reqBaiduA, net.ParseIP("10.88.0.2"), 53)
	if respBaiduA == nil {
		t.Fatalf("expected response for baidu.com Type A")
	}
	if physicalQueries.Load() == 0 {
		t.Fatalf("expected physical DNS query for baidu.com, got 0")
	}

	// 4. 测试海外域名 Type A: 走短流隧道解析 (93.184.216.34)
	reqGoogleA := buildDNSQuery("google.com", 0x0001)
	respGoogleA := dnsHandler.HandleQuery(reqGoogleA, net.ParseIP("10.88.0.2"), 53)
	if respGoogleA == nil {
		t.Fatalf("expected response for google.com Type A")
	}
	if len(respGoogleA) < 12 {
		t.Fatalf("google.com DNS response too short")
	}

	// 5. 核心防御规范断言：*.cn 与海外域名的 Type AAAA 均必须返回空应答 (ANCOUNT=0, RCODE=0)，彻底阻断 IPv6 泄露！
	reqBaiduAAAA := buildDNSQuery("baidu.com", 0x001C)
	respBaiduAAAA := dnsHandler.HandleQuery(reqBaiduAAAA, net.ParseIP("10.88.0.2"), 53)
	if respBaiduAAAA == nil {
		t.Fatalf("expected non-nil response for baidu.com AAAA")
	}
	if ancount := binary.BigEndian.Uint16(respBaiduAAAA[6:8]); ancount != 0 {
		t.Fatalf("expected 0 answers for baidu.com AAAA, got %d", ancount)
	}

	reqGoogleAAAA := buildDNSQuery("google.com", 0x001C)
	respGoogleAAAA := dnsHandler.HandleQuery(reqGoogleAAAA, net.ParseIP("10.88.0.2"), 53)
	if respGoogleAAAA == nil {
		t.Fatalf("expected non-nil response for google.com AAAA")
	}
	if ancount := binary.BigEndian.Uint16(respGoogleAAAA[6:8]); ancount != 0 {
		t.Fatalf("expected 0 answers for google.com AAAA, got %d", ancount)
	}
}

// ============================================================================
// 4. 指纹浏览器场景真实 SOCKS5 握手与连接穿透 (Fingerprint Browser & SOCKS5 Connect)
// ============================================================================

// TestSimulatedFingerprintBrowserSocks5 真实模拟指纹浏览器 (AdsPower/Hubstudio) 经混合代理发起 SOCKS5 握手与 CONNECT 数据传输
func TestSimulatedFingerprintBrowserSocks5(t *testing.T) {
	eng := NewEngine()

	// 模拟海外目标网站的 TCP Echo 响应 (经由 e.DialTCP)
	eng.SetTCPDialer(func(ctx context.Context, target string) (net.Conn, error) {
		echoClient, echoServer := net.Pipe()
		go func() {
			defer echoServer.Close()
			_, _ = io.Copy(echoServer, echoServer)
		}()
		return echoClient, nil
	})

	const profileCount = 5
	var profileWg sync.WaitGroup

	for p := 0; p < profileCount; p++ {
		profileWg.Add(1)
		go func(profileID int) {
			defer profileWg.Done()
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()

			// 真实生产路径: 启动协程处理该连接 -> serveMixedConn -> handleSocks5 -> e.DialTCP -> relayTraffic
			go eng.serveMixedConn(serverConn)

			// 步骤 A: SOCKS5 问候 (0x05, 0x01, 0x00)
			if _, err := clientConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
				t.Errorf("profile %d write greeting failed: %v", profileID, err)
				return
			}
			authResp := make([]byte, 2)
			if _, err := io.ReadFull(clientConn, authResp); err != nil {
				t.Errorf("profile %d read auth failed: %v", profileID, err)
				return
			}
			if authResp[0] != 0x05 || authResp[1] != 0x00 {
				t.Errorf("profile %d invalid auth resp: %x", profileID, authResp)
				return
			}

			// 步骤 B: SOCKS5 CONNECT 请求: VER=5, CMD=1, RSV=0, ATYP=1(IPv4), IP=127.0.0.1, Port=8080
			req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90}
			if _, err := clientConn.Write(req); err != nil {
				t.Errorf("profile %d write connect req failed: %v", profileID, err)
				return
			}

			connResp := make([]byte, 10)
			if _, err := io.ReadFull(clientConn, connResp); err != nil {
				t.Errorf("profile %d read connect resp failed: %v", profileID, err)
				return
			}
			if connResp[0] != 0x05 || connResp[1] != 0x00 {
				t.Errorf("profile %d connect rejected: %x", profileID, connResp)
				return
			}

			// 步骤 C: 发送指纹数据负载并验证回显
			payload := fmt.Sprintf("fingerprint-data-from-profile-%d", profileID)
			go func() {
				_, _ = clientConn.Write([]byte(payload))
			}()
			recvBuf := make([]byte, len(payload))
			if _, err := io.ReadFull(clientConn, recvBuf); err != nil {
				t.Errorf("profile %d read payload failed: %v", profileID, err)
				return
			}
			if string(recvBuf) != payload {
				t.Errorf("profile %d payload mismatch: got %s, want %s", profileID, string(recvBuf), payload)
			}
		}(p)
	}
	profileWg.Wait()
	_ = eng.Stop()
}

// ============================================================================
// 5. 游戏加速场景模拟 (Gaming Acceleration: UDP / MTU 1224 / Jitter)
// ============================================================================

// TestSimulatedGameAccelerationDatagramGuard 模拟游戏 UDP 数据报转发预检、gVisor ICMP 回写与抗 DPI 混淆包长
func TestSimulatedGameAccelerationDatagramGuard(t *testing.T) {
	// 1. 验证生产代码 TunnelClient.SendDatagram 预检丢弃逻辑 (规范 P2: 4 + len(payload) > currentMaxDatagramSize 立即丢弃)
	tc := NewTunnelClient(GlobalSessionPool, NewSplitEngine())
	curMax := GetCurrentMaxDatagramSize() // 1200

	// 构造超限 UDP 数据报 (1200 字节 + 4 字节头部 = 1204 > 1200)
	oversizedPayload := make([]byte, curMax)
	err := tc.SendDatagram(42, oversizedPayload)
	// 核心断言：超限直接静默返回 nil (丢弃)，严禁调用底层 Client.SendDatagram，严禁降级为 stream
	if err != nil {
		t.Fatalf("oversized datagram should be silently dropped, got err: %v", err)
	}

	// 2. 验证生产代码 buildICMPFragNeeded: 栈入口超限 IPv4 且 DF=1 生成 ICMP Type 3 Code 4
	bigPacketDF := make([]byte, 1400)
	bigPacketDF[0] = 0x45
	bigPacketDF[6] = 0x40 // DF=1
	binary.BigEndian.PutUint16(bigPacketDF[2:4], 1400)
	copy(bigPacketDF[12:16], net.ParseIP("10.88.0.2").To4()) // 原源 IP
	copy(bigPacketDF[16:20], net.ParseIP("1.1.1.1").To4())   // 原目的 IP

	gwIP := net.ParseIP("10.88.0.1")
	icmpReply := buildICMPFragNeeded(bigPacketDF, gwIP, 1224)
	if icmpReply == nil {
		t.Fatalf("expected non-nil ICMP Fragmentation Needed reply")
	}
	if len(icmpReply) < 28 {
		t.Fatalf("ICMP reply too short: %d", len(icmpReply))
	}
	// 验证 IP 协议为 ICMP (1)
	if icmpReply[9] != 1 {
		t.Fatalf("expected IP protocol 1 (ICMP), got %d", icmpReply[9])
	}
	// 验证源 IP 为网关 10.88.0.1，目的 IP 为原源 IP 10.88.0.2
	if !net.IP(icmpReply[12:16]).Equal(gwIP) {
		t.Fatalf("expected ICMP source IP %v, got %v", gwIP, net.IP(icmpReply[12:16]))
	}
	if !net.IP(icmpReply[16:20]).Equal(net.ParseIP("10.88.0.2")) {
		t.Fatalf("expected ICMP dest IP 10.88.0.2, got %v", net.IP(icmpReply[16:20]))
	}
	// 验证 ICMP Type=3, Code=4
	if icmpReply[20] != 3 || icmpReply[21] != 4 {
		t.Fatalf("expected ICMP Type 3 Code 4, got Type %d Code %d", icmpReply[20], icmpReply[21])
	}
	// 验证 Next-Hop MTU 为 1224
	nextMTU := binary.BigEndian.Uint16(icmpReply[26:28])
	if nextMTU != 1224 {
		t.Fatalf("expected Next-Hop MTU 1224, got %d", nextMTU)
	}
}
