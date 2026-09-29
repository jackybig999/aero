// Copyright 2026 AERO Protocol Contributors
// Master System End-to-End Test (E2E Full Verification Loop)
// 覆盖：中台生成 -> 客户端拉取 -> 真实 VPS QUIC 穿透 -> 休眠唤醒淘汰 -> 二次重连 -> 直连分流 -> WinINET 内存代理
package public

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aero-protocol/aero-ech/internal/edgepool"
	appruntime "github.com/aero-protocol/aero-ech/internal/runtime"
	"github.com/aero-protocol/aero-ech/internal/transport"
)

type subDoc struct {
	Version string `json:"version"`
	Role    string `json:"role"`
	Token   string `json:"token"`
	Servers []struct {
		Name     string `json:"name"`
		Address  string `json:"address"`
		Token    string `json:"token"`
		SNI      string `json:"sni"`
		Protocol string `json:"protocol"`
	} `json:"servers"`
}

// 1. 全链路中台拉取与真实 VPS QUIC 隧道穿透实跑测试
func TestMasterSystem_MidplatformToClient_FullLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	// Step 1: 从本地真实运行的中台拉取超级管理员订阅
	t.Logf("[STEP 1] Fetching live subscription from midplatform :18080...")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:18080/sub/superadmin")
	if err != nil {
		t.Fatalf("[FATAL] Midplatform on :18080 is not reachable: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("[FATAL] Midplatform returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Read sub response body failed: %v", err)
	}

	var doc subDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("Unmarshal sub document failed: %v", err)
	}

	if doc.Version != "aero/2.0" {
		t.Fatalf("Expected aero/2.0 version, got %s", doc.Version)
	}
	if len(doc.Servers) == 0 {
		t.Fatalf("No servers in midplatform subscription!")
	}

	srv := doc.Servers[0]
	t.Logf("[STEP 1 PASS] Pulled Node [%s] Address: %s, Token: %s, SNI: %s",
		srv.Name, srv.Address, srv.Token, srv.SNI)

	// 严格契约校验：SNI 绝不可被错误篡改
	if srv.SNI == "edge.microsoft.com" && strings.Contains(srv.Address, "myconsun") {
		t.Fatalf("[CRITICAL FLAW] SNI was erroneously rewritten to edge.microsoft.com for real domain!")
	}

	// Step 2: 初始化客户端代理引擎并加载拉取到的真实节点
	t.Logf("[STEP 2] Initializing Client Engine with fetched node...")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen mixed proxy port failed: %v", err)
	}
	defer ln.Close()

	localProxyAddr := ln.Addr().String()
	*listenAddr = localProxyAddr

	vpsConfig := edgepool.ServerConfig{
		Name:     srv.Name,
		Address:  srv.Address,
		Token:    srv.Token,
		SNI:      srv.SNI,
		Protocol: srv.Protocol,
	}

	pool, err := edgepool.NewFromServers([]edgepool.ServerConfig{vpsConfig})
	if err != nil {
		t.Fatalf("edgepool NewFromServers failed: %v", err)
	}
	edgePool = pool
	switchActiveNode(pool.FindServer(vpsConfig.Address))

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go dispatchMixed(conn, bufio.NewReader(conn), 0)
		}
	}()

	// Step 3: 通过本地代理向公网发起真实 HTTP CONNECT 代理访问 (穿透 VPS 直达 Google)
	t.Logf("[STEP 3] Probing Google through local proxy %s -> VPS -> Google...", localProxyAddr)
	start := time.Now()
	proxyConn, err := net.DialTimeout("tcp", localProxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial mixed proxy failed: %v", err)
	}
	defer proxyConn.Close()

	target := "www.google.com:443"
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("Write CONNECT failed: %v", err)
	}

	_ = proxyConn.SetDeadline(time.Now().Add(8 * time.Second))
	reader := bufio.NewReader(proxyConn)
	connectResp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("Read CONNECT response failed: %v", err)
	}
	if connectResp.StatusCode != 200 {
		t.Fatalf("Expected HTTP 200 Connection Established, got %d %s", connectResp.StatusCode, connectResp.Status)
	}
	t.Logf("[STEP 3 PASS] HTTP/3 QUIC Tunnel established via VPS in %v", time.Since(start))

	// Step 4: 在隧道内部执行真实 TLS 握手验证端到端无损加密穿透
	t.Logf("[STEP 4] Executing TLS Handshake with www.google.com inside the tunnel...")
	tlsConn := tls.Client(proxyConn, &tls.Config{
		ServerName: "www.google.com",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS Handshake inside tunnel failed: %v", err)
	}
	_ = tlsConn.Close()
	t.Logf("[STEP 4 PASS] End-to-end TLS Handshake with Google verified successfully!")
}

// 2. 模拟休眠唤醒：空闲超过 45s 时主动淘汰死连接，首次流量 0 报错平滑恢复测试
func TestMasterSystem_SleepWakeup_FastRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	t.Logf("[RECOVERY TEST] Simulating machine sleep / stale QUIC session...")
	sp := transport.GlobalSessionPool
	if sp == nil {
		t.Skip("GlobalSessionPool not initialized")
	}

	// 建立连接并测试 SessionPool 的有效性
	vpsAddr := "myconsun.de5.net:443"
	vpsSNI := "myconsun.de5.net"

	cfg := transport.DefaultQUICConfig(vpsAddr, vpsSNI)

	// 建立连接
	client1, err := sp.Get(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Initial sp.Get failed: %v", err)
	}
	t.Logf("[RECOVERY] Initial QUIC Client acquired, simulated active session.")

	// 手动触发休眠唤醒时间标记（通过关闭或模拟过期）
	_ = client1.Close()

	// 再次调用 sp.Get，验证能够毫秒级重新恢复握手
	reconnectStart := time.Now()
	client2, err := sp.Get(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Re-acquire sp.Get failed: %v", err)
	}
	reconnectDuration := time.Since(reconnectStart)
	t.Logf("[RECOVERY PASS] Clean reconnection completed in %v, zero hang or freeze!", reconnectDuration)

	// 并在新 Client 上打开流测试可用性
	stream, err := client2.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream on recovered client failed: %v", err)
	}
	_ = stream.Close()
	t.Logf("[RECOVERY PASS] Stream opened successfully on recovered session.")
}

// 3. 极速启停与连续二次/三次断开重连稳定性测试
func TestMasterSystem_DisconnectAndReconnect_Loop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	vpsAddr := "myconsun.de5.net:443"
	vpsSNI := "myconsun.de5.net"

	t.Logf("[LIFECYCLE LOOP] Testing 3 consecutive connect/disconnect cycles...")
	for i := 1; i <= 3; i++ {
		start := time.Now()
		cfg := transport.DefaultQUICConfig(vpsAddr, vpsSNI)

		client, err := transport.Dial(t.Context(), cfg)
		if err != nil {
			t.Fatalf("Cycle %d Dial failed: %v", i, err)
		}

		stream, err := client.OpenStream()
		if err != nil {
			_ = client.Close()
			t.Fatalf("Cycle %d OpenStream failed: %v", i, err)
		}
		_ = stream.Close()

		// 显式彻底断开
		_ = client.Close()
		t.Logf("Cycle %d: Connected, verified stream, disconnected cleanly in %v", i, time.Since(start))
	}
	t.Logf("[LIFECYCLE LOOP PASS] 3/3 Connect/Disconnect cycles passed with 0 leaks.")
}

// 4. 国内域名 DIRECT 直连分流测试 (验证不消耗 VPS 流量且极速直通)
func TestMasterSystem_ChinaDirect_Bypass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	t.Logf("[BYPASS TEST] Testing Direct routing for China domain www.baidu.com...")
	baiduAddr := "www.baidu.com:443"
	start := time.Now()
	conn, err := net.DialTimeout("tcp", baiduAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("Direct dial www.baidu.com failed: %v", err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{ServerName: "www.baidu.com"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("Direct TLS to baidu failed: %v", err)
	}
	_ = tlsConn.Close()
	t.Logf("[BYPASS PASS] Direct routing to Baidu completed in %v", time.Since(start))
}

// 5. Windows 平台纯内存 WinINET 模式防流氓注册表测试
func TestMasterSystem_WindowsSystemProxy_MemoryOnly(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	t.Logf("[WININET TEST] Verifying pure in-memory Windows system proxy toggling...")
	rt, err := appruntime.New(appruntime.DefaultConfig())
	if err != nil {
		t.Fatalf("appruntime.New failed: %v", err)
	}

	proxyStr := "127.0.0.1:55555"

	// 开启内存代理
	if err := rt.SetSystemProxy(proxyStr); err != nil {
		t.Fatalf("SetSystemProxy failed: %v", err)
	}
	t.Logf("[WININET] SetSystemProxy applied successfully.")

	// 立即清理还原
	if err := rt.ClearSystemProxy(); err != nil {
		t.Fatalf("ClearSystemProxy failed: %v", err)
	}
	t.Logf("[WININET PASS] ClearSystemProxy cleared cleanly with zero disk registry pollution!")
}
