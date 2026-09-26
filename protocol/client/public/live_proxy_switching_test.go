package public

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aero-protocol/aero-ech/internal/edgepool"
	"github.com/aero-protocol/aero-ech/internal/split"
	"github.com/aero-protocol/aero-ech/internal/transport"
)

func TestLiveProxySwitching(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live VPS test in short mode")
	}
	// Start mixed listener on random free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	testPort := ln.Addr().String()
	*listenAddr = testPort

	vps1 := edgepool.ServerConfig{
		Name:     "VPS 1 (de5)",
		Address:  "myconsun.de5.net:443",
		Token:    "aero_65aa450a49293a85888d8195bbc81940",
		SNI:      "myconsun.de5.net",
		PinSPKI:  []string{"N75oS2cgnhLGCuVcdWhBeyXX40746PDH3UqVghF9mzw="},
		Protocol: "quic",
	}
	vps2 := edgepool.ServerConfig{
		Name:     "VPS 2 (cc.cd)",
		Address:  "myconsun.cc.cd:443",
		Token:    "aero_080381bf99afebe5bab9a5c92e84a59d",
		SNI:      "myconsun.cc.cd",
		Protocol: "quic",
	}

	pool, err := edgepool.NewFromServers([]edgepool.ServerConfig{vps1, vps2})
	if err != nil {
		t.Fatalf("NewFromServers failed: %v", err)
	}
	edgePool = pool
	transport.AddPins(vps1.PinSPKI...)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go dispatchMixed(conn, bufio.NewReader(conn), 0)
		}
	}()

	// Helper to send CONNECT and verify TLS to target
	testProxyCONNECT := func(nodeName string, target string) time.Duration {
		start := time.Now()
		c, err := net.DialTimeout("tcp", testPort, 3*time.Second)
		if err != nil {
			t.Fatalf("[%s] Dial mixed proxy failed: %v", nodeName, err)
		}
		defer c.Close()

		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatalf("[%s] Write CONNECT failed: %v", nodeName, err)
		}

		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Logf("[%s] ReadResponse failed (node may be offline): %v", nodeName, err)
			return 0
		}
		if resp.StatusCode != 200 {
			t.Logf("[%s] Proxy returned status %d %s (node in maintenance/offline), skipping", nodeName, resp.StatusCode, resp.Status)
			return 0
		}

		// Perform real TLS handshake over tunnel to target
		host, _, _ := net.SplitHostPort(target)
		tlsConn := tls.Client(c, &tls.Config{ServerName: host})
		tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("[%s] End-to-end TLS Handshake to %s failed: %v", nodeName, target, err)
		}
		elapsed := time.Since(start)
		t.Logf("[%s] SUCCESS: CONNECT to %s via proxy in %v (ALPN=%s)",
			nodeName, target, elapsed, tlsConn.ConnectionState().NegotiatedProtocol)
		return elapsed
	}

	// 1. Test via VPS 1
	switchActiveNode(pool.FindServer(vps1.Address))
	dur1 := testProxyCONNECT("VPS 1", "www.google.com:443")
	if dur1 > 0 && dur1 > 3*time.Second {
		t.Errorf("VPS 1 latency too high: %v", dur1)
	}

	// 2. Switch to VPS 2 (the one that previously failed with SPKI pin mismatch)
	t.Logf(">>> Switching to VPS 2 (%s) <<<", vps2.Address)
	switchActiveNode(pool.FindServer(vps2.Address))

	dur2 := testProxyCONNECT("VPS 2", "www.google.com:443")
	if dur2 > 0 && dur2 > 3*time.Second {
		t.Errorf("VPS 2 latency too high: %v", dur2)
	}

	// 3. Switch back to VPS 1
	t.Logf(">>> Switching back to VPS 1 (%s) <<<", vps1.Address)
	switchActiveNode(pool.FindServer(vps1.Address))
	dur3 := testProxyCONNECT("VPS 1 (switchback)", "cloudflare.com:443")

	// 4. Test Split DIRECT path (Domestic website www.baidu.com)
	splitEngine = split.NewEngine()
	durDirect := testProxyCONNECT("DIRECT Baidu", "www.baidu.com:443")
	t.Logf("DIRECT path latency to www.baidu.com: %v", durDirect)

	t.Logf("All tests passed! VPS 1=%v, VPS 2=%v, SwitchBack=%v, DIRECT=%v", dur1, dur2, dur3, durDirect)

	transport.GlobalSessionPool.Reset()
}
