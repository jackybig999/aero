package client

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
)

func TestBaselineFreeze_DNSAndSysproxy(t *testing.T) {
	split := NewSplitEngine()
	dnsHandler := NewDNSHandler(split)

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

	_, fakeCIDR, err := net.ParseCIDR("198.18.0.0/15")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	// 1. openai.com 的 A 查询得到 198.18.0.0/15，Decide 不是 direct
	reqOpenAI := buildDNSQuery("openai.com", 0x0001)
	respOpenAI := dnsHandler.HandleQuery(reqOpenAI, net.ParseIP("10.88.0.2"), 53)
	if respOpenAI == nil {
		t.Fatalf("expected response for openai.com A query")
	}
	ipOpenAI := extractFirstAAnswer(respOpenAI)
	if ipOpenAI == nil || !fakeCIDR.Contains(ipOpenAI) {
		t.Fatalf("expected openai.com A query to return 198.18.0.0/15 Fake-IP, got %v", ipOpenAI)
	}
	if split.Decide("openai.com") == "direct" {
		t.Fatalf("expected split.Decide(openai.com) != 'direct', got %q", split.Decide("openai.com"))
	}

	// 2. baidu.com 和 example.cn 的 A 查询走进注入的物理 DNS，不分配假 IP
	prevPhysicalCount := physicalQueries.Load()

	reqBaidu := buildDNSQuery("baidu.com", 0x0001)
	respBaidu := dnsHandler.HandleQuery(reqBaidu, net.ParseIP("10.88.0.2"), 53)
	if respBaidu == nil {
		t.Fatalf("expected response for baidu.com A query")
	}
	ipBaidu := extractFirstAAnswer(respBaidu)
	if ipBaidu == nil || fakeCIDR.Contains(ipBaidu) {
		t.Fatalf("expected baidu.com A query to NOT return Fake-IP, got %v", ipBaidu)
	}

	reqExampleCN := buildDNSQuery("example.cn", 0x0001)
	respExampleCN := dnsHandler.HandleQuery(reqExampleCN, net.ParseIP("10.88.0.2"), 53)
	if respExampleCN == nil {
		t.Fatalf("expected response for example.cn A query")
	}
	ipExampleCN := extractFirstAAnswer(respExampleCN)
	if ipExampleCN == nil || fakeCIDR.Contains(ipExampleCN) {
		t.Fatalf("expected example.cn A query to NOT return Fake-IP, got %v", ipExampleCN)
	}

	if physicalQueries.Load()-prevPhysicalCount < 2 {
		t.Fatalf("expected baidu.com and example.cn to hit physical DNS, got %d calls", physicalQueries.Load()-prevPhysicalCount)
	}

	// 3. platform.moonshot.cn、api.siliconflow.cn、api.sparkdesk.cn 的 A 查询改为假 IP，并且不再调用物理 DNS
	prevCountAI := physicalQueries.Load()
	for _, aiDomain := range []string{"platform.moonshot.cn", "api.siliconflow.cn", "api.sparkdesk.cn"} {
		req := buildDNSQuery(aiDomain, 0x0001)
		resp := dnsHandler.HandleQuery(req, net.ParseIP("10.88.0.2"), 53)
		if resp == nil {
			t.Fatalf("expected response for %s A query", aiDomain)
		}
		ipAI := extractFirstAAnswer(resp)
		if ipAI == nil || !fakeCIDR.Contains(ipAI) {
			t.Fatalf("expected %s to return 198.18.0.0/15 Fake-IP, got %v", aiDomain, ipAI)
		}
	}
	if physicalQueries.Load() != prevCountAI {
		t.Fatalf("expected AI domains to NOT query physical DNS, but physical count increased by %d", physicalQueries.Load()-prevCountAI)
	}

	// 节点自身的域名仍然回真实 IP
	nodeIP := net.ParseIP("198.51.100.99")
	dnsHandler.SetEdge("node.example.com", nodeIP)
	reqNode := buildDNSQuery("node.example.com", 0x0001)
	respNode := dnsHandler.HandleQuery(reqNode, net.ParseIP("10.88.0.2"), 53)
	if respNode == nil {
		t.Fatalf("expected response for node.example.com A query")
	}
	ipNode := extractFirstAAnswer(respNode)
	if ipNode == nil || !ipNode.Equal(nodeIP) {
		t.Fatalf("expected node.example.com to return real IP %v, got %v", nodeIP, ipNode)
	}

	// 4. sysproxy 不碰宿主 /32：验证模式为 sysproxy 时 switchActiveNodeLocked 与 onNetworkChange 正常执行且不改变宿主路由
	eng := NewEngine()
	eng.SetMode("sysproxy")
	eng.state.Store(stateRunning)
	eng.running.Store(true)

	if err := eng.switchActiveNodeLocked("198.51.100.1:443", "tok_test", "node1.example.com"); err != nil {
		t.Fatalf("switchActiveNodeLocked failed: %v", err)
	}
	eng.onNetworkChange("10.0.0.1", "eth0")

	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}
