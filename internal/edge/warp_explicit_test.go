package edge

import (
	"net"
	"testing"
)

// 回归：未配置 WARP 时，edge 曾把本机 127.0.0.1:40000 / 1080 上任意可连通的服务当作 WARP，
// 并让全部出站经由它（fail-closed）。WARP 只能显式配置（ADR-0006）。
func TestWarpExplicitNoAutoDetectionOfLocalPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:40000")
	if err != nil {
		t.Skipf("127.0.0.1:40000 unavailable on this host: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	srv, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", DataDir: t.TempDir(), Domain: "example.test", AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	if proxy, _, enabled, _ := srv.dialGuard.GetWarpStatus(); enabled {
		t.Fatalf("WARP enabled without configuration (proxy %s): an unrelated local service was taken over as egress", proxy)
	}
}

// 显式配置时按配置启用，warp_all 默认关闭（只走 AI 域名）。
func TestWarpExplicitConfiguredProxyIsUsed(t *testing.T) {
	srv, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", DataDir: t.TempDir(), Domain: "example.test", AllowSelfSignedCertForTest: true, WarpProxy: "127.0.0.1:40001"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	proxy, all, enabled, _ := srv.dialGuard.GetWarpStatus()
	if !enabled || proxy != "127.0.0.1:40001" || all {
		t.Fatalf("WARP status = (%s, all=%v, enabled=%v), want (127.0.0.1:40001, false, true)", proxy, all, enabled)
	}
}
