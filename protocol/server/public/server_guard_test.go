package public_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aero-protocol/aero-edge/public"
)

func TestAuthGuard_SSRFInterception(t *testing.T) {
	guard := public.NewAuthGuard(10)

	// 1. 本地回环与内网私有地址：必须硬编码拦截
	blockedTargets := []string{
		"127.0.0.1:80",
		"127.0.0.5:443",
		"localhost:8080",
		"192.168.1.1:80",
		"10.0.0.1:22",
		"172.16.0.1:3306",
		"169.254.169.254:80", // 云厂商元数据服务硬阻断
		"[::1]:80",
	}

	for _, target := range blockedTargets {
		err := guard.CheckSSRF(target)
		if err == nil {
			t.Fatalf("expected SSRF error for %s, got nil", target)
		}
	}

	// 2. 公网合法地址：正常放行
	allowedTargets := []string{
		"1.1.1.1:443",
		"8.8.8.8:53",
	}

	for _, target := range allowedTargets {
		err := guard.CheckSSRF(target)
		if err != nil {
			t.Fatalf("expected allowed for %s, got error: %v", target, err)
		}
	}
}

func TestAuthGuard_ConcurrencySlot(t *testing.T) {
	guard := public.NewAuthGuard(2) // 限制单 Token 最多 2 个并发流
	token := "tok_vip_test"

	if !guard.AcquireSlot(token) {
		t.Fatalf("acquire slot 1 should succeed")
	}
	if !guard.AcquireSlot(token) {
		t.Fatalf("acquire slot 2 should succeed")
	}
	if guard.AcquireSlot(token) {
		t.Fatalf("acquire slot 3 should be rejected due to quota")
	}

	if guard.ActiveSlots(token) != 2 {
		t.Fatalf("expected 2 active slots, got %d", guard.ActiveSlots(token))
	}

	guard.ReleaseSlot(token)
	if guard.ActiveSlots(token) != 1 {
		t.Fatalf("expected 1 active slot after release, got %d", guard.ActiveSlots(token))
	}

	if !guard.AcquireSlot(token) {
		t.Fatalf("acquire slot should succeed after release")
	}
}

func TestServerMetrics_127Isolation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	srv, err := public.StartMetricsServer(port)
	if err != nil {
		t.Fatalf("StartMetricsServer failed: %v", err)
	}
	defer srv.Stop()
	time.Sleep(50 * time.Millisecond)

	// 本地 127.0.0.1 访问
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for /metrics, got %d", resp.StatusCode)
	}
}

func TestMASQUEHandler_SSRFBlocked(t *testing.T) {
	guard := public.NewAuthGuard(10)
	metrics := public.GetGlobalMetrics()
	initialSSRF := metrics.SSRFBlocks.Value()

	handler := public.NewMASQUEHandler(guard, metrics)

	// 发起指向 AWS 元数据地址的恶意 CONNECT 请求
	req := httptest.NewRequest(http.MethodConnect, "http://169.254.169.254:80", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for SSRF attempt, got %d", rec.Code)
	}
	if metrics.SSRFBlocks.Value() <= initialSSRF {
		t.Fatalf("expected SSRFBlocks metric to increment")
	}
}
