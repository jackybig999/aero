// Copyright 2026 AERO Protocol Contributors
package mid

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveIPRegionAndASN(t *testing.T) {
	// Test IP known to have ASN
	region := ResolveIPRegion("1.1.1.1")
	if region == "" {
		t.Fatalf("expected non-empty region for 1.1.1.1")
	}
	t.Logf("1.1.1.1 resolved region: %s", region)
	// Check that it contains AS
	if !strings.Contains(region, "AS") {
		t.Errorf("expected region to contain AS, got: %s", region)
	}

	// Test fallback or local
	localRegion := ResolveIPRegion("127.0.0.1")
	t.Logf("127.0.0.1 resolved region: %s", localRegion)
	if localRegion == "" {
		t.Errorf("expected non-empty fallback region for 127.0.0.1")
	}
}

func TestNodeLifecycleSyncOnUninstall(t *testing.T) {
	nodeSvc := NewNodeService()
	n, err := nodeSvc.CreateNode("edge-test", "edge", "1.2.3.4", "aero-quic", 443, 500, false, 100, 99)
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}
	if n == nil {
		t.Fatalf("expected non-nil node")
	}

	// Verify node exists
	list, _ := nodeSvc.ListAll()
	if len(list) != 1 {
		t.Fatalf("expected 1 node, got %d", len(list))
	}

	// Simulate AERO Edge uninstall: DeleteMatching
	deleted, err := nodeSvc.DeleteMatching(99, "1.2.3.4")
	if err != nil {
		t.Fatalf("DeleteMatching failed: %v", err)
	}
	if len(deleted) != 1 {
		t.Errorf("expected 1 deleted node, got %d", len(deleted))
	}

	// Verify node is completely removed
	listAfter, _ := nodeSvc.ListAll()
	if len(listAfter) != 0 {
		t.Errorf("expected 0 nodes after uninstall, got %d", len(listAfter))
	}
	availAfter, _ := nodeSvc.ListAvailable()
	if len(availAfter) != 0 {
		t.Errorf("expected 0 available nodes after uninstall, got %d", len(availAfter))
	}
}

func TestAdminUnrestrictedSubscription(t *testing.T) {
	uDB := NewMemoryUserStore()
	subBuilder := NewSubBuilder(uDB, nil, nil, nil)

	mux := http.NewServeMux()
	subBuilder.RegisterRoutes(mux)

	// 1. Test /sub/superadmin
	reqSuper := httptest.NewRequest("GET", "/sub/superadmin", nil)
	wSuper := httptest.NewRecorder()
	mux.ServeHTTP(wSuper, reqSuper)
	if wSuper.Code != http.StatusOK {
		t.Fatalf("expected status 200 for /sub/superadmin, got %d", wSuper.Code)
	}

	// 2. Test /sub/admin for staff user
	adminUser := &User{
		ID:       1,
		Username: "admin",
		SubSlug:  "superadmin",
		SubToken: "token-admin",
		Status:   true,
		IsStaff:  true,
	}
	_, _ = uDB.CreateUser(adminUser)

	reqAdmin := httptest.NewRequest("GET", "/sub/admin", nil)
	wAdmin := httptest.NewRecorder()
	mux.ServeHTTP(wAdmin, reqAdmin)
	if wAdmin.Code != http.StatusOK {
		t.Fatalf("expected status 200 for /sub/admin, got %d", wAdmin.Code)
	}
}

func TestEvaluatePurity_CNMarkedAndGeminiBlocked(t *testing.T) {
	// 场景 1: IP 被标记为中国 (送中)，Gemini 返回 403 阻断
	rawOut := "YT:CN,GEMINI:403,G:200,CF:200,AI:403,WARPINST:0,WARPPORT:0,WARPTRACE:0,WARP:0"
	res := EvaluatePurity(rawOut, 101)

	if !res.IsCNMarked {
		t.Errorf("expected IsCNMarked=true, got false")
	}
	if !res.AIBlocked {
		t.Errorf("expected AIBlocked=true, got false")
	}
	if res.GeminiOK {
		t.Errorf("expected GeminiOK=false, got true")
	}
	if res.YouTubeLoc != "CN" {
		t.Errorf("expected YouTubeLoc=CN, got %s", res.YouTubeLoc)
	}
	if res.WARPInstalled {
		t.Errorf("expected WARPInstalled=false, got true")
	}
	if res.WARPRunning {
		t.Errorf("expected WARPRunning=false, got true")
	}
}

func TestEvaluatePurity_WARPActiveEgress(t *testing.T) {
	// 场景 2: 已配置并激活官方 WARP 40000 端口，Gemini 解锁且源 IP 保护生效
	rawOut := "YT:US,GEMINI:200,G:200,CF:200,AI:200,WARPINST:1,WARPPORT:1,WARPTRACE:1,WARP:1"
	res := EvaluatePurity(rawOut, 102)

	if res.IsCNMarked {
		t.Errorf("expected IsCNMarked=false, got true")
	}
	if res.AIBlocked {
		t.Errorf("expected AIBlocked=false, got true")
	}
	if !res.GeminiOK {
		t.Errorf("expected GeminiOK=true, got false")
	}
	if res.YouTubeLoc != "US" {
		t.Errorf("expected YouTubeLoc=US, got %s", res.YouTubeLoc)
	}
	if !res.WARPInstalled {
		t.Errorf("expected WARPInstalled=true, got false")
	}
	if !res.WARPRunning {
		t.Errorf("expected WARPRunning=true, got false")
	}
	if !res.IsWARPEgress {
		t.Errorf("expected IsWARPEgress=true, got false")
	}
	if res.PurityScore < 95 {
		t.Errorf("expected PurityScore >= 95, got %d", res.PurityScore)
	}
}

func TestDefaultWarpInstallSteps(t *testing.T) {
	steps := DefaultWarpInstallSteps()
	if len(steps) != 5 {
		t.Fatalf("expected 5 steps, got %d", len(steps))
	}
	expectedKeys := []string{"warp_detect", "warp_install", "warp_config", "firewall_ufw", "verify_unblock"}
	for i, key := range expectedKeys {
		if steps[i].Key != key {
			t.Errorf("step %d expected key %s, got %s", i, key, steps[i].Key)
		}
	}
}
