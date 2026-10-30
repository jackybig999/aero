// Copyright 2026 AERO Protocol Contributors
package mid

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
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
	rawOut := "RAW_YT:CN,RAW_GEMINI:403,RAW_G:200,RAW_CF:200,AI:403,WARP_CLI:0,WARP_PORT:0,WARP_TRACE:0,WARP_GEMINI:000"
	res := EvaluatePurity(rawOut, 101, "US")

	if !res.IsCNMarked {
		t.Errorf("expected IsCNMarked=true, got false")
	}
	if !res.AIBlocked {
		t.Errorf("expected AIBlocked=true, got false")
	}
	if res.NativeGeminiOK {
		t.Errorf("expected NativeGeminiOK=false, got true")
	}
	if res.GeminiOK {
		t.Errorf("expected GeminiOK=false, got true")
	}
	if res.YouTubeLoc != "CN" {
		t.Errorf("expected YouTubeLoc=CN, got %s", res.YouTubeLoc)
	}
	if !res.IsRegionMismatched {
		t.Errorf("expected IsRegionMismatched=true (CN != US), got false")
	}
	if res.WARPInstalled {
		t.Errorf("expected WARPInstalled=false, got true")
	}
	if res.WARPRunning {
		t.Errorf("expected WARPRunning=false, got true")
	}
}

func TestEvaluatePurity_CNMarked_WithWARPRescue(t *testing.T) {
	// 场景 2: 源 IP 送中且原生 Gemini 阻断，但已安装 WARP 并激活 40000 端口救援解锁
	rawOut := "RAW_YT:CN,RAW_GEMINI:403,RAW_G:200,RAW_CF:200,WARP_CLI:1,WARP_PORT:1,WARP_TRACE:1,WARP_GEMINI:200"
	res := EvaluatePurity(rawOut, 102, "US")

	// 核心铁律：WARP 救援不能抹杀源 IP 的送中与地区漂移事实！
	if !res.IsCNMarked {
		t.Errorf("expected IsCNMarked=true (native defect must NOT be masked by WARP), got false")
	}
	if res.NativeGeminiOK {
		t.Errorf("expected NativeGeminiOK=false, got true")
	}
	if !res.IsRegionMismatched {
		t.Errorf("expected IsRegionMismatched=true, got false")
	}

	// 独立救援层状态：WARP 正常运行并成功解锁 Gemini
	if !res.WARPInstalled {
		t.Errorf("expected WARPInstalled=true, got false")
	}
	if !res.WARPRunning {
		t.Errorf("expected WARPRunning=true, got false")
	}
	if !res.WARPGeminiOK {
		t.Errorf("expected WARPGeminiOK=true, got false")
	}
	if !res.GeminiOK {
		t.Errorf("expected overall GeminiOK=true (via WARP rescue), got false")
	}
}

func TestEvaluatePurity_RegionMismatch(t *testing.T) {
	// 场景 3: 物理 IP 为 US，但油管识别为 HK（地区漂移）
	rawOut := "RAW_YT:HK,RAW_GEMINI:200,RAW_G:200,RAW_CF:200,WARP_CLI:0,WARP_PORT:0,WARP_TRACE:0,WARP_GEMINI:000"
	res := EvaluatePurity(rawOut, 103, "US")

	if !res.IsRegionMismatched {
		t.Errorf("expected IsRegionMismatched=true for HK vs US, got false")
	}
	if res.YouTubeLoc != "HK" {
		t.Errorf("expected YouTubeLoc=HK, got %s", res.YouTubeLoc)
	}
	if res.IPCountry != "US" {
		t.Errorf("expected IPCountry=US, got %s", res.IPCountry)
	}
	if !res.NativeGeminiOK {
		t.Errorf("expected NativeGeminiOK=true, got false")
	}
}

func TestEvaluatePurity_WARPActiveEgress(t *testing.T) {
	// 场景 4: 原生 IP 纯净且已配置并激活官方 WARP 40000 端口
	rawOut := "RAW_YT:US,RAW_GEMINI:200,RAW_G:200,RAW_CF:200,WARP_CLI:1,WARP_PORT:1,WARP_TRACE:1,WARP_GEMINI:200"
	res := EvaluatePurity(rawOut, 104, "US")

	if res.IsCNMarked {
		t.Errorf("expected IsCNMarked=false, got true")
	}
	if res.IsRegionMismatched {
		t.Errorf("expected IsRegionMismatched=false, got true")
	}
	if !res.NativeGeminiOK {
		t.Errorf("expected NativeGeminiOK=true, got false")
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

func TestEvaluatePurity_DeepInspection_VPS13_CHNMarked(t *testing.T) {
	// 场景 5: VPS 13 实机场景：YouTube 包含 www.google.cn, Gemini 识别 CHN, Google 搜索 302 重定向到香港
	// 同时 WARP 40000 活跃且 WARP 出口 Gemini 识别为 USA
	rawOut := "RAW_YT:CN,YT_CN:1,RAW_GEM_CC:CHN,G_HK:1,RAW_G:302,RAW_CF:200,WARP_CLI:1,WARP_PORT:1,WARP_TRACE:1,WARP_GEM_CC:USA"
	res := EvaluatePurity(rawOut, 13, "US")

	if !res.IsCNMarked {
		t.Errorf("expected IsCNMarked=true for VPS 13 (CHN, google.cn, g_hk), got false")
	}
	if res.NativeGeminiOK {
		t.Errorf("expected NativeGeminiOK=false (CHN blocked), got true")
	}
	if res.YouTubeLoc != "CN" {
		t.Errorf("expected YouTubeLoc=CN, got %s", res.YouTubeLoc)
	}
	if !res.IsRegionMismatched {
		t.Errorf("expected IsRegionMismatched=true (CN != US), got false")
	}
	if !res.WARPRunning {
		t.Errorf("expected WARPRunning=true, got false")
	}
	if !res.WARPGeminiOK {
		t.Errorf("expected WARPGeminiOK=true (via USA warp egress), got false")
	}
	if !res.GeminiOK {
		t.Errorf("expected overall GeminiOK=true (unblocked by WARP), got false")
	}
}

func TestEvaluatePurity_DeepInspection_VPS8_Clean(t *testing.T) {
	// 场景 6: VPS 8 (192...) 实机场景：原生干净，未包含 google.cn，未重定向，Gemini 识别 USA
	rawOut := "RAW_YT:US,YT_CN:0,RAW_GEM_CC:USA,G_HK:0,RAW_G:200,RAW_CF:200,WARP_CLI:0,WARP_PORT:0,WARP_TRACE:0,WARP_GEM_CC:"
	res := EvaluatePurity(rawOut, 8, "US")

	if res.IsCNMarked {
		t.Errorf("expected IsCNMarked=false for clean VPS 8, got true")
	}
	if !res.NativeGeminiOK {
		t.Errorf("expected NativeGeminiOK=true, got false")
	}
	if res.IsRegionMismatched {
		t.Errorf("expected IsRegionMismatched=false, got true")
	}
	if res.YouTubeLoc != "US" {
		t.Errorf("expected YouTubeLoc=US, got %s", res.YouTubeLoc)
	}
	if res.WARPRunning {
		t.Errorf("expected WARPRunning=false, got true")
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

func TestDiagCache_Concurrency(t *testing.T) {
	vpsID := uint64(9999)
	InvalidateDiagCache(vpsID)

	baseDiag := map[string]any{
		"domain": "test.aero",
		"online": true,
		"nodes":  []any{"node1", "node2"},
	}
	diagCacheMu.Lock()
	diagCache[vpsID] = diagCacheEntry{
		diag:      cloneDiagMap(baseDiag),
		createdAt: time.Now(),
	}
	diagCacheMu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			diagCacheMu.RLock()
			cached, ok := diagCache[vpsID]
			var res map[string]any
			if ok && time.Since(cached.createdAt) < 3*time.Second {
				res = cloneDiagMap(cached.diag)
			}
			diagCacheMu.RUnlock()

			if res != nil {
				res["purity"] = map[string]any{"worker": workerID}
				if res["domain"] != "test.aero" {
					t.Errorf("expected domain test.aero, got %v", res["domain"])
				}
			}
		}(i)
	}
	wg.Wait()
	InvalidateDiagCache(vpsID)
}

func TestDiag_StatusParsingAndWireContract(t *testing.T) {
	// 1. 测试 parseKV 对含 JSON 报文的正确解析能力（单行 JSON）
	rawOutput := "SERVICE=active\nMAIN_PID=2167517\nPORT_2083=yes\nPORT_2083_PROC=aero-edge\nPORT_443=yes\nPORT_443_PROC=xray-linux-amd6\nEDGE_STATUS={\"ok\":true,\"version\":\"1.2.16\",\"uptime_sec\":1234.5}\n"
	kv := parseKV(rawOutput)
	if kv["SERVICE"] != "active" {
		t.Fatalf("expected SERVICE=active, got %s", kv["SERVICE"])
	}
	if kv["MAIN_PID"] != "2167517" {
		t.Fatalf("expected MAIN_PID=2167517, got %s", kv["MAIN_PID"])
	}
	if kv["PORT_2083_PROC"] != "aero-edge" {
		t.Fatalf("expected PORT_2083_PROC=aero-edge, got %s", kv["PORT_2083_PROC"])
	}
	if kv["EDGE_STATUS"] == "" {
		t.Fatalf("expected EDGE_STATUS not empty")
	}

	var edgeStatus map[string]any
	if err := json.Unmarshal([]byte(kv["EDGE_STATUS"]), &edgeStatus); err != nil {
		t.Fatalf("unmarshal EDGE_STATUS failed: %v", err)
	}
	if edgeStatus["version"] != "1.2.16" || edgeStatus["ok"] != true {
		t.Fatalf("unexpected edgeStatus payload: %+v", edgeStatus)
	}

	// 2. 验证正则匹配：严防 inactive 中包含 active 子串造成的致命误判
	testLines := []string{"inactive", "active", "unknown"}
	activeRegex := regexp.MustCompile(`^(active|activating)$`)
	matchedCount := 0
	for _, l := range testLines {
		if activeRegex.MatchString(l) {
			matchedCount++
			if l != "active" {
				t.Fatalf("regex matched non-active line: %s", l)
			}
		}
	}
	if matchedCount != 1 {
		t.Fatalf("expected exactly 1 match for active, got %d", matchedCount)
	}
}
