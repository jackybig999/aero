// Copyright 2026 AERO Protocol Contributors
package sub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// 回归：/sub/superadmin 与 /sub/{管理员用户名} 曾无鉴权返回全节点管理员订阅。
// 管理员只能通过自身随机 slug 取订阅，且该订阅不限期、标记 unrestricted。
func TestSubAdminOnlyViaOwnSlug(t *testing.T) {
	uDB := NewMemoryUserStore()
	adminSlug := "admin" + GenerateUserToken()
	if _, err := uDB.CreateUser(&User{ID: 1, Username: "admin", SubSlug: adminSlug, SubToken: "token-admin", Status: true, IsStaff: true}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	NewSubBuilder(uDB, nil, nil, nil).RegisterRoutes(mux)

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	for _, path := range []string{"/sub/superadmin", "/sub/admin"} {
		if rec := get(path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
	rec := get("/sub/" + adminSlug)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET own admin slug = %d, want 200", rec.Code)
	}
	var doc struct {
		Unrestricted bool   `json:"unrestricted"`
		SubURL       string `json:"sub_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Unrestricted {
		t.Error("admin subscription is not marked unrestricted")
	}
	if doc.SubURL != "" && !strings.HasSuffix(doc.SubURL, "/sub/"+adminSlug) {
		t.Errorf("sub_url %q does not use the admin's own slug", doc.SubURL)
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
