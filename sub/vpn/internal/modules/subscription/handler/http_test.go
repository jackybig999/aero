package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	subHandler "github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/handler"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/subscription/snimatrix"
	userD "github.com/vpn-platform/vpsserver/vpn/internal/modules/user/domain"
	userStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/user/store"
	aeroEndpoint "github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/endpoint"
	vpsD "github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
	vpsStore "github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/store"
)

func setupTestSubHandler(t *testing.T) (*subHandler.Handler, userStore.Store, *aeroEndpoint.Persist, vpsStore.Store, *userD.User) {
	t.Helper()

	uStore := userStore.NewMemoryStore()
	now := time.Now()
	user := &userD.User{
		Username:  "ai_dev",
		SubSlug:   "aidev888888",
		SubToken:  "tok_test_123",
		Status:    true,
		ExpireAt:  now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}
	_, err := uStore.CreateUser(user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	epFile := filepath.Join(t.TempDir(), "endpoints.json")
	epPersist, err := aeroEndpoint.NewPersist(epFile)
	if err != nil {
		t.Fatalf("failed to create epPersist: %v", err)
	}

	vStore := vpsStore.NewMemoryStore()
	sniMgr := snimatrix.New("")

	h := subHandler.NewWithStores(nil, uStore, epPersist, sniMgr)
	h.SetVPSStore(vStore)

	return h, uStore, epPersist, vStore, user
}

func TestServeSub_PurposeAI_Routing(t *testing.T) {
	h, _, epStore, vStore, user := setupTestSubHandler(t)

	// VPS 1: Tier 1 纯净节点 (Purity 95, AI clean, not WARP)
	v1ID, _ := vStore.Create(&vpsD.VPSHost{IP: "1.1.1.1", SSHPort: 22, Name: "VPS-US-Clean"}, "")
	_ = vStore.UpdatePurity(v1ID, 95, false, true, true, false)
	epStore.Upsert(aeroEndpoint.Info{
		VPSID: v1ID, Name: "US-Clean", Host: "us-clean.example.com", Port: 443, Installed: true,
	})

	// VPS 2: Dirty 节点 (AI 封控 403, Purity 40)
	v2ID, _ := vStore.Create(&vpsD.VPSHost{IP: "2.2.2.2", SSHPort: 22, Name: "VPS-JP-Dirty"}, "")
	_ = vStore.UpdatePurity(v2ID, 40, true, false, true, false)
	epStore.Upsert(aeroEndpoint.Info{
		VPSID: v2ID, Name: "JP-Dirty", Host: "jp-dirty.example.com", Port: 443, Installed: true,
	})

	// VPS 3: WARP 出口节点 (虽然 100 分但不是 Tier 1 纯净源站)
	v3ID, _ := vStore.Create(&vpsD.VPSHost{IP: "3.3.3.3", SSHPort: 22, Name: "VPS-WARP"}, "")
	_ = vStore.UpdatePurity(v3ID, 100, false, true, true, true)
	epStore.Upsert(aeroEndpoint.Info{
		VPSID: v3ID, Name: "WARP-Egress", Host: "warp.example.com", Port: 443, Installed: true,
	})

	// 1. 常规请求：应下发全部 3 个可用节点
	{
		req := httptest.NewRequest("GET", "/sub/"+user.SubSlug, nil)
		rec := httptest.NewRecorder()
		h.ServeSub(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("json unmarshal failed: %v", err)
		}
		servers := resp["servers"].([]any)
		if len(servers) != 3 {
			t.Fatalf("expected 3 servers in default sub, got %d", len(servers))
		}
	}

	// 2. AI 专线请求 (?purpose=ai)：必须严格仅下发 Tier 1 纯净节点 (仅 VPS 1)
	{
		req := httptest.NewRequest("GET", "/sub/"+user.SubSlug+"?purpose=ai", nil)
		rec := httptest.NewRecorder()
		h.ServeSub(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("json unmarshal failed: %v", err)
		}
		servers := resp["servers"].([]any)
		if len(servers) != 1 {
			t.Fatalf("expected exactly 1 Tier 1 server for AI purpose, got %d", len(servers))
		}
		cleanServer := servers[0].(map[string]any)
		if cleanServer["address"] != "us-clean.example.com:443" {
			t.Fatalf("expected us-clean.example.com:443, got %v", cleanServer["address"])
		}
		if cleanServer["aiBlocked"] != false {
			t.Fatalf("expected aiBlocked=false, got %v", cleanServer["aiBlocked"])
		}
	}
}

func TestServeSub_PurposeAI_Exhausted_CircuitBreak(t *testing.T) {
	h, _, epStore, vStore, user := setupTestSubHandler(t)

	// 仅配置一个被 AI 阻断的 Dirty 节点
	vDirtyID, _ := vStore.Create(&vpsD.VPSHost{IP: "4.4.4.4", SSHPort: 22, Name: "VPS-Dirty"}, "")
	_ = vStore.UpdatePurity(vDirtyID, 40, true, false, true, false)
	epStore.Upsert(aeroEndpoint.Info{
		VPSID: vDirtyID, Name: "Dirty-Node", Host: "dirty.example.com", Port: 443, Installed: true,
	})

	// 1. 无 allow_degrade 时，应熔断并返回 503 Service Unavailable 与 Retry-After: 120
	{
		req := httptest.NewRequest("GET", "/sub/"+user.SubSlug+"?purpose=ai", nil)
		rec := httptest.NewRecorder()
		h.ServeSub(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 Service Unavailable, got %d", rec.Code)
		}
		retryAfter := rec.Header().Get("Retry-After")
		if retryAfter != "120" {
			t.Fatalf("expected Retry-After: 120, got %s", retryAfter)
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["error"] != "TIER1_AI_NODES_EXHAUSTED" {
			t.Fatalf("expected error TIER1_AI_NODES_EXHAUSTED, got %v", resp["error"])
		}
	}

	// 2. 携带 allow_degrade=true 时，允许降级并注入 riskWarning
	{
		req := httptest.NewRequest("GET", "/sub/"+user.SubSlug+"?purpose=ai&allow_degrade=true", nil)
		rec := httptest.NewRecorder()
		h.ServeSub(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on degrade, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["riskWarning"] != "dirty_ip_degraded" {
			t.Fatalf("expected riskWarning dirty_ip_degraded, got %v", resp["riskWarning"])
		}
		servers := resp["servers"].([]any)
		if len(servers) != 1 {
			t.Fatalf("expected 1 degraded server, got %d", len(servers))
		}
	}
}
