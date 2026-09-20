package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/secret"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/service"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/store"
)

func setupTestHandler(t *testing.T) (*Handler, store.Store, *http.ServeMux) {
	t.Helper()
	st := store.NewMemoryStore()
	box, err := secret.NewBox()
	if err != nil {
		t.Fatalf("secret.NewBox failed: %v", err)
	}
	svc := service.New(st, box)
	h := New(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return h, st, mux
}

func TestHandler_InvalidID_Returns422(t *testing.T) {
	_, _, mux := setupTestHandler(t)

	// Test GET with invalid ID
	req := httptest.NewRequest("GET", "/api/v1/vps/invalid-id/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for invalid id, got %d", rec.Code)
	}

	// Test GET with 0 ID
	req = httptest.NewRequest("GET", "/api/v1/vps/0/", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for id=0, got %d", rec.Code)
	}

	// Test PATCH with 0 ID
	req = httptest.NewRequest("PATCH", "/api/v1/vps/0/", bytes.NewReader([]byte(`{"name":"test"}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for patch id=0, got %d", rec.Code)
	}

	// Test DELETE with invalid ID
	req = httptest.NewRequest("DELETE", "/api/v1/vps/abc/", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for delete invalid id, got %d", rec.Code)
	}

	// Test PROBE with 0 ID
	req = httptest.NewRequest("POST", "/api/v1/vps/0/probe/", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for probe id=0, got %d", rec.Code)
	}
}

func TestHandler_LifecycleAndMeta(t *testing.T) {
	_, st, mux := setupTestHandler(t)

	// 1. Pre-populate host directly in store (bypass external DNS check during unit tests)
	id, err := st.Create(&domain.VPSHost{
		Name: "Edge-Tokyo", Role: "edge", Domain: "edge1.example.com",
		IP: "198.51.100.10", SSHPort: 2222, SSHUsername: "root",
	}, "cipher-test")
	if err != nil || id == 0 {
		t.Fatalf("Failed to pre-populate VPS: %v", err)
	}

	// 2. Get the VPS via HTTP
	req := httptest.NewRequest("GET", "/api/v1/vps/1/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Get VPS failed: code %d", rec.Code)
	}

	// 3. Patch metadata (name, remark, role)
	patchBody := `{"name":"Edge-Tokyo-Renamed","remark":"production edge","role":"gateway"}`
	req = httptest.NewRequest("PATCH", "/api/v1/vps/1/", bytes.NewReader([]byte(patchBody)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Patch VPS failed: code %d, body %s", rec.Code, rec.Body.String())
	}

	var patchResp struct {
		Code int             `json:"code"`
		Data *domain.VPSHost `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &patchResp); err != nil || patchResp.Data == nil {
		t.Fatalf("Failed to parse patch response: %v", err)
	}
	if patchResp.Data.Name != "Edge-Tokyo-Renamed" || patchResp.Data.Remark != "production edge" || patchResp.Data.Role != "gateway" {
		t.Errorf("Patch meta mismatch: %+v", patchResp.Data)
	}

	// 4. ProbeAll (with timeout context inside handler)
	req = httptest.NewRequest("POST", "/api/v1/vps/probe-all/", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ProbeAll failed: code %d, body %s", rec.Code, rec.Body.String())
	}

	// 5. Delete VPS via HTTP
	req = httptest.NewRequest("DELETE", "/api/v1/vps/1/", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Delete VPS failed: code %d", rec.Code)
	}

	// 6. Confirm deleted (Get returns 404)
	req = httptest.NewRequest("GET", "/api/v1/vps/1/", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected 404 after delete, got %d", rec.Code)
	}
}
