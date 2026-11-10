package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func probeRequest(srv *Server, path, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// 回归：/healthz 曾对公网返回固定的 "ok"，伪装站上的探针路径会暴露节点身份。
func TestProbeEndpointsHiddenFromNonLoopback(t *testing.T) {
	srv, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", DataDir: t.TempDir(), Domain: "example.test", AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	cover := probeRequest(srv, "/", "203.0.113.7:4000")
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := probeRequest(srv, path, "203.0.113.7:4000")
		if rec.Body.String() == "ok" || rec.Body.String() != cover.Body.String() || rec.Code != cover.Code {
			t.Fatalf("public %s = %d %q, want the cover page", path, rec.Code, rec.Body.String())
		}
	}
}

// /readyz 在 Start 完成前返回 503，完成后 200；/healthz 只表示进程存活（L0 §8.7）。
func TestProbeEndpointsReadinessFollowsStart(t *testing.T) {
	srv, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", DataDir: t.TempDir(), Domain: "example.test", AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	if rec := probeRequest(srv, "/healthz", "127.0.0.1:5000"); rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("loopback /healthz before Start = %d %q, want 200 ok", rec.Code, rec.Body.String())
	}
	if rec := probeRequest(srv, "/readyz", "127.0.0.1:5000"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("loopback /readyz before Start = %d, want 503", rec.Code)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if rec := probeRequest(srv, "/readyz", "[::1]:5000"); rec.Code != http.StatusOK {
		t.Fatalf("loopback /readyz after Start = %d, want 200", rec.Code)
	}
}
