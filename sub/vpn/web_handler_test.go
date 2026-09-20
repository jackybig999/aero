// Copyright 2025 AERO Protocol Contributors
// Plan.md Phase 2: Web 路由与 AERO Console 静态测试

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestWebHandlerRouting(t *testing.T) {
	// Create temporary directories to simulate dist
	tmpDir := t.TempDir()

	userDist := filepath.Join(tmpDir, "user")
	adminDist := filepath.Join(tmpDir, "admin")
	aeroDist := filepath.Join(tmpDir, "aero")

	_ = os.MkdirAll(filepath.Join(userDist, "assets"), 0755)
	_ = os.MkdirAll(filepath.Join(adminDist, "assets"), 0755)
	_ = os.MkdirAll(filepath.Join(aeroDist, "assets"), 0755)

	_ = os.WriteFile(filepath.Join(userDist, "index.html"), []byte("<html>User Portal</html>"), 0644)
	_ = os.WriteFile(filepath.Join(adminDist, "index.html"), []byte("<html>Admin Dashboard</html>"), 0644)
	_ = os.WriteFile(filepath.Join(aeroDist, "index.html"), []byte("<html>AERO Console</html>"), 0644)
	_ = os.WriteFile(filepath.Join(aeroDist, "assets", "test.js"), []byte("console.log('aero');"), 0644)

	paths := WebPaths{
		UserDist:   userDist,
		AdminDist:  adminDist,
		AeroUIDist: aeroDist,
	}

	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"api":"ok"}`))
	})

	handler := NewWebHandler(paths, api)

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string
		wantHeader string
	}{
		{
			name:       "API health pass-through",
			path:       "/health",
			wantStatus: http.StatusOK,
			wantBody:   `{"api":"ok"}`,
		},
		{
			name:       "API v1 pass-through",
			path:       "/api/v1/nodes/",
			wantStatus: http.StatusOK,
			wantBody:   `{"api":"ok"}`,
		},
		{
			name:       "Redirect /admin to /admin/",
			path:       "/admin",
			wantStatus: http.StatusMovedPermanently,
		},
		{
			name:       "Admin dashboard index",
			path:       "/admin/",
			wantStatus: http.StatusOK,
			wantBody:   "<html>Admin Dashboard</html>",
		},
		{
			name:       "Admin dashboard SPA subroute fallback",
			path:       "/admin/vps",
			wantStatus: http.StatusOK,
			wantBody:   "<html>Admin Dashboard</html>",
		},
		{
			name:       "Redirect /aero-ui to /aero-ui/",
			path:       "/aero-ui",
			wantStatus: http.StatusMovedPermanently,
		},
		{
			name:       "AERO Console index",
			path:       "/aero-ui/",
			wantStatus: http.StatusOK,
			wantBody:   "<html>AERO Console</html>",
		},
		{
			name:       "AERO Console with query params (as in iframe)",
			path:       "/aero-ui/?mode=mid&embed=1",
			wantStatus: http.StatusOK,
			wantBody:   "<html>AERO Console</html>",
		},
		{
			name:       "AERO Console asset",
			path:       "/aero-ui/assets/test.js",
			wantStatus: http.StatusOK,
			wantBody:   "console.log('aero');",
		},
		{
			name:       "User portal index",
			path:       "/",
			wantStatus: http.StatusOK,
			wantBody:   "<html>User Portal</html>",
		},
		{
			name:       "User portal SPA subroute fallback",
			path:       "/login",
			wantStatus: http.StatusOK,
			wantBody:   "<html>User Portal</html>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d for path %s", tt.wantStatus, rec.Code, tt.path)
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Fatalf("expected body %q, got %q for path %s", tt.wantBody, rec.Body.String(), tt.path)
			}
		})
	}
}
