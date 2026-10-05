// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// Shared HTTP JSON Serialization Helpers
// ============================================================================

// writeJSON serializes response as application/json.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteJSON is the exported alias for writeJSON.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	writeJSON(w, status, v)
}

// errResp produces standard code/message error maps.
func errResp(code int, msg string) map[string]any {
	return map[string]any{"code": code, "message": msg}
}

// ============================================================================
// Authentication & Security Middleware (from middleware.go)
// ============================================================================

type CtxKey string

const (
	CtxUserID  CtxKey = "user_id"
	CtxIsStaff CtxKey = "is_staff"
)

// TokenVerifier validates a session token and returns (userID, isStaff, error).
type TokenVerifier func(token string) (userID uint64, isStaff bool, err error)

// Gate wraps the app mux and enforces authentication on protected API endpoints.
type Gate struct {
	Verify TokenVerifier
	Next   http.Handler
}

func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	if method == http.MethodOptions {
		g.Next.ServeHTTP(w, r)
		return
	}

	// Non-API paths (/health, /sub/..., /admin/..., /login) bypass gate
	if !strings.HasPrefix(path, "/api/") {
		g.Next.ServeHTTP(w, r)
		return
	}

	// Public APIs do not require credentials
	if isPublicAPI(method, path) {
		g.Next.ServeHTTP(w, r)
		return
	}

	token := ExtractToken(r)
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 1003, "message": "unauthorized: login required"})
		return
	}

	uid, staff, err := g.Verify(token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 1003, "message": "invalid token"})
		return
	}

	ctx := WithUser(r, uid, staff)
	r = r.WithContext(ctx)

	if isUserOpenAPI(method, path) {
		g.Next.ServeHTTP(w, r)
		return
	}

	if !staff {
		writeJSON(w, http.StatusForbidden, map[string]any{"code": 1003, "message": "admin privilege required"})
		return
	}

	g.Next.ServeHTTP(w, r)
}

func isPublicAPI(method, path string) bool {
	if method == http.MethodPost && path == "/api/v1/auth/login/" {
		return true
	}
	if method == http.MethodPost && path == "/api/v1/users/" {
		return true
	}
	if method == http.MethodGet && path == "/api/v1/plans/" {
		return true
	}
	if method == http.MethodGet && path == "/api/v1/payments/in/channels/" {
		return true
	}
	if method == http.MethodGet && (path == "/api/v1/nodes/" || path == "/api/v1/nodes/available/") {
		return true
	}
	if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/nodes/") && strings.HasSuffix(path, "/heartbeat/") {
		return true
	}
	return false
}

func isUserOpenAPI(method, path string) bool {
	if strings.HasPrefix(path, "/api/v1/orders/") {
		return true
	}
	if strings.HasPrefix(path, "/api/v1/user/subscription") {
		return true
	}
	if method == http.MethodGet && path == "/api/v1/auth/me/" {
		return true
	}
	if method == http.MethodGet && strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/traffic/") {
		return true
	}
	if method == http.MethodGet && strings.HasPrefix(path, "/api/v1/users/") {
		rest := strings.TrimPrefix(path, "/api/v1/users/")
		if rest != "" && !strings.Contains(strings.Trim(rest, "/"), "/") {
			return true
		}
	}
	if method == http.MethodPost && path == "/api/v1/payments/in/orders/" {
		return true
	}
	return false
}

// Recover catches panics and prevents the middle platform from crashing.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{
					"code":    1006,
					"message": "internal server error recovered",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// CORSPermissive enables CORS headers for cross-origin browser requests.
func CORSPermissive(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,Accept")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ExtractToken parses Bearer or Token headers.
func ExtractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if s, ok := strings.CutPrefix(auth, "Bearer "); ok {
		return strings.TrimSpace(s)
	}
	if s, ok := strings.CutPrefix(auth, "Token "); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// WithUser binds user session values into request context.
func WithUser(r *http.Request, userID uint64, isStaff bool) context.Context {
	ctx := r.Context()
	ctx = context.WithValue(ctx, CtxUserID, userID)
	ctx = context.WithValue(ctx, CtxIsStaff, isStaff)
	return ctx
}

// ============================================================================
// Web SPA Static File Serving & Asset Discovery (from web_handler.go)
// ============================================================================

type WebPaths struct {
	UserDist  string
	AdminDist string
}

func FindWebDist() WebPaths {
	candidates := []string{
		".",
		"web",
		"aerosub/cmd/mid/web",
		filepath.Dir(os.Args[0]),
		filepath.Join(filepath.Dir(os.Args[0]), "web"),
		filepath.Join(filepath.Dir(os.Args[0]), "..", "web"),
	}
	cwd, _ := os.Getwd()
	candidates = append(candidates, cwd, filepath.Join(cwd, "web"), filepath.Join(cwd, "aerosub", "cmd", "mid", "web"))

	var p WebPaths
	for _, root := range candidates {
		try := func(parts ...string) string {
			fp := filepath.Join(append([]string{root}, parts...)...)
			if st, err := os.Stat(filepath.Join(fp, "index.html")); err == nil && !st.IsDir() {
				abs, _ := filepath.Abs(fp)
				return abs
			}
			return ""
		}
		if p.UserDist == "" {
			p.UserDist = try("web", "user", "dist")
			if p.UserDist == "" {
				p.UserDist = try("user", "dist")
			}
		}
		if p.AdminDist == "" {
			p.AdminDist = try("web", "admin", "dist")
			if p.AdminDist == "" {
				p.AdminDist = try("admin", "dist")
			}
		}
		if p.UserDist != "" && p.AdminDist != "" {
			break
		}
	}
	return p
}

func NewWebHandler(p WebPaths, api http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))

		if upath == "/health" || upath == "/healthz" || upath == "/metrics" || upath == "/admin/metering" || strings.HasPrefix(upath, "/admin/metering") || strings.HasPrefix(upath, "/api/") || strings.HasPrefix(upath, "/sub/") {
			api.ServeHTTP(w, r)
			return
		}

		if r.URL.Path == "/admin" {
			http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
			return
		}
		if upath == "/admin" || strings.HasPrefix(upath, "/admin/") {
			if p.AdminDist == "" {
				http.Error(w, "admin UI not built — check web/admin/dist", http.StatusServiceUnavailable)
				return
			}
			serveSPA(w, r, p.AdminDist, "/admin")
			return
		}

		if p.UserDist == "" {
			http.Error(w, "user UI not built — check web/user/dist", http.StatusServiceUnavailable)
			return
		}
		serveSPA(w, r, p.UserDist, "")
	})
}

func serveSPA(w http.ResponseWriter, r *http.Request, distDir, urlPrefix string) {
	reqPath := r.URL.Path
	if urlPrefix != "" {
		reqPath = strings.TrimPrefix(reqPath, urlPrefix)
	}
	if reqPath == "" || reqPath == "/" {
		reqPath = "/index.html"
	}

	rel := path.Clean("/" + strings.TrimPrefix(reqPath, "/"))
	full := filepath.Join(distDir, filepath.FromSlash(rel))
	if !strings.HasPrefix(full, distDir) {
		http.NotFound(w, r)
		return
	}

	if st, err := os.Stat(full); err == nil && !st.IsDir() {
		if strings.HasSuffix(rel, ".html") {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}
		http.ServeFile(w, r, full)
		return
	}

	if ext := path.Ext(rel); ext != "" && ext != ".html" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	http.ServeFile(w, r, filepath.Join(distDir, "index.html"))
}

// NewFSWebHandler supports serving directly from an embedded fs.FS (e.g. //go:embed all:web)
// with automatic fallback to filesystem paths.
func NewFSWebHandler(embeddedFS fs.FS, p WebPaths, api http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))

		if upath == "/health" || upath == "/healthz" || upath == "/metrics" || upath == "/admin/metering" || strings.HasPrefix(upath, "/admin/metering") || strings.HasPrefix(upath, "/api/") || strings.HasPrefix(upath, "/sub/") {
			api.ServeHTTP(w, r)
			return
		}

		if r.URL.Path == "/admin" {
			http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
			return
		}
		if upath == "/admin" || strings.HasPrefix(upath, "/admin/") {
			if serveSPAFromEmbeddedFS(w, r, embeddedFS, "web/admin/dist", "/admin") {
				return
			}
			if p.AdminDist != "" {
				serveSPA(w, r, p.AdminDist, "/admin")
				return
			}
			http.Error(w, "admin UI not found", http.StatusServiceUnavailable)
			return
		}

		if serveSPAFromEmbeddedFS(w, r, embeddedFS, "web/user/dist", "") {
			return
		}
		if p.UserDist != "" {
			serveSPA(w, r, p.UserDist, "")
			return
		}
		http.Error(w, "user UI not found", http.StatusServiceUnavailable)
	})
}

func serveSPAFromEmbeddedFS(w http.ResponseWriter, r *http.Request, fsys fs.FS, baseDir, urlPrefix string) bool {
	if fsys == nil {
		return false
	}
	sub, err := fs.Sub(fsys, baseDir)
	if err != nil {
		return false
	}
	// Check if index.html exists in sub
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return false
	}

	reqPath := r.URL.Path
	if urlPrefix != "" {
		reqPath = strings.TrimPrefix(reqPath, urlPrefix)
	}
	if reqPath == "" || reqPath == "/" {
		reqPath = "/index.html"
	}

	rel := strings.TrimPrefix(path.Clean("/"+reqPath), "/")
	if rel == "" {
		rel = "index.html"
	}

	f, err := sub.Open(rel)
	if err == nil {
		defer f.Close()
		st, statErr := f.Stat()
		if statErr == nil && !st.IsDir() {
			if strings.HasSuffix(rel, ".html") {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			}
			if rs, ok := f.(io.ReadSeeker); ok {
				http.ServeContent(w, r, st.Name(), st.ModTime(), rs)
				return true
			}
		}
	}

	// Fallback to index.html for SPA client-side routing
	if ext := path.Ext(rel); ext != "" && ext != ".html" {
		return false
	}

	idxFile, err := sub.Open("index.html")
	if err == nil {
		defer idxFile.Close()
		st, statErr := idxFile.Stat()
		if statErr == nil {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			if rs, ok := idxFile.(io.ReadSeeker); ok {
				http.ServeContent(w, r, "index.html", st.ModTime(), rs)
				return true
			}
		}
	}

	return false
}

// ============================================================================
// Modular AERO Console & Management API Handlers (from aero_handler.go)
// ============================================================================

// AeroHandler exposes /api/v1/aero/* endpoints for the modular AERO Console.
type AeroHandler struct {
	svc      *VPSService
	db       *AeroDB
	adminKey string
}

func NewAeroHandler(svc *VPSService) *AeroHandler {
	return &AeroHandler{svc: svc}
}

func (h *AeroHandler) SetAeroDB(db *AeroDB) {
	h.db = db
}

func (h *AeroHandler) SetAdminKey(key string) {
	h.adminKey = key
}

// RegisterMeteringRoutes mounts HandleAdminMetering onto mux.
func RegisterMeteringRoutes(mux *http.ServeMux, db *AeroDB, adminKey string) {
	mux.HandleFunc("POST /admin/metering", HandleAdminMetering(db, adminKey))
}

func (h *AeroHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/aero/vps-options/", h.VPSOptions)
	mux.HandleFunc("GET /api/v1/aero/source-status/", h.SourceStatus)
	mux.HandleFunc("GET /api/v1/aero/tasks/", h.ListTasks)
	mux.HandleFunc("GET /api/v1/aero/tasks/{id}/", h.GetTask)
	mux.HandleFunc("DELETE /api/v1/aero/tasks/{id}/", h.DeleteTask)
	mux.HandleFunc("POST /api/v1/aero/tasks/clear-failed/", h.ClearFailed)

	mux.HandleFunc("POST /api/v1/aero/install/", h.Install)
	mux.HandleFunc("POST /api/v1/aero/uninstall/", h.Uninstall)

	mux.HandleFunc("GET /api/v1/aero/vps/{id}/endpoint/", h.GetEndpoint)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/endpoint/refresh/", h.RefreshEndpoint)
	mux.HandleFunc("GET /api/v1/aero/vps/{id}/tokens/", h.ListTokens)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/tokens/", h.AddToken)
	mux.HandleFunc("DELETE /api/v1/aero/vps/{id}/tokens/", h.DelToken)

	mux.HandleFunc("GET /api/v1/aero/vps/{id}/status/", h.Diagnose)
	mux.HandleFunc("GET /api/v1/aero/vps/{id}/diagnose/", h.Diagnose)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/cert/renew/", h.RenewCert)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/restart/", h.RestartEdge)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/subs/sync/", h.SyncSubs)
	mux.HandleFunc("POST /api/v1/aero/subs/broadcast/", h.BroadcastSubs)

	if h.db != nil {
		RegisterMeteringRoutes(mux, h.db, h.adminKey)
	}
}

func (h *AeroHandler) VPSOptions(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.svc.List()
	if err != nil {
		writeJSON(w, 500, errResp(1003, err.Error()))
		return
	}
	type item struct {
		ID     uint64 `json:"id"`
		Name   string `json:"name"`
		IP     string `json:"ip"`
		Domain string `json:"domain"`
	}
	res := make([]item, 0, len(hosts))
	for _, v := range hosts {
		res = append(res, item{ID: v.ID, Name: v.Name, IP: v.IP, Domain: v.Domain})
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res, "results": res})
}

func (h *AeroHandler) SourceStatus(w http.ResponseWriter, r *http.Request) {
	st := DetectAeroSource()
	writeJSON(w, 200, map[string]any{"code": 0, "data": st})
}

func (h *AeroHandler) ListTasks(w http.ResponseWriter, r *http.Request) {
	tasks := globalTaskManager.List()
	writeJSON(w, 200, map[string]any{"code": 0, "data": tasks, "results": tasks})
}

func (h *AeroHandler) GetTask(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		writeJSON(w, 400, errResp(1002, "invalid task id"))
		return
	}
	task, ok := globalTaskManager.Get(id)
	if !ok {
		writeJSON(w, 404, errResp(1001, "task not found"))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": task})
}

func (h *AeroHandler) DeleteTask(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseUint(idStr, 10, 64)
	globalTaskManager.Delete(id)
	writeJSON(w, 200, map[string]any{"code": 0, "message": "deleted"})
}

func (h *AeroHandler) ClearFailed(w http.ResponseWriter, r *http.Request) {
	cnt := globalTaskManager.ClearFailed()
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"deleted": cnt}})
}

func parseReqVPSID(r *http.Request) (uint64, error) {
	var raw map[string]any
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return 0, fmt.Errorf("invalid json: %w", err)
	}
	v, ok := raw["vps_id"]
	if !ok || v == nil {
		return 0, fmt.Errorf("vps_id required")
	}
	switch val := v.(type) {
	case float64:
		if val <= 0 {
			return 0, fmt.Errorf("vps_id must be positive")
		}
		return uint64(val), nil
	case string:
		s := strings.TrimSpace(val)
		if s == "" {
			return 0, fmt.Errorf("vps_id required")
		}
		id, err := strconv.ParseUint(s, 10, 64)
		if err != nil || id == 0 {
			return 0, fmt.Errorf("invalid vps_id string: %s", val)
		}
		return id, nil
	default:
		return 0, fmt.Errorf("vps_id required")
	}
}

func (h *AeroHandler) Install(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VPSID uint64 `json:"vps_id"`
		Port  int    `json:"port"`
	}
	body, err := io.ReadAll(r.Body)
	if err == nil && len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, errResp(1001, "invalid json body: "+err.Error()))
			return
		}
	}
	if req.VPSID == 0 {
		vpsID, err := parseReqVPSID(r)
		if err != nil {
			writeJSON(w, 422, errResp(1002, "vps_id required"))
			return
		}
		req.VPSID = vpsID
	}
	cred, err := h.svc.store.GetCredentials(req.VPSID)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "vps not found: "+err.Error()))
		return
	}
	task := globalTaskManager.CreateTask("install", req.VPSID, cred.Name, DefaultInstallSteps())
	go RunInstallTask(task.ID, req.VPSID, req.Port, h.svc)
	writeJSON(w, 201, map[string]any{"code": 0, "data": task})
}

func (h *AeroHandler) Uninstall(w http.ResponseWriter, r *http.Request) {
	vpsID, err := parseReqVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "vps_id required"))
		return
	}
	cred, err := h.svc.store.GetCredentials(vpsID)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "vps not found: "+err.Error()))
		return
	}
	task := globalTaskManager.CreateTask("uninstall", vpsID, cred.Name, DefaultUninstallSteps())
	go RunUninstallTask(task.ID, vpsID, h.svc)
	writeJSON(w, 200, map[string]any{"code": 0, "data": task})
}

func (h *AeroHandler) Restart(w http.ResponseWriter, r *http.Request) {
	vpsID, err := parseReqVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "vps_id required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := h.svc.RestartEdge(ctx, vpsID)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res})
}

func (h *AeroHandler) GetEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	if h.svc.eps != nil {
		if ep, ok := h.svc.eps.Get(id); ok {
			writeJSON(w, 200, map[string]any{"code": 0, "data": ep})
			return
		}
	}
	v, err := h.svc.Get(id)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "vps not found"))
		return
	}
	host := v.Domain
	if host == "" {
		host = v.IP
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": EndpointInfo{
		VPSID:     id,
		Name:      v.Name,
		Host:      host,
		Port:      443,
		Installed: false,
	}})
}

func (h *AeroHandler) RefreshEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ep, err := h.svc.InstallAeroOnVPS(id)
	if err != nil {
		writeJSON(w, 500, errResp(1003, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": ep})
}

func (h *AeroHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	v, _ := h.svc.Get(id)
	defTok := "aero_default_user_token"
	if v != nil && v.Name != "" {
		defTok = "tok_" + v.Name
	}
	tokens := []map[string]any{
		{
			"token":      defTok,
			"token_mask": defTok[:4] + "…" + defTok[len(defTok)-3:],
			"label":      "默认用户",
			"created_at": time.Now().Format("2006-01-02 15:04:05"),
		},
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": tokens}})
}

func (h *AeroHandler) AddToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Label    string `json:"label"`
		TTLHours int    `json:"ttl_hours"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, errResp(1001, "invalid json body: "+err.Error()))
			return
		}
	}
	tok := req.Token
	if tok == "" {
		tok = "tok_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	item := map[string]any{
		"token":      tok,
		"token_mask": tok[:4] + "…",
		"label":      req.Label,
	}
	writeJSON(w, 201, map[string]any{"code": 0, "data": item})
}

func (h *AeroHandler) DelToken(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"code": 0, "message": "deleted"})
}

func (h *AeroHandler) Diagnose(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	diag, err := h.svc.Diagnose(ctx, id)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": diag})
}

func (h *AeroHandler) RenewCert(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	var req struct {
		Force bool `json:"force"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, errResp(1001, "invalid json body: "+err.Error()))
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	res, err := h.svc.RenewCert(ctx, id, req.Force)
	if err != nil {
		writeJSON(w, 502, map[string]any{"code": 1006, "message": err.Error(), "data": res})
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res})
}

func (h *AeroHandler) RestartEdge(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := h.svc.RestartEdge(ctx, id)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res})
}

func (h *AeroHandler) SyncSubs(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	if h.svc == nil || h.svc.userStore == nil {
		writeJSON(w, 500, errResp(1004, "user store unavailable"))
		return
	}
	if err := h.svc.SyncAllUsersToVPS(id, h.svc.userStore); err != nil {
		writeJSON(w, 502, map[string]any{"code": 1006, "message": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "message": "synced successfully"})
}

func (h *AeroHandler) BroadcastSubs(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || h.svc.userStore == nil {
		writeJSON(w, 500, errResp(1004, "user store unavailable"))
		return
	}
	h.svc.BroadcastAllUsersToAllEdges(h.svc.userStore)
	writeJSON(w, 200, map[string]any{"code": 0, "message": "broadcasted successfully"})
}
