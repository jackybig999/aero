// aero-panel: thin standalone WebUI host for aero-edge.
//
// Serves the same Vue SPA as mid-platform embeds under /aero-ui/,
// and exposes a unified /api/v1/aero/* surface that proxies edge Admin.
//
//	AERO_EDGE_URL=https://127.0.0.1:443
//	AERO_ADMIN_KEY=...
//	AERO_SUB_URL=https://edge.example.com/sub/secret   (optional)
//	LISTEN=:8090
//	AERO_WEBUI_DIST=/path/to/aero/webui/dist
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func main() {
	listen := env("LISTEN", ":8090")
	cfg := &panelConfig{
		EdgeURL:  strings.TrimRight(env("AERO_EDGE_URL", "https://127.0.0.1:443"), "/"),
		AdminKey: env("AERO_ADMIN_KEY", ""),
		SubURL:   env("AERO_SUB_URL", ""),
	}
	dist := findDist()
	p := &panel{cfg: cfg, dist: dist}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"status": "ok", "product": "aero-panel", "mode": "standalone",
			"edge": cfg.snapshot().EdgeURL, "ui": dist != "",
		})
	})
	mux.HandleFunc("GET /api/v1/aero/panel/config/", p.getConfig)
	mux.HandleFunc("POST /api/v1/aero/panel/config/", p.saveConfig)
	mux.HandleFunc("GET /api/v1/aero/endpoint/", p.getEndpoint)
	mux.HandleFunc("POST /api/v1/aero/endpoint/refresh/", p.getEndpoint)
	mux.HandleFunc("GET /api/v1/aero/tokens/", p.listTokens)
	mux.HandleFunc("POST /api/v1/aero/tokens/", p.addToken)
	mux.HandleFunc("DELETE /api/v1/aero/tokens/", p.delToken)
	mux.HandleFunc("GET /api/v1/aero/status/", p.status)

	// SPA at / and /aero-ui/ (both bases work)
	mux.HandleFunc("/", p.serveUI)

	fmt.Printf("\n  aero-panel → http://127.0.0.1%s\n", listen)
	fmt.Printf("    edge: %s\n", cfg.EdgeURL)
	fmt.Printf("    ui:   %s\n\n", empty(dist, "(missing — npm run build in aero/webui)"))
	log.Fatal(http.ListenAndServe(listen, cors(mux)))
}

type panelConfig struct {
	mu       sync.RWMutex
	EdgeURL  string `json:"edge_url"`
	AdminKey string `json:"-"`
	SubURL   string `json:"sub_url"`
}

func (c *panelConfig) snapshot() panelConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return panelConfig{EdgeURL: c.EdgeURL, AdminKey: c.AdminKey, SubURL: c.SubURL}
}

func (c *panelConfig) set(edge, key, sub string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if edge != "" {
		c.EdgeURL = strings.TrimRight(edge, "/")
	}
	// allow explicit clear with empty after first set via "-"
	if key == "-" {
		c.AdminKey = ""
	} else if key != "" {
		c.AdminKey = key
	}
	if sub != "" {
		c.SubURL = sub
	}
}

type panel struct {
	cfg  *panelConfig
	dist string
}

func (p *panel) getConfig(w http.ResponseWriter, r *http.Request) {
	s := p.cfg.snapshot()
	writeJSON(w, 200, dataResp(map[string]any{
		"mode":          "standalone",
		"edge_url":      s.EdgeURL,
		"sub_url":       s.SubURL,
		"admin_key_set": s.AdminKey != "",
	}))
}

func (p *panel) saveConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EdgeURL  string `json:"edge_url"`
		AdminKey string `json:"admin_key"`
		SubURL   string `json:"sub_url"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	p.cfg.set(req.EdgeURL, req.AdminKey, req.SubURL)
	writeJSON(w, 200, dataResp(map[string]any{"ok": true}))
}

func (p *panel) getEndpoint(w http.ResponseWriter, r *http.Request) {
	s := p.cfg.snapshot()
	// try edge status for version
	ver := ""
	if st, err := p.edgeDo(http.MethodGet, "/admin/status", nil); err == nil {
		var m map[string]any
		_ = json.Unmarshal(st, &m)
		if v, ok := m["version"].(string); ok {
			ver = v
		}
	}
	host := hostOf(s.EdgeURL)
	writeJSON(w, 200, dataResp(map[string]any{
		"host":      host,
		"sub_url":   s.SubURL,
		"has_admin": s.AdminKey != "",
		"version":   ver,
		"installed": true,
	}))
}

func (p *panel) listTokens(w http.ResponseWriter, r *http.Request) {
	raw, err := p.edgeDo(http.MethodGet, "/admin/tokens", nil)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	var wrap struct {
		Tokens []map[string]any `json:"tokens"`
	}
	_ = json.Unmarshal(raw, &wrap)
	for i := range wrap.Tokens {
		if t, ok := wrap.Tokens[i]["token"].(string); ok && len(t) > 8 {
			wrap.Tokens[i]["token_mask"] = t[:4] + "…" + t[len(t)-4:]
			wrap.Tokens[i]["token_full"] = t
		}
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": wrap.Tokens}})
}

func (p *panel) addToken(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	raw, err := p.edgeDo(http.MethodPost, "/admin/tokens", body)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	writeJSON(w, 201, dataResp(m))
}

func (p *panel) delToken(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		writeJSON(w, 422, errResp(1002, "token required"))
		return
	}
	path := "/admin/tokens?token=" + url.QueryEscape(tok)
	if _, err := p.edgeDo(http.MethodDelete, path, nil); err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "message": "ok"})
}

func (p *panel) status(w http.ResponseWriter, r *http.Request) {
	raw, err := p.edgeDo(http.MethodGet, "/admin/status", nil)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	writeJSON(w, 200, dataResp(m))
}

func (p *panel) edgeDo(method, path string, body any) ([]byte, error) {
	s := p.cfg.snapshot()
	// optional request override header
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.EdgeURL+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.AdminKey != "" {
		req.Header.Set("X-Aero-Admin-Key", s.AdminKey)
	}
	cli := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("edge HTTP %d: %s", resp.StatusCode, trim(string(raw), 160))
	}
	return raw, nil
}

func (p *panel) serveUI(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if p.dist == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body style="font-family:system-ui;background:#0b1220;color:#e8eef9;padding:40px">
<h1>aero-panel</h1><p>UI not built. Run: <code>cd aero/webui &amp;&amp; npm.cmd install &amp;&amp; npm.cmd run build</code></p>
<p><a href="/health">/health</a></p></body></html>`))
		return
	}
	// support both / and /aero-ui/
	reqPath := r.URL.Path
	if strings.HasPrefix(reqPath, "/aero-ui") {
		reqPath = strings.TrimPrefix(reqPath, "/aero-ui")
	}
	if reqPath == "" || reqPath == "/" {
		reqPath = "/index.html"
	}
	rel := filepath.Clean("/" + strings.TrimPrefix(reqPath, "/"))
	full := filepath.Join(p.dist, filepath.FromSlash(rel))
	if !strings.HasPrefix(full, p.dist) {
		http.NotFound(w, r)
		return
	}
	if st, err := os.Stat(full); err == nil && !st.IsDir() {
		http.ServeFile(w, r, full)
		return
	}
	if ext := filepath.Ext(rel); ext != "" && ext != ".html" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(p.dist, "index.html"))
}

func findDist() string {
	if d := env("AERO_WEBUI_DIST", ""); d != "" {
		if st, err := os.Stat(filepath.Join(d, "index.html")); err == nil && !st.IsDir() {
			abs, _ := filepath.Abs(d)
			return abs
		}
	}
	var roots []string
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots, wd, filepath.Join(wd, ".."), filepath.Join(wd, "..", ".."))
	}
	if ex, err := os.Executable(); err == nil {
		d := filepath.Dir(ex)
		roots = append(roots, d, filepath.Join(d, ".."), filepath.Join(d, "..", ".."))
	}
	for _, root := range roots {
		for _, rel := range [][]string{
			{"dist"},
			{"webui", "dist"},
			{"public", "webui", "dist"},
			{"protocol", "server", "public", "webui", "dist"},
			{"aero", "webui", "dist"},
		} {
			fp := filepath.Join(append([]string{root}, rel...)...)
			if st, err := os.Stat(filepath.Join(fp, "index.html")); err == nil && !st.IsDir() {
				abs, _ := filepath.Abs(fp)
				return abs
			}
		}
	}
	return ""
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Aero-Admin-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func dataResp(v any) map[string]any { return map[string]any{"code": 0, "data": v} }
func errResp(code int, msg string) map[string]any {
	return map[string]any{"code": code, "message": msg}
}
func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
func empty(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
func hostOf(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return strings.Split(u, "/")[0]
}
