// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// aero-panel: standalone embedded WebUI host for aero-edge.
// Serves embedded Vue SPA from dist/ and exposes /api/v1/aero/* proxying edge Admin.
package main

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed dist/*
var embeddedDist embed.FS

func main() {
	listenFlag := flag.String("listen", env("LISTEN", ":8090"), "panel listen address")
	edgeFlag := flag.String("edge", env("AERO_EDGE_URL", "https://127.0.0.1:443"), "aero-edge URL")
	adminKeyFlag := flag.String("admin-key", env("AERO_ADMIN_KEY", ""), "admin authentication key")
	subURLFlag := flag.String("sub-url", env("AERO_SUB_URL", ""), "subscription base URL")
	flag.Parse()

	cfg := &panelConfig{
		EdgeURL:  strings.TrimRight(*edgeFlag, "/"),
		AdminKey: *adminKeyFlag,
		SubURL:   *subURLFlag,
	}

	distFS, err := fs.Sub(embeddedDist, "dist")
	if err != nil {
		log.Fatalf("failed to open embedded dist: %v", err)
	}

	p := &panel{
		cfg:    cfg,
		distFS: distFS,
	}

	mux := http.NewServeMux()

	// 1. GET /health is public and never requires authentication
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"product": "aero-panel",
			"mode":    "standalone",
			"edge":    cfg.snapshot().EdgeURL,
			"ui":      true,
		})
	})

	// 2. Admin API routes wrapped with X-Aero-Admin-Key authentication middleware
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("GET /api/v1/aero/panel/config/", p.getConfig)
	apiMux.HandleFunc("POST /api/v1/aero/panel/config/", p.saveConfig)
	apiMux.HandleFunc("GET /api/v1/aero/endpoint/", p.getEndpoint)
	apiMux.HandleFunc("POST /api/v1/aero/endpoint/refresh/", p.getEndpoint)
	apiMux.HandleFunc("GET /api/v1/aero/tokens/", p.listTokens)
	apiMux.HandleFunc("POST /api/v1/aero/tokens/", p.addToken)
	apiMux.HandleFunc("DELETE /api/v1/aero/tokens/", p.delToken)
	apiMux.HandleFunc("GET /api/v1/aero/status/", p.status)

	mux.Handle("/api/", p.adminKeyMiddleware(apiMux))

	// 3. Embedded SPA Web UI at / and /aero-ui/
	mux.HandleFunc("/", p.serveUI)

	fmt.Printf("\n  aero-panel → http://127.0.0.1%s\n", *listenFlag)
	fmt.Printf("    edge: %s\n", cfg.EdgeURL)
	fmt.Printf("    auth: %s\n\n", hasAuth(cfg.AdminKey))

	log.Fatal(http.ListenAndServe(*listenFlag, cors(mux)))
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
	cfg    *panelConfig
	distFS fs.FS
}

// adminKeyMiddleware authenticates requests against AERO_ADMIN_KEY
func (p *panel) adminKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := p.cfg.snapshot()
		// If AdminKey is configured, enforce strict authentication
		if s.AdminKey != "" {
			providedKey := r.Header.Get("X-Aero-Admin-Key")
			if providedKey == "" {
				providedKey = r.URL.Query().Get("key")
			}
			if subtle.ConstantTimeCompare([]byte(providedKey), []byte(s.AdminKey)) != 1 {
				writeJSON(w, http.StatusUnauthorized, errResp(401, "unauthorized: valid X-Aero-Admin-Key required"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (p *panel) getConfig(w http.ResponseWriter, r *http.Request) {
	s := p.cfg.snapshot()
	writeJSON(w, http.StatusOK, dataResp(map[string]any{
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
	writeJSON(w, http.StatusOK, dataResp(map[string]any{"ok": true}))
}

func (p *panel) getEndpoint(w http.ResponseWriter, r *http.Request) {
	s := p.cfg.snapshot()
	ver := ""
	if st, err := p.edgeDo(http.MethodGet, "/admin/status", nil); err == nil {
		var m map[string]any
		_ = json.Unmarshal(st, &m)
		if v, ok := m["version"].(string); ok {
			ver = v
		}
	}
	host := hostOf(s.EdgeURL)
	writeJSON(w, http.StatusOK, dataResp(map[string]any{
		"host":      host,
		"sub_url":   s.SubURL,
		"has_admin": s.AdminKey != "",
		"version":   ver,
		"installed": true,
	}))
}

// listTokens lists tokens with masking; STOP returning token_full
func (p *panel) listTokens(w http.ResponseWriter, r *http.Request) {
	raw, err := p.edgeDo(http.MethodGet, "/admin/tokens", nil)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errResp(1006, err.Error()))
		return
	}
	var wrap struct {
		Tokens []map[string]any `json:"tokens"`
	}
	_ = json.Unmarshal(raw, &wrap)

	// STOP returning token_full in API responses; only provide token_mask
	for i := range wrap.Tokens {
		if t, ok := wrap.Tokens[i]["token"].(string); ok && len(t) > 8 {
			wrap.Tokens[i]["token_mask"] = t[:4] + "…" + t[len(t)-4:]
			delete(wrap.Tokens[i], "token")
			delete(wrap.Tokens[i], "token_full")
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"results": wrap.Tokens}})
}

func (p *panel) addToken(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	raw, err := p.edgeDo(http.MethodPost, "/admin/tokens", body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errResp(1006, err.Error()))
		return
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	// Mask returned token if present
	if t, ok := m["token"].(string); ok && len(t) > 8 {
		m["token_mask"] = t[:4] + "…" + t[len(t)-4:]
		delete(m, "token_full")
	}
	writeJSON(w, http.StatusCreated, dataResp(m))
}

func (p *panel) delToken(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		writeJSON(w, http.StatusUnprocessableEntity, errResp(1002, "token required"))
		return
	}
	path := "/admin/tokens?token=" + url.QueryEscape(tok)
	if _, err := p.edgeDo(http.MethodDelete, path, nil); err != nil {
		writeJSON(w, http.StatusBadGateway, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "ok"})
}

func (p *panel) status(w http.ResponseWriter, r *http.Request) {
	raw, err := p.edgeDo(http.MethodGet, "/admin/status", nil)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errResp(1006, err.Error()))
		return
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	writeJSON(w, http.StatusOK, dataResp(m))
}

func (p *panel) edgeDo(method, path string, body any) ([]byte, error) {
	s := p.cfg.snapshot()
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
		return nil, fmt.Errorf("edge HTTP %d: %s", resp.StatusCode, trimStr(string(raw), 160))
	}
	return raw, nil
}

// serveUI serves embedded static assets or SPA index.html
func (p *panel) serveUI(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}

	reqPath := r.URL.Path
	if strings.HasPrefix(reqPath, "/aero-ui") {
		reqPath = strings.TrimPrefix(reqPath, "/aero-ui")
	}
	reqPath = strings.TrimPrefix(reqPath, "/")
	if reqPath == "" {
		reqPath = "index.html"
	}

	// Try reading exact file
	f, err := p.distFS.Open(reqPath)
	if err == nil {
		defer f.Close()
		stat, err := f.Stat()
		if err == nil && !stat.IsDir() {
			http.FileServer(http.FS(p.distFS)).ServeHTTP(w, r)
			return
		}
	}

	// Fallback to index.html for SPA client-side routing
	indexData, err := fs.ReadFile(p.distFS, "index.html")
	if err != nil {
		http.Error(w, "index.html not found in embedded UI", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(indexData)
}

func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Aero-Admin-Key, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func dataResp(d any) map[string]any {
	return map[string]any{"code": 0, "data": d}
}

func errResp(code int, msg string) map[string]any {
	return map[string]any{"code": code, "message": msg}
}

func hostOf(u string) string {
	if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return u
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func hasAuth(k string) string {
	if k != "" {
		return "enabled (X-Aero-Admin-Key enforced)"
	}
	return "disabled (no key set)"
}

func trimStr(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
