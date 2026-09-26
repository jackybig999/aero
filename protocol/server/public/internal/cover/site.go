// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package cover 同端口正站伪装：无凭证的普通 HTTP 请求看起来像正常网站。
package cover

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Config 伪装站配置
type Config struct {
	// Enabled 默认 true
	Enabled bool
	// SiteName 站点标题
	SiteName string
	// ExtraHTML 可选追加到首页的 HTML 片段
	ExtraHTML string
}

// Site 正站 Handler
type Site struct {
	cfg Config
}

// New 创建伪装站；SiteName 空则用默认
func New(cfg Config) *Site {
	if cfg.SiteName == "" {
		cfg.SiteName = "CloudEdge CDN"
	}
	cfg.Enabled = true
	return &Site{cfg: cfg}
}

// ServeHTTP 处理非 CONNECT 的伪装流量
func (s *Site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s == nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.URL.Path == "/robots.txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("User-agent: *\nAllow: /\n"))
		return
	case r.URL.Path == "/favicon.ico":
		w.WriteHeader(http.StatusNoContent)
		return
	case r.URL.Path == "/" || r.URL.Path == "/index.html":
		s.writeHome(w, r)
		return
	case r.URL.Path == "/healthz" || r.URL.Path == "/status":
		// 看起来像运维探活，非 AERO 内部 /health
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"edge-cdn"}`))
		return
	default:
		s.write404(w, r)
	}
}

func (s *Site) writeHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	body := fmt.Sprintf(homeHTML, s.cfg.SiteName, s.cfg.SiteName, host, time.Now().UTC().Format(time.RFC3339), s.cfg.ExtraHTML)
	_, _ = w.Write([]byte(body))
}

func (s *Site) write404(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprintf(w, notFoundHTML, s.cfg.SiteName, escape(r.URL.Path))
}

func escape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

const homeHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0b1220;color:#e8eefc}
.wrap{max-width:720px;margin:12vh auto;padding:0 24px}
h1{font-size:1.75rem;font-weight:600;margin:0 0 8px}
p{color:#9db0d0;line-height:1.6}
.card{background:#121a2b;border:1px solid #1e2a44;border-radius:12px;padding:28px}
.badge{display:inline-block;background:#163524;color:#5ddea5;padding:4px 10px;border-radius:999px;font-size:12px;margin-bottom:16px}
footer{margin-top:24px;font-size:12px;color:#6b7c99}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="badge">Operational</div>
    <h1>%s</h1>
    <p>This edge node is part of a content delivery network. Static assets and API traffic are terminated here.</p>
    <p>Host: <strong>%s</strong><br>Time (UTC): %s</p>
    %s
  </div>
  <footer>&copy; Cloud infrastructure. All rights reserved.</footer>
</div>
</body>
</html>
`

const notFoundHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>404 — %s</title>
<style>body{font-family:system-ui,sans-serif;background:#0b1220;color:#e8eefc;padding:48px}</style>
</head><body><h1>404 Not Found</h1><p>No resource at <code>%s</code>.</p></body></html>
`
