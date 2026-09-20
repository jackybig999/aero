// Copyright 2025 AERO Protocol Contributors
// Plan.md Phase 2: 中台静态前端 Web 资源路由与单页应用 (SPA) 支持

package main

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type WebPaths struct {
	UserDist  string
	AdminDist string
}

func FindWebDist() WebPaths {
	candidates := []string{
		".",
		"web",
		"sub/vpn",
		filepath.Dir(os.Args[0]),
		filepath.Join(filepath.Dir(os.Args[0]), "..", "..", "sub", "vpn"),
	}
	cwd, _ := os.Getwd()
	candidates = append(candidates, cwd, filepath.Join(cwd, "sub", "vpn"))

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

		if upath == "/health" || strings.HasPrefix(upath, "/api/") || strings.HasPrefix(upath, "/sub/") {
			api.ServeHTTP(w, r)
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
