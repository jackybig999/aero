// Package web serves built Vue SPAs (user portal + admin) from dist folders.
package web

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Paths to dist directories.
type Paths struct {
	UserDist   string
	AdminDist  string
	AeroUIDist string // protocol/server/public/webui/dist
}

// FindDist locates web/user/dist + web/admin/dist + protocol webui (AIsys layout).
func FindDist() Paths {
	var roots []string
	if r := strings.TrimSpace(os.Getenv("WEB_ROOT")); r != "" {
		roots = append(roots, r)
	}
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots, wd, filepath.Join(wd, ".."), filepath.Join(wd, "..", ".."))
	}
	if ex, err := os.Executable(); err == nil {
		d := filepath.Dir(ex)
		roots = append(roots, d, filepath.Join(d, ".."), filepath.Join(d, "..", ".."))
	}
	var p Paths
	for _, root := range roots {
		try := func(rel ...string) string {
			fp := filepath.Join(append([]string{root}, rel...)...)
			if st, err := os.Stat(filepath.Join(fp, "index.html")); err == nil && !st.IsDir() {
				abs, _ := filepath.Abs(fp)
				return abs
			}
			return ""
		}
		if p.UserDist == "" {
			p.UserDist = try("vpn", "web", "user", "dist")
			if p.UserDist == "" {
				p.UserDist = try("web", "user", "dist")
			}
		}
		if p.AdminDist == "" {
			p.AdminDist = try("vpn", "web", "admin", "dist")
			if p.AdminDist == "" {
				p.AdminDist = try("web", "admin", "dist")
			}
		}
		if p.AeroUIDist == "" {
			candidates := [][]string{
				{"protocol", "server", "public", "webui", "dist"},
				{"..", "protocol", "server", "public", "webui", "dist"},
				{"web", "aero-ui", "dist"},
				{"protocol", "server", "webui", "dist"},
				{"..", "protocol", "server", "webui", "dist"},
				{"protocol", "webui", "dist"},
				{"..", "protocol", "webui", "dist"},
			}
			for _, parts := range candidates {
				if p.AeroUIDist = try(parts...); p.AeroUIDist != "" {
					break
				}
			}
		}
		if p.UserDist != "" && p.AdminDist != "" && p.AeroUIDist != "" {
			break
		}
	}
	return p
}

// Handler serves:
//
//	/aero-ui/* → aero modular console
//	/admin/*   → web/admin/dist
//	/*         → web/user/dist (/login 用户订阅)
func Handler(p Paths) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))

		if upath == "/aero-ui" || strings.HasPrefix(upath, "/aero-ui/") {
			if p.AeroUIDist == "" {
				http.Error(w, "protocol webui not built — npm run build in protocol/server/public/webui", 503)
				return
			}
			serveSPA(w, r, p.AeroUIDist, "/aero-ui")
			return
		}

		if upath == "/admin" || strings.HasPrefix(upath, "/admin/") {
			if p.AdminDist == "" {
				http.Error(w, "admin UI not built — npm run build in web/admin", 503)
				return
			}
			serveSPA(w, r, p.AdminDist, "/admin")
			return
		}

		if p.UserDist == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(missingHTML()))
			return
		}
		serveSPA(w, r, p.UserDist, "")
	})
}

// serveSPA: try real file under dist; otherwise index.html for SPA routes.
// urlPrefix is the public prefix stripped before looking up files (e.g. "/admin").
func serveSPA(w http.ResponseWriter, r *http.Request, distDir, urlPrefix string) {
	reqPath := r.URL.Path
	if urlPrefix != "" {
		reqPath = strings.TrimPrefix(reqPath, urlPrefix)
	}
	if reqPath == "" || reqPath == "/" {
		reqPath = "/index.html"
	}
	// prevent path escape
	rel := path.Clean("/" + strings.TrimPrefix(reqPath, "/"))
	full := filepath.Join(distDir, filepath.FromSlash(rel))
	// ensure still under distDir
	if !strings.HasPrefix(full, distDir) {
		http.NotFound(w, r)
		return
	}

	if st, err := os.Stat(full); err == nil && !st.IsDir() {
		http.ServeFile(w, r, full)
		return
	}
	// asset with extension missing → 404
	if ext := path.Ext(rel); ext != "" && ext != ".html" {
		http.NotFound(w, r)
		return
	}
	// SPA fallback
	http.ServeFile(w, r, filepath.Join(distDir, "index.html"))
}

func missingHTML() string {
	return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>vpsserver</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:40px;line-height:1.6}
a{color:#38bdf8}code{background:#1e293b;padding:2px 8px;border-radius:4px}</style></head>
<body>
<h1>前端尚未构建</h1>
<pre>cd web/user &amp;&amp; npm.cmd run build
cd web/admin &amp;&amp; npm.cmd run build</pre>
<p>或运行 <code>scripts/start.ps1</code></p>
<p><a href="/health">/health</a> · <a href="/login">/login</a> · <a href="/admin/">/admin/</a></p>
</body></html>`
}
