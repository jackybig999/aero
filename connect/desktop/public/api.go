package public

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
)

var (
	appLogs   []string
	appLogsMu sync.Mutex
)

func AddLog(msg string) {
	appLogsMu.Lock()
	defer appLogsMu.Unlock()
	appLogs = append(appLogs, msg)
	if len(appLogs) > 200 {
		appLogs = appLogs[len(appLogs)-200:]
	}
}

func getLogs() []string {
	appLogsMu.Lock()
	defer appLogsMu.Unlock()
	copied := make([]string, len(appLogs))
	copy(copied, appLogs)
	return copied
}

func clearLogs() {
	appLogsMu.Lock()
	defer appLogsMu.Unlock()
	appLogs = nil
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// StartServer initializes the config, sets the platform, sets up routes, and begins listening.
func StartServer(p Platform, configDir string, requestedPort int) (net.Listener, string, error) {
	InitConfig(configDir)
	SetPlatform(p)

	mux := http.NewServeMux()

	// ─── Proxy ─────────────────────────────────────────────────────────────
	mux.HandleFunc("/api/proxy/detect", func(w http.ResponseWriter, r *http.Request) {
		proxies, sp := DetectProxies(p)
		writeJSON(w, http.StatusOK, DetectResponse{
			Success:     true,
			Proxies:     proxies,
			SystemProxy: sp,
		})
	})

	// ─── AERO Engine ───────────────────────────────────────────────────────
	mux.HandleFunc("/api/aero/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, aeroCtrl.Status())
	})
	mux.HandleFunc("/api/aero/start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Sub string `json:"sub"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, http.StatusOK, aeroCtrl.Start(req.Sub))
	})
	mux.HandleFunc("/api/aero/stop", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, aeroCtrl.Stop())
	})

	// ─── App Launch ────────────────────────────────────────────────────────
	mux.HandleFunc("/api/app/launch", func(w http.ResponseWriter, r *http.Request) {
		var lp LaunchParams
		if err := json.NewDecoder(r.Body).Decode(&lp); err != nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		msg, err := Launch(p, lp)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		AddLog(msg)
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": msg})
	})

	mux.HandleFunc("/api/app/kill-all", func(w http.ResponseWriter, r *http.Request) {
		if p != nil {
			p.KillProcessGroup()
		}
		AddLog("已终止所有运行中的外部进程")
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	})

	// ─── Config (Shared config.json) ───────────────────────────────────────
	mux.HandleFunc("/api/config/apps", func(w http.ResponseWriter, r *http.Request) {
		cfg := GetConfig()
		tools := cfg.Tools
		res := make(map[string]interface{})
		for k, v := range tools {
			res[k] = map[string]interface{}{
				"command":  v.Command,
				"args":     v.Args,
				"cwd":      v.Cwd,
				"type":     v.Type,
				"proxyEnv": v.ProxyEnv,
			}
		}
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("/api/config/cwd", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			for k, v := range body {
				UpdateToolCwd(k, v)
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
			return
		}
		writeJSON(w, http.StatusOK, GetToolCwdMap())
	})

	mux.HandleFunc("/api/config/lang", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var b struct {
				Lang string `json:"lang"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b.Lang != "" {
				UpdateLang(b.Lang)
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "lang": b.Lang})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"lang": GetConfig().Lang})
	})

	mux.HandleFunc("/api/config/i18n", func(w http.ResponseWriter, r *http.Request) {
		lang := r.URL.Query().Get("lang")
		if lang == "" {
			lang = GetConfig().Lang
		}
		writeJSON(w, http.StatusOK, GetI18nDict(lang))
	})

	mux.HandleFunc("/api/config/trial", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"licensed": true,
			"valid":    true,
		})
	})

	// ─── System ────────────────────────────────────────────────────────────
	mux.HandleFunc("/api/system/browsers", func(w http.ResponseWriter, r *http.Request) {
		if p != nil {
			writeJSON(w, http.StatusOK, p.ScanBrowsers())
		} else {
			writeJSON(w, http.StatusOK, map[string]interface{}{})
		}
	})
	mux.HandleFunc("/api/system/desktop", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{})
	})
	mux.HandleFunc("/api/system/versions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"os":      runtime.GOOS + "/" + runtime.GOARCH,
			"version": "1.0.0",
		})
	})
	mux.HandleFunc("/api/system/select-directory", func(w http.ResponseWriter, r *http.Request) {
		home, _ := os.UserHomeDir()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"path":    home,
		})
	})
	mux.HandleFunc("/api/system/select-browser", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": false})
	})
	mux.HandleFunc("/api/system/tray-notify", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	})

	// ─── Logs ──────────────────────────────────────────────────────────────
	mux.HandleFunc("/api/log", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"logs":    getLogs(),
		})
	})
	mux.HandleFunc("/api/log/clear", func(w http.ResponseWriter, r *http.Request) {
		clearLogs()
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	})

	// ─── Third-Party API Providers ─────────────────────────────────────────
	mux.HandleFunc("/api/provider/list", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":   true,
			"providers": ListProviders(),
		})
	})
	mux.HandleFunc("/api/provider/save", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID      string `json:"id"`
			APIKey  string `json:"apiKey"`
			Model   string `json:"model"`
			BaseURL string `json:"baseUrl"`
			URLTag  string `json:"urlTag"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = SaveProvider(req.ID, req.APIKey, req.Model, req.BaseURL, req.URLTag)
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	})
	mux.HandleFunc("/api/provider/delete", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = DeleteProvider(req.ID)
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	})
	mux.HandleFunc("/api/provider/test", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID      string `json:"id"`
			BaseURL string `json:"baseUrl"`
			Fmt     string `json:"fmt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, http.StatusOK, TestProviderAPI(req.ID, req.BaseURL, req.Fmt))
	})
	mux.HandleFunc("/api/provider/models", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID      string `json:"id"`
			BaseURL string `json:"baseUrl"`
			Fmt     string `json:"fmt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		res := TestProviderAPI(req.ID, req.BaseURL, req.Fmt)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"models":  res["models"],
		})
	})
	mux.HandleFunc("/api/provider/apply", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID    string   `json:"id"`
			Tools []string `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, http.StatusOK, ApplyProvider(req.ID, req.Tools))
	})
	mux.HandleFunc("/api/provider/restore", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	})

	// ─── Static Web UI ─────────────────────────────────────────────────────
	rFS, err := GetRendererFS()
	if err == nil {
		fileServer := http.FileServer(http.FS(rFS))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fileServer.ServeHTTP(w, r)
		})
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "AI Runtime Manager Desktop")
		})
	}

	listenAddr := fmt.Sprintf("127.0.0.1:%d", requestedPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, "", err
	}

	actualPort := listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d/index.html", actualPort)

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()

	return listener, url, nil
}
