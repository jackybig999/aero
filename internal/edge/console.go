// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//go:embed web/console.html
var consoleHTML []byte

//go:embed web/console.css
var consoleCSS []byte

//go:embed web/console.js
var consoleJS []byte

var validUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_@.-]{2,64}$`)
var validCodeRegex = regexp.MustCompile(`^[a-z0-9]{6}$`)

// ConsoleHandler provides the embedded Web Console routes, authentication, and REST APIs.
type ConsoleHandler struct {
	adminKey         string
	server           *Server
	dialGuard        *DialGuard
	tokenStore       *TokenStore
	subStore         *SubStore
	metricsCollector *MetricsCollector
	purityEngine     *PurityEngine
	warpInstaller    *WarpInstaller
	coverRenderer    func(http.ResponseWriter, *http.Request)
}

// NewConsoleHandler instantiates the Web Console handler.
func NewConsoleHandler(
	adminKey string,
	server *Server,
	dialGuard *DialGuard,
	tokenStore *TokenStore,
	subStore *SubStore,
	metricsCollector *MetricsCollector,
	purityEngine *PurityEngine,
	warpInstaller *WarpInstaller,
	coverRenderer func(http.ResponseWriter, *http.Request),
) *ConsoleHandler {
	return &ConsoleHandler{
		adminKey:         strings.TrimSpace(adminKey),
		server:           server,
		dialGuard:        dialGuard,
		tokenStore:       tokenStore,
		subStore:         subStore,
		metricsCollector: metricsCollector,
		purityEngine:     purityEngine,
		warpInstaller:    warpInstaller,
		coverRenderer:    coverRenderer,
	}
}

// authenticate validates the request against the configured admin key in constant-time.
func (h *ConsoleHandler) authenticate(r *http.Request) bool {
	// 1. Authorization: Bearer <key>
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		key := strings.TrimPrefix(auth, "Bearer ")
		if h.checkKey(key) {
			return true
		}
	}
	// 2. Custom header: X-Aero-Admin-Key or Aero-Admin-Key
	if key := r.Header.Get("X-Aero-Admin-Key"); key != "" {
		if h.checkKey(key) {
			return true
		}
	}
	if key := r.Header.Get("Aero-Admin-Key"); key != "" {
		if h.checkKey(key) {
			return true
		}
	}
	// 3. Query param: ?key=... or ?admin_key=...
	if key := r.URL.Query().Get("key"); key != "" {
		if h.checkKey(key) {
			return true
		}
	}
	if key := r.URL.Query().Get("admin_key"); key != "" {
		if h.checkKey(key) {
			return true
		}
	}
	// 4. Session cookie: aero_key=...
	if c, err := r.Cookie("aero_key"); err == nil && c.Value != "" {
		if h.checkKey(c.Value) {
			return true
		}
	}
	// 5. Loopback fallback when no adminKey is configured
	if h.adminKey == "" {
		return h.isLoopback(r)
	}
	return false
}

func (h *ConsoleHandler) checkKey(key string) bool {
	key = strings.TrimSpace(key)
	if h.adminKey == "" || key == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(h.adminKey)) == 1
}

func (h *ConsoleHandler) isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// TryServe processes /console requests. Returns false if path does not match /console.
func (h *ConsoleHandler) TryServe(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/console" && !strings.HasPrefix(p, "/console/") {
		return false
	}

	// Active probing camouflage: unauthorized requests return decoy cover page
	if !h.authenticate(r) {
		if strings.HasPrefix(p, "/console/api/") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"ok":false,"error":"forbidden","code":403}`))
			return true
		}
		if h.coverRenderer != nil {
			h.coverRenderer(w, r)
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
		}
		return true
	}

	switch {
	case p == "/console" || p == "/console/":
		// Set HttpOnly session cookie if key is present in query parameter
		if key := r.URL.Query().Get("key"); key != "" && h.checkKey(key) {
			http.SetCookie(w, &http.Cookie{
				Name:     "aero_key",
				Value:    key,
				Path:     "/console",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   86400,
			})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(consoleHTML)
		return true

	case p == "/console/web/console.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "private, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(consoleCSS)
		return true

	case p == "/console/web/console.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "private, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(consoleJS)
		return true

	case p == "/console/api/status" && r.Method == http.MethodGet:
		h.handleAPIStatus(w, r)
		return true

	case p == "/console/api/purity" && r.Method == http.MethodGet:
		h.handleAPIPurity(w, r)
		return true

	case p == "/console/api/warp/install" && r.Method == http.MethodPost:
		h.handleAPIWarpInstall(w, r)
		return true

	case p == "/console/api/warp/uninstall" && r.Method == http.MethodPost:
		h.handleAPIWarpUninstall(w, r)
		return true

	case p == "/console/api/warp/logs" && r.Method == http.MethodGet:
		h.handleAPIWarpLogs(w, r)
		return true

	case p == "/console/api/warp/toggle" && r.Method == http.MethodPost:
		h.handleAPIWarpToggle(w, r)
		return true

	case p == "/console/api/geodata/update" && r.Method == http.MethodPost:
		h.handleAPIGeoDataUpdate(w, r)
		return true

	case p == "/console/api/users" && r.Method == http.MethodGet:
		h.handleAPIListUsers(w, r)
		return true

	case p == "/console/api/users" && r.Method == http.MethodPost:
		h.handleAPICreateUser(w, r)
		return true

	case p == "/console/api/users" && r.Method == http.MethodDelete:
		h.handleAPIDeleteUser(w, r)
		return true

	default:
		http.NotFound(w, r)
		return true
	}
}

func (h *ConsoleHandler) primaryDomain() string {
	if h.server != nil && h.server.cfg.Domain != "" {
		return h.server.cfg.Domain
	}
	if h.server != nil && h.server.cfg.AdvertiseHost != "" {
		return h.server.cfg.AdvertiseHost
	}
	if h.subStore != nil {
		doc := h.subStore.Document()
		if len(doc.Servers) > 0 {
			if doc.Servers[0].Host != "" {
				return doc.Servers[0].Host
			}
			if doc.Servers[0].SNI != "" {
				return doc.Servers[0].SNI
			}
		}
	}
	return "localhost"
}

func (h *ConsoleHandler) listenPort() int {
	if h.server != nil && h.server.cfg.Listen != "" {
		if _, portStr, err := net.SplitHostPort(h.server.cfg.Listen); err == nil {
			if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
				return p
			}
		}
	}
	if h.subStore != nil {
		doc := h.subStore.Document()
		if len(doc.Servers) > 0 && doc.Servers[0].Address != "" {
			if _, portStr, err := net.SplitHostPort(doc.Servers[0].Address); err == nil {
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
					return p
				}
			}
		}
	}
	return 443
}

func (h *ConsoleHandler) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	domain := h.primaryDomain()
	listen := ":443"
	var uptimeSec float64
	var activeTunnels int
	var maxConn int = DefaultMaxGlobal
	var tokenCount int

	if h.server != nil {
		listen = h.server.cfg.Listen
		uptimeSec = time.Since(h.server.startedAt).Seconds()
		if h.server.connLimit != nil {
			activeTunnels = int(h.server.connLimit.Active())
		}
		if h.server.cfg.MaxConn > 0 {
			maxConn = h.server.cfg.MaxConn
		}
	}
	if h.tokenStore != nil && h.tokenStore.v != nil {
		tokenCount = h.tokenStore.v.Count()
	}

	// Cert info
	certInfo := map[string]any{
		"domain":         domain,
		"status":         "valid",
		"auto_reload":    true,
		"is_self_signed": false,
		"days_left":      60,
		"days_remaining": 60,
	}
	if h.server != nil {
		if cert := h.server.CurrentCert(); cert != nil && len(cert.Certificate) > 0 {
			if parsed, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
				until := time.Until(parsed.NotAfter)
				certInfo["domain"] = parsed.Subject.CommonName
				certInfo["not_after"] = parsed.NotAfter.Format(time.RFC3339)
				certInfo["expires_at"] = parsed.NotAfter.Unix()
				if until <= 0 {
					daysLeft := int64(until.Hours() / 24)
					certInfo["status"] = "expired"
					certInfo["days_left"] = daysLeft
					certInfo["days_remaining"] = daysLeft
				} else {
					daysLeft := int64(math.Ceil(until.Hours() / 24.0))
					certInfo["status"] = "valid"
					certInfo["days_left"] = daysLeft
					certInfo["days_remaining"] = daysLeft
				}
				if parsed.Issuer.CommonName == parsed.Subject.CommonName {
					certInfo["is_self_signed"] = true
				}
			}
		}
	}

	// VPS Metrics
	var vpsMetrics *SystemMetrics
	if h.metricsCollector != nil {
		vpsMetrics = h.metricsCollector.GetMetrics()
	}
	if vpsMetrics == nil {
		vpsMetrics, _ = collectPlatformMetrics(nil)
	}

	// WARP Status
	var warpProxy string
	var warpAll, warpEnabled, warpHealthy bool
	if h.dialGuard != nil {
		warpProxy, warpAll, warpEnabled, warpHealthy = h.dialGuard.GetWarpStatus()
	}

	// 管理员订阅 URL（免端口）：仅在已鉴权的控制台返回，路径为不可猜测的 secret。
	adminURL := ""
	if h.subStore != nil && h.subStore.Secret() != "" {
		adminURL = FormatZeroPortSubURL(domain, h.subStore.Secret())
	}

	var userCount int
	if h.subStore != nil {
		userCount = len(h.subStore.ListUserSubs())
	}

	resp := map[string]any{
		"ok":         true,
		"version":    Version,
		"protocol":   Protocol,
		"domain":     domain,
		"listen":     listen,
		"uptime_sec": uptimeSec,
		"node": map[string]any{
			"version":        Version,
			"protocol":       Protocol,
			"api_level":      APILevel,
			"domain":         domain,
			"listen":         listen,
			"active_tunnels": activeTunnels,
			"max_conn":       maxConn,
			"token_count":    tokenCount,
			"uptime_sec":     uptimeSec,
		},
		"vps":           vpsMetrics,
		"system":        vpsMetrics,
		"cert":          certInfo,
		"admin_sub_url": adminURL,
		"admin_sub": map[string]any{
			"url":                 adminURL,
			"expire_at":           int64(0),
			"traffic_limit_bytes": int64(0),
		},
		"warp": map[string]any{
			"installed":        warpEnabled || (h.warpInstaller != nil && (h.warpInstaller.GetStatus().Bypassed || h.warpInstaller.IsInstalled())),
			"running":          warpEnabled,
			"active":           warpEnabled,
			"proxy_addr":       warpProxy,
			"warp_all":         warpAll,
			"smart_routing":    warpEnabled && !warpAll,
			"healthy":          warpHealthy,
			"update_available": false,
		},
		"geodata": func() map[string]any {
			if h.server != nil && h.server.geoHandler != nil {
				rulesCount, lastUpdate, etag := h.server.geoHandler.GetStatus()
				return map[string]any{
					"rules_count":  rulesCount,
					"last_updated": lastUpdate.Unix(),
					"etag":         etag,
				}
			}
			return map[string]any{
				"rules_count":  0,
				"last_updated": int64(0),
				"etag":         "",
			}
		}(),
		"stats": map[string]any{
			"active_tunnels": activeTunnels,
			"max_conn":       maxConn,
			"user_sub_count": userCount,
		},
	}

	writeJSON(w, resp)
}

func (h *ConsoleHandler) handleAPIGeoDataUpdate(w http.ResponseWriter, r *http.Request) {
	if h.server == nil || h.server.geoHandler == nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"ok":false,"error":"geodata handler not available"}`))
		return
	}
	if err := h.server.geoHandler.ForceUpdate(r.Context()); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error())))
		return
	}
	rulesCount, lastUpdate, etag := h.server.geoHandler.GetStatus()
	writeJSON(w, map[string]any{
		"ok":           true,
		"rules_count":  rulesCount,
		"last_updated": lastUpdate.Unix(),
		"etag":         etag,
	})
}

func (h *ConsoleHandler) handleAPIPurity(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"
	if h.purityEngine == nil {
		h.purityEngine = NewPurityEngine("127.0.0.1:40000")
	}
	report, err := h.purityEngine.Probe(r.Context(), force)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error())))
		return
	}
	resp := map[string]any{
		"ok":                   true,
		"score":                report.Score,
		"purity_score":         report.Score,
		"ip_country":           report.IPCountry,
		"youtube_loc":          report.YouTubeLoc,
		"google_clean":         report.GoogleClean,
		"google_hk_redirect":   report.GoogleHKRedirect,
		"cf_clean":             report.CFClean,
		"native_gemini_ok":     report.NativeGeminiOK,
		"gemini_country":       report.GeminiCountry,
		"warp_installed":       report.WARPInstalled,
		"warp_running":         report.WARPRunning,
		"warp_gemini_ok":       report.WARPGeminiOK,
		"gemini_ok":            report.GeminiOK,
		"is_cn_marked":         report.IsCNMarked,
		"is_region_mismatched": report.IsRegionMismatched,
		"ai_blocked":           report.AIBlocked,
		"is_warp_egress":       report.IsWARPEgress,
		"last_probe_at":        report.LastProbeAt,
		"probe_duration_ms":    report.ProbeDurationMs,
	}
	if report.ProbeError != "" {
		resp["probe_error"] = report.ProbeError
	}
	writeJSON(w, resp)
}

func (h *ConsoleHandler) handleAPIWarpInstall(w http.ResponseWriter, r *http.Request) {
	if h.warpInstaller == nil {
		h.warpInstaller = NewWarpInstaller(h.dialGuard)
	}
	status, bypassed, err := h.warpInstaller.StartInstall(r.Context())
	if errors.Is(err, ErrInstallInProgress) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"ok":false,"status":"running","error":"installation already in progress"}`))
		return
	}
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error())))
		return
	}

	if bypassed {
		writeJSON(w, map[string]any{
			"ok":       true,
			"status":   "already_active",
			"bypassed": true,
			"message":  "Cloudflare WARP proxy 127.0.0.1:40000 is already active; installation bypassed to preserve configuration.",
		})
		return
	}

	writeJSON(w, map[string]any{
		"ok":       true,
		"status":   status,
		"bypassed": false,
		"message":  "Cloudflare WARP silent installation pipeline started.",
	})
}

func (h *ConsoleHandler) handleAPIWarpUninstall(w http.ResponseWriter, r *http.Request) {
	if h.warpInstaller == nil {
		h.warpInstaller = NewWarpInstaller(h.dialGuard)
	}
	status, err := h.warpInstaller.StartUninstall(r.Context())
	if err != nil {
		if errors.Is(err, ErrInstallInProgress) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"ok":false,"error":"installation or uninstallation already in progress"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":"%s"}`, err.Error())))
		return
	}

	writeJSON(w, map[string]any{
		"ok":      true,
		"status":  status,
		"message": "Cloudflare WARP uninstallation pipeline started.",
	})
}

func (h *ConsoleHandler) handleAPIWarpLogs(w http.ResponseWriter, r *http.Request) {
	if h.warpInstaller == nil {
		h.warpInstaller = NewWarpInstaller(h.dialGuard)
	}
	st := h.warpInstaller.GetStatus()
	writeJSON(w, map[string]any{
		"ok":        true,
		"status":    st.Status,
		"progress":  st.Progress,
		"step":      st.Step,
		"step_desc": st.StepDesc,
		"bypassed":  st.Bypassed,
		"error":     st.Error,
		"logs":      st.Logs,
	})
}

type warpToggleRequest struct {
	Enabled  *bool `json:"enabled"`
	WarpAll  *bool `json:"warp_all"`
	CamelAll *bool `json:"warpAll"`
}

func (h *ConsoleHandler) handleAPIWarpToggle(w http.ResponseWriter, r *http.Request) {
	var req warpToggleRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":"invalid request json: %s"}`, err.Error())))
		return
	}

	if req.Enabled != nil && *req.Enabled {
		// Verify port 40000 is open
		conn, err := net.DialTimeout("tcp", "127.0.0.1:40000", 350*time.Millisecond)
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"ok":false,"error":"WARP local port 40000 is not active. Please install and start WARP first."}`))
			return
		}
		_ = conn.Close()

		warpAll := true
		if req.WarpAll != nil {
			warpAll = *req.WarpAll
		} else if req.CamelAll != nil {
			warpAll = *req.CamelAll
		}
		if h.dialGuard != nil {
			h.dialGuard.SetWarpProxy("127.0.0.1:40000", warpAll)
		}
	} else if req.Enabled != nil && !*req.Enabled {
		if h.dialGuard != nil {
			h.dialGuard.SetWarpProxy("", false)
		}
	}

	var proxy string
	var all, enabled, healthy bool
	if h.dialGuard != nil {
		proxy, all, enabled, healthy = h.dialGuard.GetWarpStatus()
	}

	writeJSON(w, map[string]any{
		"ok":           true,
		"warp_enabled": enabled,
		"warp_proxy":   proxy,
		"warp_all":     all,
		"warp_healthy": healthy,
	})
}

// CreateUserRequest supports strict JSON validation with dual snake_case and camelCase.
type CreateUserRequest struct {
	Username          string `json:"username"`
	Code              string `json:"code,omitempty"`
	ExpireDays        int    `json:"expire_days"`
	ExpireAt          int64  `json:"expire_at"`
	TrafficLimitGB    int64  `json:"traffic_limit_gb"`
	TrafficLimitBytes int64  `json:"traffic_limit_bytes"`
}

func (r *CreateUserRequest) UnmarshalJSON(data []byte) error {
	type Alias CreateUserRequest
	aux := struct {
		*Alias
		CamelCode         string `json:"code"`
		CamelExpireDays   int    `json:"expireDays"`
		CamelExpireAt     int64  `json:"expireAt"`
		CamelTrafficGB    int64  `json:"trafficLimitGb"`
		CamelTrafficBytes int64  `json:"trafficLimitBytes"`
	}{
		Alias: (*Alias)(r),
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&aux); err != nil {
		return fmt.Errorf("decode create user request: %w", err)
	}
	if r.Code == "" && aux.CamelCode != "" {
		r.Code = aux.CamelCode
	}
	if r.ExpireDays == 0 && aux.CamelExpireDays != 0 {
		r.ExpireDays = aux.CamelExpireDays
	}
	if r.ExpireAt == 0 && aux.CamelExpireAt != 0 {
		r.ExpireAt = aux.CamelExpireAt
	}
	if r.TrafficLimitGB == 0 && aux.CamelTrafficGB != 0 {
		r.TrafficLimitGB = aux.CamelTrafficGB
	}
	if r.TrafficLimitBytes == 0 && aux.CamelTrafficBytes != 0 {
		r.TrafficLimitBytes = aux.CamelTrafficBytes
	}
	return nil
}

func (r *CreateUserRequest) ValidateAndNormalize() error {
	r.Username = strings.TrimSpace(r.Username)
	if r.Username == "" {
		return fmt.Errorf("username required")
	}
	if !validUsernameRegex.MatchString(r.Username) {
		return fmt.Errorf("invalid username format (alphanumeric, underscore, hyphen, dot, @, length 2-64)")
	}
	if r.Code != "" {
		r.Code = strings.ToLower(strings.TrimSpace(r.Code))
		if !validCodeRegex.MatchString(r.Code) {
			return fmt.Errorf("invalid code format: must be 6 lowercase alphanumeric characters")
		}
	}
	now := time.Now().Unix()
	if r.ExpireAt == 0 && r.ExpireDays > 0 {
		r.ExpireAt = now + int64(r.ExpireDays)*86400
	}
	if r.TrafficLimitBytes == 0 && r.TrafficLimitGB > 0 {
		r.TrafficLimitBytes = r.TrafficLimitGB * 1024 * 1024 * 1024
	}
	return nil
}

func (h *ConsoleHandler) handleAPICreateUser(w http.ResponseWriter, r *http.Request) {
	if h.subStore == nil || h.tokenStore == nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"ok":false,"error":"sub store or token store uninitialized"}`))
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error())))
		return
	}
	if err := req.ValidateAndNormalize(); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error())))
		return
	}

	// Generate 6-char random code if not provided
	code := req.Code
	if code == "" {
		c, err := randomHexCode(6)
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":"generate random code: %s"}`, err.Error())))
			return
		}
		code = c
	}

	slug := req.Username + code

	// Calculate token TTL (default 100 years for permanent valid subscriptions)
	ttl := 100 * 365 * 24 * time.Hour
	if req.ExpireAt > 0 {
		rem := time.Until(time.Unix(req.ExpireAt, 0))
		if rem > 0 {
			ttl = rem
		}
	}

	// Generate & register user token
	token, err := h.tokenStore.AddReturn("", "user:"+slug, ttl)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":"add user token: %s"}`, err.Error())))
		return
	}

	// Persist UserSub
	now := time.Now().Unix()
	userSub := UserSub{
		Username:          req.Username,
		Slug:              slug,
		Token:             token,
		ExpireAt:          req.ExpireAt,
		TrafficLimitBytes: req.TrafficLimitBytes,
		TrafficUsedBytes:  0,
		CreatedAt:         now,
	}
	if err := h.subStore.UpsertUserSub(userSub); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":"upsert user sub: %s"}`, err.Error())))
		return
	}

	domain := h.primaryDomain()
	subURL := FormatZeroPortSubURL(domain, slug)
	directSubURL := FormatDirectSubURL(domain, h.listenPort(), slug)

	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]any{
		"ok":                  true,
		"username":            req.Username,
		"slug":                slug,
		"sub_url":             subURL,
		"direct_sub_url":      directSubURL,
		"token":               token,
		"expire_at":           req.ExpireAt,
		"traffic_limit_bytes": req.TrafficLimitBytes,
		"created_at":          now,
	})
}

func (h *ConsoleHandler) handleAPIListUsers(w http.ResponseWriter, r *http.Request) {
	if h.subStore == nil {
		writeJSON(w, map[string]any{"ok": true, "count": 0, "users": []any{}})
		return
	}

	domain := h.primaryDomain()
	listenPort := h.listenPort()
	userSubs := h.subStore.ListUserSubs()
	out := make([]map[string]any, 0, len(userSubs))
	now := time.Now().Unix()

	for _, u := range userSubs {
		isExpired := u.ExpireAt > 0 && now > u.ExpireAt
		isOverQuota := u.TrafficLimitBytes > 0 && u.TrafficUsedBytes >= u.TrafficLimitBytes
		status := "active"
		if isExpired {
			status = "expired"
		} else if isOverQuota {
			status = "quota_exceeded"
		}

		subURL := FormatZeroPortSubURL(domain, u.Slug)
		directSubURL := FormatDirectSubURL(domain, listenPort, u.Slug)
		out = append(out, map[string]any{
			"username":            u.Username,
			"slug":                u.Slug,
			"sub_url":             subURL,
			"direct_sub_url":      directSubURL,
			"expire_at":           u.ExpireAt,
			"traffic_limit_bytes": u.TrafficLimitBytes,
			"traffic_used_bytes":  u.TrafficUsedBytes,
			"is_expired":          isExpired,
			"is_traffic_exceeded": isOverQuota,
			"status":              status,
			"created_at":          u.CreatedAt,
		})
	}

	writeJSON(w, map[string]any{
		"ok":    true,
		"count": len(out),
		"users": out,
	})
}

func (h *ConsoleHandler) handleAPIDeleteUser(w http.ResponseWriter, r *http.Request) {
	if h.subStore == nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"ok":false,"error":"user store not ready"}`))
		return
	}

	slug := strings.TrimSpace(r.URL.Query().Get("slug"))
	username := strings.TrimSpace(r.URL.Query().Get("username"))

	if slug == "" && username == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error":"missing slug or username parameter"}`))
		return
	}

	targetSlug := slug
	var foundSub UserSub
	var found bool

	if targetSlug != "" {
		foundSub, found = h.subStore.GetUserSub(targetSlug)
	} else {
		// Search by username
		for _, u := range h.subStore.ListUserSubs() {
			if u.Username == username {
				targetSlug = u.Slug
				foundSub = u
				found = true
				break
			}
		}
	}

	if !found {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"ok":false,"error":"user not found"}`))
		return
	}

	// Purge token
	if foundSub.Token != "" && h.tokenStore != nil {
		_ = h.tokenStore.Remove(foundSub.Token)
	}
	// Delete sub
	if err := h.subStore.DeleteUserSub(targetSlug); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":"delete sub: %s"}`, err.Error())))
		return
	}

	writeJSON(w, map[string]any{
		"ok":           true,
		"deleted_slug": targetSlug,
	})
}

func randomHexCode(n int) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	var sb strings.Builder
	sb.Grow(n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		sb.WriteByte(chars[num.Int64()])
	}
	return sb.String(), nil
}
