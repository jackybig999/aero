// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	Version  = "1.0.0"
	Protocol = "aero/3.0"
	APILevel = 3
)

// AdminHandler handles /admin/* management endpoints
type AdminHandler struct {
	adminKey   string
	validator  *Validator
	tokenStore *TokenStore
	subStore   *SubStore
	connLimit  *ConnLimiter
	bwLimit    *BandwidthLimiter
	dialGuard  *DialGuard
	quicServer *QUICServer
	startedAt  time.Time
}

// NewAdminHandler creates an AdminHandler
func NewAdminHandler(key string, v *Validator, ts *TokenStore, ss *SubStore, cl *ConnLimiter, bl *BandwidthLimiter, dg *DialGuard) *AdminHandler {
	return &AdminHandler{
		adminKey:   key,
		validator:  v,
		tokenStore: ts,
		subStore:   ss,
		connLimit:  cl,
		bwLimit:    bl,
		dialGuard:  dg,
		startedAt:  time.Now(),
	}
}

// SetQUICServer links the QUICServer instance for disaster-recovery policy inspection.
func (h *AdminHandler) SetQUICServer(qs *QUICServer) {
	h.quicServer = qs
}

func (h *AdminHandler) isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (h *AdminHandler) adminOK(r *http.Request) bool {
	if h.isLoopback(r) {
		return true
	}
	if h.adminKey == "" {
		return false
	}
	key := r.Header.Get("X-Aero-Admin-Key")
	if key == "" {
		key = r.URL.Query().Get("key")
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(h.adminKey)) == 1
}

// TryServe processes /admin/* requests. Returns false if path does not start with /admin.
func (h *AdminHandler) TryServe(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/admin") {
		return false
	}
	if !h.adminOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return true
	}

	switch {
	case r.URL.Path == "/admin/version" && r.Method == http.MethodGet:
		writeJSON(w, map[string]any{
			"version":   Version,
			"protocol":  Protocol,
			"api_level": APILevel,
		})
	case r.URL.Path == "/admin/status" && r.Method == http.MethodGet:
		h.handleStatus(w)
	case r.URL.Path == "/admin/tokens" && r.Method == http.MethodGet:
		h.handleListTokens(w)
	case r.URL.Path == "/admin/tokens" && r.Method == http.MethodPost:
		h.handleAddToken(w, r)
	case r.URL.Path == "/admin/tokens" && r.Method == http.MethodDelete:
		h.handleDelToken(w, r)
	case r.URL.Path == "/admin/subs" && r.Method == http.MethodGet:
		h.handleListSubs(w)
	case r.URL.Path == "/admin/subs" && r.Method == http.MethodPost:
		h.handleUpsertSubs(w, r)
	case r.URL.Path == "/admin/subs" && r.Method == http.MethodDelete:
		h.handleDeleteSub(w, r)
	case r.URL.Path == "/admin/reload" && r.Method == http.MethodPost:
		h.handleReload(w)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

func (h *AdminHandler) handleStatus(w http.ResponseWriter) {
	active := int64(0)
	maxG, maxU := int64(0), int64(0)
	if h.connLimit != nil {
		active = h.connLimit.Active()
		maxG = h.connLimit.MaxGlobal()
		maxU = h.connLimit.MaxPerTok()
	}
	bw := 0.0
	if h.bwLimit != nil {
		bw = h.bwLimit.Rate()
	}
	dialCap := 0
	if h.dialGuard != nil {
		dialCap = h.dialGuard.Cap()
	}
	body := map[string]any{
		"ok":             true,
		"version":        Version,
		"protocol":       Protocol,
		"api_level":      APILevel,
		"active_tunnels": active,
		"max_conn":       maxG,
		"max_conn_user":  maxU,
		"token_count":    h.validator.Count(),
		"bw_per_user":    bw,
		"max_dial":       dialCap,
		"uptime_sec":     time.Since(h.startedAt).Seconds(),
	}
	if h.quicServer != nil {
		policy := h.quicServer.OfflinePolicy()
		body["offline_policy"] = map[string]any{
			"grace_period_sec": policy.GracePeriod.Seconds(),
			"max_burst_bytes":  policy.MaxBurstPerToken,
		}
	}
	writeJSON(w, body)
}

func (h *AdminHandler) handleListTokens(w http.ResponseWriter) {
	var list []TokenRecord
	if h.tokenStore != nil {
		list = h.tokenStore.List()
	} else {
		for _, t := range h.validator.ListTokens() {
			list = append(list, TokenRecord{
				Token:     t.Token,
				Label:     t.Label,
				CreatedAt: t.CreatedAt,
				ExpiresAt: t.ExpiresAt,
			})
		}
	}
	writeJSON(w, map[string]any{"tokens": list, "count": len(list)})
}

type addTokenAdminReq struct {
	Token    string `json:"token"`
	Label    string `json:"label"`
	TTLHours int    `json:"ttl_hours"`
}

func (h *AdminHandler) handleAddToken(w http.ResponseWriter, r *http.Request) {
	var req addTokenAdminReq
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid json body: " + err.Error()})
			return
		}
	}
	ttl := time.Duration(req.TTLHours) * time.Hour
	if ttl <= 0 {
		ttl = 365 * 24 * time.Hour
	}
	var tok string
	var err error
	if h.tokenStore != nil {
		tok, err = h.tokenStore.AddReturn(req.Token, req.Label, ttl)
	} else {
		tok = req.Token
		if tok == "" {
			tok, err = GenerateToken()
		}
		if err == nil {
			h.validator.AddToken(tok, req.Label, ttl)
		}
	}
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "token": tok, "label": req.Label})
}

func (h *AdminHandler) handleDelToken(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	var err error
	if h.tokenStore != nil {
		err = h.tokenStore.Remove(tok)
	} else {
		h.validator.RemoveToken(tok)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "removed": tok})
}

func (h *AdminHandler) handleListSubs(w http.ResponseWriter) {
	if h.subStore == nil {
		writeJSON(w, map[string]any{"subs": []any{}, "count": 0})
		return
	}
	subs := h.subStore.ListUserSubs()
	writeJSON(w, map[string]any{
		"subs":       subs,
		"count":      len(subs),
		"legacy_sub": "/sub/" + h.subStore.Secret(),
	})
}

type upsertSubsAdminReq struct {
	Username string      `json:"username"`
	Slug     string      `json:"slug"`
	Token    string      `json:"token"`
	ExpireAt int64       `json:"expire_at"`
	Servers  []SubServer `json:"servers"`
	Subs     []UserSub   `json:"subs"`
}

func (h *AdminHandler) handleUpsertSubs(w http.ResponseWriter, r *http.Request) {
	if h.subStore == nil {
		http.Error(w, "subscription store unavailable", http.StatusServiceUnavailable)
		return
	}
	var req upsertSubsAdminReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	toProcess := req.Subs
	if req.Slug != "" {
		toProcess = append(toProcess, UserSub{
			Username: req.Username,
			Slug:     req.Slug,
			Token:    req.Token,
			ExpireAt: req.ExpireAt,
			Servers:  req.Servers,
		})
	}
	if len(toProcess) == 0 {
		http.Error(w, "no subscriptions provided", http.StatusBadRequest)
		return
	}

	synced := 0
	for _, item := range toProcess {
		if item.Slug == "" {
			continue
		}
		if err := h.subStore.UpsertUserSub(item); err != nil {
			http.Error(w, "upsert failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Mount user token into TokenStore and Validator immediately
		if item.Token != "" {
			ttl := 365 * 24 * time.Hour
			if item.ExpireAt > time.Now().Unix() {
				ttl = time.Duration(item.ExpireAt-time.Now().Unix()) * time.Second
			}
			label := "user:" + item.Username
			if item.Username == "" {
				label = "user:" + item.Slug
			}
			if h.tokenStore != nil {
				_, _ = h.tokenStore.AddReturn(item.Token, label, ttl)
			} else if h.validator != nil {
				h.validator.AddToken(item.Token, label, ttl)
			}
		}
		synced++
	}
	writeJSON(w, map[string]any{"ok": true, "synced_count": synced})
}

func (h *AdminHandler) handleDeleteSub(w http.ResponseWriter, r *http.Request) {
	if h.subStore == nil {
		http.Error(w, "subscription store unavailable", http.StatusServiceUnavailable)
		return
	}
	slug := r.URL.Query().Get("slug")
	if slug == "" {
		http.Error(w, "slug required", http.StatusBadRequest)
		return
	}
	if sub, ok := h.subStore.GetUserSub(slug); ok && sub.Token != "" {
		if h.tokenStore != nil {
			_ = h.tokenStore.Remove(sub.Token)
		} else if h.validator != nil {
			h.validator.RemoveToken(sub.Token)
		}
	}
	if err := h.subStore.DeleteUserSub(slug); err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "deleted_slug": slug})
}

func (h *AdminHandler) handleReload(w http.ResponseWriter) {
	if h.tokenStore == nil {
		http.Error(w, "no token store", http.StatusServiceUnavailable)
		return
	}
	n, err := h.tokenStore.Reload()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "token_count": n})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// Revoke removes a token from TokenStore and Validator, persisting changes to disk.
func (s *TokenStore) Revoke(token string) error {
	return s.Remove(token)
}
