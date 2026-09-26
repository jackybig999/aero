// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aero-protocol/aero-edge/public/internal/auth"
	"github.com/aero-protocol/aero-edge/public/internal/cover"
	"github.com/aero-protocol/aero-edge/public/internal/subscribe"
)

func (h *edgeHandler) adminOK(r *http.Request) bool {
	if cover.IsLoopback(r) {
		return true
	}
	if h.adminKey == "" {
		return false
	}
	key := r.Header.Get("X-Aero-Admin-Key")
	if key == "" {
		key = r.URL.Query().Get("key")
	}
	return subtleEqual(key, h.adminKey)
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// tryAdmin 处理 /admin/*（v1 冻结路径）
func (h *edgeHandler) tryAdmin(w http.ResponseWriter, r *http.Request) bool {
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
			"version": Version, "protocol": Protocol, "api_level": APILevel,
		})
	case r.URL.Path == "/admin/status" && r.Method == http.MethodGet:
		h.adminStatus(w)
	case r.URL.Path == "/admin/tokens" && r.Method == http.MethodGet:
		h.adminListTokens(w)
	case r.URL.Path == "/admin/tokens" && r.Method == http.MethodPost:
		h.adminAddToken(w, r)
	case r.URL.Path == "/admin/tokens" && r.Method == http.MethodDelete:
		h.adminDelToken(w, r)
	case r.URL.Path == "/admin/subs" && r.Method == http.MethodGet:
		h.adminListSubs(w)
	case r.URL.Path == "/admin/subs" && r.Method == http.MethodPost:
		h.adminUpsertSubs(w, r)
	case r.URL.Path == "/admin/subs" && r.Method == http.MethodDelete:
		h.adminDeleteSub(w, r)
	case r.URL.Path == "/admin/reload" && r.Method == http.MethodPost:
		h.adminReload(w)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

func (h *edgeHandler) adminStatus(w http.ResponseWriter) {
	snap := h.metrics.Snapshot()
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
		"ok":               true,
		"version":          Version,
		"protocol":         Protocol,
		"api_level":        APILevel,
		"active_tunnels":   active,
		"max_conn":         maxG,
		"max_conn_user":    maxU,
		"token_count":      h.validator.Count(),
		"metrics":          snap,
		"draining":         h.draining.Load(),
		"idle_timeout_sec": int(h.idleTimeout.Seconds()),
		"max_life_sec":     int(h.maxLife.Seconds()),
		"bw_per_user":      bw,
		"max_dial":         dialCap,
		"uptime_sec":       time.Since(h.startedAt).Seconds(),
	}
	if h.certMgr != nil {
		info := h.certMgr.Info()
		if !info.NotAfter.IsZero() {
			body["cert_not_after"] = info.NotAfter.UTC().Format(time.RFC3339)
			body["cert_days_left"] = info.DaysLeft
			body["cert_issuer"] = info.Issuer
		}
	}
	writeJSON(w, body)
}

func (h *edgeHandler) adminListTokens(w http.ResponseWriter) {
	var list []auth.Record
	if h.tokenStore != nil {
		list = h.tokenStore.List()
	} else {
		for _, t := range h.validator.ListTokens() {
			list = append(list, auth.Record{
				Token: t.Token, Label: t.Label, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
			})
		}
	}
	writeJSON(w, map[string]any{"tokens": list, "count": len(list)})
}

type addTokenReq struct {
	Token    string `json:"token"`
	Label    string `json:"label"`
	TTLHours int    `json:"ttl_hours"`
}

func (h *edgeHandler) adminAddToken(w http.ResponseWriter, r *http.Request) {
	var req addTokenReq
	_ = json.NewDecoder(r.Body).Decode(&req)
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
			tok = auth.GenerateToken()
		}
		h.validator.AddToken(tok, req.Label, ttl)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "token": tok, "label": req.Label})
}

func (h *edgeHandler) adminDelToken(w http.ResponseWriter, r *http.Request) {
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

func (h *edgeHandler) adminListSubs(w http.ResponseWriter) {
	if h.subHandler == nil || h.subHandler.Store == nil {
		writeJSON(w, map[string]any{"subs": []any{}, "count": 0})
		return
	}
	subs := h.subHandler.Store.ListUserSubs()
	writeJSON(w, map[string]any{
		"subs":       subs,
		"count":      len(subs),
		"legacy_sub": "/sub/" + h.subHandler.Store.Secret(),
	})
}

type upsertSubsReq struct {
	Username string              `json:"username"`
	Slug     string              `json:"slug"`
	Token    string              `json:"token"`
	ExpireAt int64               `json:"expire_at"`
	Servers  []subscribe.Server  `json:"servers"`
	Subs     []subscribe.UserSub `json:"subs"`
}

func (h *edgeHandler) adminUpsertSubs(w http.ResponseWriter, r *http.Request) {
	if h.subHandler == nil || h.subHandler.Store == nil {
		http.Error(w, "subscription store unavailable", http.StatusServiceUnavailable)
		return
	}
	var req upsertSubsReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	toProcess := req.Subs
	if req.Slug != "" {
		toProcess = append(toProcess, subscribe.UserSub{
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
		if err := h.subHandler.Store.UpsertUserSub(item); err != nil {
			http.Error(w, "upsert failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// 自动挂载该用户的 Token 进 TokenStore / Validator，免重载热生效
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

func (h *edgeHandler) adminDeleteSub(w http.ResponseWriter, r *http.Request) {
	if h.subHandler == nil || h.subHandler.Store == nil {
		http.Error(w, "subscription store unavailable", http.StatusServiceUnavailable)
		return
	}
	slug := r.URL.Query().Get("slug")
	if slug == "" {
		http.Error(w, "slug required", http.StatusBadRequest)
		return
	}
	if sub, ok := h.subHandler.Store.GetUserSub(slug); ok && sub.Token != "" {
		if h.tokenStore != nil {
			_ = h.tokenStore.Remove(sub.Token)
		} else if h.validator != nil {
			h.validator.RemoveToken(sub.Token)
		}
	}
	if err := h.subHandler.Store.DeleteUserSub(slug); err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "deleted_slug": slug})
}

func (h *edgeHandler) adminReload(w http.ResponseWriter) {
	if h.tokenStore == nil {
		http.Error(w, "no token store", http.StatusServiceUnavailable)
		return
	}
	n, err := h.tokenStore.Reload()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := map[string]any{"ok": true, "token_count": n, "cert_ok": true}
	if h.certMgr != nil {
		if cerr := h.certMgr.ReloadFromDisk(); cerr != nil {
			out["cert_ok"] = false
			out["cert_error"] = cerr.Error()
		}
	}
	writeJSON(w, out)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
