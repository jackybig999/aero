// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aero-protocol/aero-edge/internal/auth"
	"github.com/aero-protocol/aero-edge/internal/cover"
	"github.com/aero-protocol/aero-edge/internal/tokenstore"
	"github.com/aero-protocol/aero-edge/internal/version"
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
			"version": version.Version, "protocol": version.Protocol, "api_level": version.APILevel,
		})
	case r.URL.Path == "/admin/status" && r.Method == http.MethodGet:
		h.adminStatus(w)
	case r.URL.Path == "/admin/tokens" && r.Method == http.MethodGet:
		h.adminListTokens(w)
	case r.URL.Path == "/admin/tokens" && r.Method == http.MethodPost:
		h.adminAddToken(w, r)
	case r.URL.Path == "/admin/tokens" && r.Method == http.MethodDelete:
		h.adminDelToken(w, r)
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
	writeJSON(w, map[string]any{
		"ok":               true,
		"version":          version.Version,
		"protocol":         version.Protocol,
		"api_level":        version.APILevel,
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
	})
}

func (h *edgeHandler) adminListTokens(w http.ResponseWriter) {
	var list []tokenstore.Record
	if h.tokenStore != nil {
		list = h.tokenStore.List()
	} else {
		for _, t := range h.validator.ListTokens() {
			list = append(list, tokenstore.Record{
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
	writeJSON(w, map[string]any{"ok": true, "token_count": n})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
