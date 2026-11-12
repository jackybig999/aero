// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	Version  = "1.3.2"
	Protocol = "aero/3.0"
	APILevel = 3
)

// AdminHandler handles /admin/* management endpoints
type AdminHandler struct {
	adminKey   string
	validator  *Validator
	tokenStore *TokenStore
	subStore   *SubStore
}

// NewAdminHandler 创建旧管理接口处理器（只剩 /admin/subs）。
func NewAdminHandler(key string, v *Validator, ts *TokenStore, ss *SubStore) *AdminHandler {
	return &AdminHandler{adminKey: key, validator: v, tokenStore: ts, subStore: ss}
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
	var key string
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		key = strings.TrimPrefix(auth, "Bearer ")
	}
	if key == "" {
		key = r.Header.Get("X-Aero-Admin-Key")
	}
	if key == "" {
		key = r.URL.Query().Get("key")
	}

	// 模式 A：配置了 adminKey，强校验必须匹配（彻底杜绝反代穿透绕过）
	if h.adminKey != "" {
		if key == "" {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(key), []byte(h.adminKey)) == 1
	}

	// 模式 B：未配置 adminKey，仅允许本地回环（保留无 Key 单机部署便利）
	return h.isLoopback(r)
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

	// 旧管理接口只保留订阅注入（签名 token 过渡期结束后删除）；其余由 C13 /admin/v1/* 取代。
	switch {
	case r.URL.Path == "/admin/subs" && r.Method == http.MethodGet:
		h.handleListSubs(w)
	case r.URL.Path == "/admin/subs" && r.Method == http.MethodPost:
		h.handleUpsertSubs(w, r)
	case r.URL.Path == "/admin/subs" && r.Method == http.MethodDelete:
		h.handleDeleteSub(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

func (h *AdminHandler) handleListSubs(w http.ResponseWriter) {
	if h.subStore == nil {
		writeJSON(w, map[string]any{"subs": []any{}, "count": 0, "admin_sub": ""})
		return
	}
	subs := h.subStore.ListUserSubs()
	adminSub := ""
	if secret := h.subStore.Secret(); secret != "" {
		adminSub = "/sub/" + secret
	}
	writeJSON(w, map[string]any{
		"subs":       subs,
		"count":      len(subs),
		"legacy_sub": adminSub,
		"admin_sub":  adminSub,
	})
}

type upsertSubsAdminReq struct {
	Username          string      `json:"username"`
	Slug              string      `json:"slug"`
	Token             string      `json:"token"`
	ExpireAt          int64       `json:"expire_at"`
	TrafficLimitBytes int64       `json:"traffic_limit_bytes"`
	TrafficUsedBytes  int64       `json:"traffic_used_bytes"`
	Servers           []SubServer `json:"servers"`
	Subs              []UserSub   `json:"subs"`
}

func (r *upsertSubsAdminReq) UnmarshalJSON(data []byte) error {
	type Alias upsertSubsAdminReq
	aux := struct {
		*Alias
		CamelExpireAt     int64 `json:"expireAt"`
		CamelTrafficLimit int64 `json:"trafficLimitBytes"`
		CamelTrafficUsed  int64 `json:"trafficUsedBytes"`
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if r.ExpireAt == 0 && aux.CamelExpireAt != 0 {
		r.ExpireAt = aux.CamelExpireAt
	}
	if r.TrafficLimitBytes == 0 && aux.CamelTrafficLimit != 0 {
		r.TrafficLimitBytes = aux.CamelTrafficLimit
	}
	if r.TrafficUsedBytes == 0 && aux.CamelTrafficUsed != 0 {
		r.TrafficUsedBytes = aux.CamelTrafficUsed
	}
	return nil
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
			Username:          req.Username,
			Slug:              req.Slug,
			Token:             req.Token,
			ExpireAt:          req.ExpireAt,
			TrafficLimitBytes: req.TrafficLimitBytes,
			TrafficUsedBytes:  req.TrafficUsedBytes,
			Servers:           req.Servers,
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
		// 挂载 token：有效期与订阅到期时间一致；订阅已过期则移除 token（在线会话由
		// token 执行器断开），不得挂载成长期 token。
		if item.Token != "" {
			if err := h.mountSubToken(item); err != nil {
				http.Error(w, "mount token failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		synced++
	}
	writeJSON(w, map[string]any{"ok": true, "synced_count": synced})
}

// mountSubToken 按订阅到期时间挂载或移除用户 token。ExpireAt 为 0 表示不限期，
// 沿用一年有效期（启动时 Ensure 会续期）。
func (h *AdminHandler) mountSubToken(item UserSub) error {
	now := time.Now()
	if item.ExpireAt > 0 && item.ExpireAt <= now.Unix() {
		if h.tokenStore != nil {
			return h.tokenStore.Remove(item.Token)
		}
		if h.validator != nil {
			h.validator.RemoveToken(item.Token)
		}
		return nil
	}
	ttl := 365 * 24 * time.Hour
	if item.ExpireAt > 0 {
		ttl = time.Unix(item.ExpireAt, 0).Sub(now)
	}
	label := "user:" + item.Username
	if item.Username == "" {
		label = "user:" + item.Slug
	}
	if h.tokenStore != nil {
		_, err := h.tokenStore.AddReturn(item.Token, label, ttl)
		return err
	}
	if h.validator != nil {
		h.validator.AddToken(item.Token, label, ttl)
	}
	return nil
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
