// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package subscribe

import (
	"net/http"
	"strings"
)

// Handler 提供 GET /sub/{secret}
type Handler struct {
	Store *Store
}

// ServeHTTP 仅处理 /sub/ 前缀；其它 path 返回 false
func (h *Handler) TryServe(w http.ResponseWriter, r *http.Request) bool {
	if h == nil || h.Store == nil {
		return false
	}
	path := r.URL.Path
	if !strings.HasPrefix(path, "/sub/") {
		return false
	}
	secret := strings.TrimPrefix(path, "/sub/")
	secret = strings.Trim(secret, "/")
	if secret == "" || strings.Contains(secret, "/") {
		http.NotFound(w, r)
		return true
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	if secret != h.Store.Secret() {
		http.NotFound(w, r)
		return true
	}
	body, err := h.Store.DocumentJSON()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}
