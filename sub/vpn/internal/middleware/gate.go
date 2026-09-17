// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package middleware enforces public / user / admin rules on API routes only.
// UI paths (/login, /admin, static assets) are always open — SPAs handle their own auth.
package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
)

// TokenVerifier validates a session token and returns (userID, isStaff, error).
type TokenVerifier func(token string) (userID uint64, isStaff bool, err error)

// Gate wraps the app mux.
type Gate struct {
	Verify TokenVerifier
	Next   http.Handler
}

func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	if method == http.MethodOptions {
		g.Next.ServeHTTP(w, r)
		return
	}

	// Non-API: pages / static / health — no token required
	if !strings.HasPrefix(path, "/api/") {
		g.Next.ServeHTTP(w, r)
		return
	}

	if isPublicAPI(method, path) {
		g.Next.ServeHTTP(w, r)
		return
	}

	token := ExtractToken(r)
	if token == "" {
		writeErr(w, 401, 1003, "unauthorized: login required")
		return
	}
	uid, staff, err := g.Verify(token)
	if err != nil {
		writeErr(w, 401, 1003, "invalid token")
		return
	}
	ctx := WithUser(r, uid, staff)
	r = r.WithContext(ctx)

	if isUserOpenAPI(method, path) {
		g.Next.ServeHTTP(w, r)
		return
	}
	if !staff {
		writeErr(w, 403, 1003, "admin only")
		return
	}
	g.Next.ServeHTTP(w, r)
}

func isPublicAPI(method, path string) bool {
	if method == http.MethodPost && path == "/api/v1/auth/login/" {
		return true
	}
	if method == http.MethodPost && path == "/api/v1/users/" {
		return true
	}
	if method == http.MethodGet && path == "/api/v1/plans/" {
		return true
	}
	if method == http.MethodGet && path == "/api/v1/payments/in/channels/" {
		return true
	}
	if method == http.MethodGet && path == "/api/v1/subscriptions/config/" {
		return true
	}
	if method == http.MethodGet && path == "/api/v1/nodes/available/" {
		return true
	}
	if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/nodes/") && strings.HasSuffix(path, "/heartbeat/") {
		return true
	}
	if method == http.MethodPost && strings.Contains(path, "/api/v1/sync/agents/") && strings.HasSuffix(path, "/heartbeat/") {
		return true
	}
	return false
}

func isUserOpenAPI(method, path string) bool {
	if method == http.MethodGet && strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/traffic/") {
		return true
	}
	if method == http.MethodGet && strings.HasPrefix(path, "/api/v1/users/") {
		rest := strings.TrimPrefix(path, "/api/v1/users/")
		if rest != "" && !strings.Contains(strings.Trim(rest, "/"), "/") {
			return true
		}
	}
	if method == http.MethodPost && path == "/api/v1/payments/in/orders/" {
		return true
	}
	if path == "/api/v1/subscriptions/" && (method == http.MethodGet || method == http.MethodPost) {
		return true
	}
	if method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/subscriptions/") {
		return true
	}
	if strings.HasPrefix(path, "/api/v1/test/") {
		return true
	}
	return false
}

func writeErr(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": msg})
}
