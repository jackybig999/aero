// Copyright 2025 AERO Protocol Contributors
// Plan.md Phase 2: 平铺无子包运营中台 — 全局安全鉴权、CORS 与崩溃恢复中间件
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type CtxKey string

const (
	CtxUserID  CtxKey = "user_id"
	CtxIsStaff CtxKey = "is_staff"
)

// TokenVerifier validates a session token and returns (userID, isStaff, error).
type TokenVerifier func(token string) (userID uint64, isStaff bool, err error)

// Gate wraps the app mux and enforces authentication on protected API endpoints.
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

	// Non-API paths (/health, /sub/..., /admin/..., /login) bypass gate
	if !strings.HasPrefix(path, "/api/") {
		g.Next.ServeHTTP(w, r)
		return
	}

	// Public APIs do not require credentials
	if isPublicAPI(method, path) {
		g.Next.ServeHTTP(w, r)
		return
	}

	token := ExtractToken(r)
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 1003, "message": "unauthorized: login required"})
		return
	}

	uid, staff, err := g.Verify(token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 1003, "message": "invalid token"})
		return
	}

	ctx := WithUser(r, uid, staff)
	r = r.WithContext(ctx)

	if isUserOpenAPI(method, path) {
		g.Next.ServeHTTP(w, r)
		return
	}

	if !staff {
		writeJSON(w, http.StatusForbidden, map[string]any{"code": 1003, "message": "admin privilege required"})
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
	if method == http.MethodGet && path == "/api/v1/nodes/available/" {
		return true
	}
	if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/nodes/") && strings.HasSuffix(path, "/heartbeat/") {
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
	if method == http.MethodGet && path == "/api/v1/user/subscription" {
		return true
	}
	return false
}

// Recover catches panics and prevents the middle platform from crashing.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{
					"code":    1006,
					"message": "internal server error recovered",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// CORSPermissive enables CORS headers for cross-origin browser requests.
func CORSPermissive(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,Accept")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ExtractToken parses Bearer or Token headers.
func ExtractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if s, ok := strings.CutPrefix(auth, "Bearer "); ok {
		return strings.TrimSpace(s)
	}
	if s, ok := strings.CutPrefix(auth, "Token "); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// WithUser binds user session values into request context.
func WithUser(r *http.Request, userID uint64, isStaff bool) context.Context {
	ctx := r.Context()
	ctx = context.WithValue(ctx, CtxUserID, userID)
	ctx = context.WithValue(ctx, CtxIsStaff, isStaff)
	return ctx
}

// writeJSON provides uniform HTTP JSON output.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errResp(code int, msg string) map[string]any {
	return map[string]any{"code": code, "message": msg}
}
