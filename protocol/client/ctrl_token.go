// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// EnsureCtrlToken 获取或生成本地控制面鉴权 Token (0600 权限落盘)
func EnsureCtrlToken(customPath ...string) (string, error) {
	var tokenPath string
	if len(customPath) > 0 && strings.TrimSpace(customPath[0]) != "" {
		tokenPath = customPath[0]
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			tokenPath = "ctrl.token"
		} else {
			dir := filepath.Join(homeDir, ".aero")
			_ = os.MkdirAll(dir, 0700)
			tokenPath = filepath.Join(dir, "ctrl.token")
		}
	}

	// 1. 若文件已存在且有效，直接加载
	if data, err := os.ReadFile(tokenPath); err == nil {
		token := strings.TrimSpace(string(data))
		if len(token) >= 32 {
			return token, nil
		}
	}

	// 2. 生成高熵安全 32-byte (64 字符十六进制) 随机 Token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate ctrl token rand failed: %w", err)
	}
	token := hex.EncodeToString(b)

	// 3. 严格以 0600 权限安全落盘
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		return "", fmt.Errorf("save ctrl token failed: %w", err)
	}
	return token, nil
}

// ValidateCtrlToken 恒定时间比较防时序攻击验证 Token
func ValidateCtrlToken(expected, provided string) bool {
	if expected == "" || provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}

// ExtractTokenFromRequest 从请求头或 Query 参数中提取 Token
func ExtractTokenFromRequest(r *http.Request) string {
	// 1. Authorization: Bearer <token>
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	// 2. X-Ctrl-Token: <token>
	if custom := r.Header.Get("X-Ctrl-Token"); custom != "" {
		return strings.TrimSpace(custom)
	}
	// 3. ?ctrl_token=<token>
	return strings.TrimSpace(r.URL.Query().Get("ctrl_token"))
}

// CtrlAuthMiddleware 为本地 HTTP 控制面注入 Token 守卫
func CtrlAuthMiddleware(expectedToken string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// 免密白名单：健康检查、PAC、静态资源及状态探针
		if path == "/health" || path == "/api/v1/health" ||
			strings.HasSuffix(path, "/proxy.pac") ||
			path == "/favicon.ico" ||
			r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// 核心敏感变异操作必须鉴权
		token := ExtractTokenFromRequest(r)
		if !ValidateCtrlToken(expectedToken, token) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    http.StatusUnauthorized,
				"error":   "unauthorized: invalid or missing ctrl.token",
				"message": "本地控制面受保护：请在请求头携带 Authorization: Bearer <ctrl.token>",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
