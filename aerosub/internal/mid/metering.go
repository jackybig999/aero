// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package mid

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"sort"
)

// MeteringRecord represents the traffic usage report for a single token.
type MeteringRecord struct {
	Token     string `json:"token"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
}

// MeteringReportRequest represents the metering report sent from edge nodes.
type MeteringReportRequest struct {
	NodeID  string           `json:"node_id"`
	Records []MeteringRecord `json:"records"`
}

// MeteringReportResponse represents the response with quota circuit-broken tokens.
type MeteringReportResponse struct {
	Code          int      `json:"code"`
	RevokedTokens []string `json:"revoked_tokens"`
	Message       string   `json:"message"`
}

// HandleAdminMetering handles traffic metering reports and quota circuit-breaking.
func HandleAdminMetering(db *AeroDB, adminKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, MeteringReportResponse{
				Code:    1005,
				Message: "method not allowed",
			})
			return
		}

		// 1. 鉴权：检查请求头 Aero-Admin-Key 或 query key
		reqKey := r.Header.Get("Aero-Admin-Key")
		if reqKey == "" {
			reqKey = r.URL.Query().Get("key")
		}

		effectiveKey := adminKey
		if effectiveKey == "" {
			effectiveKey = os.Getenv("AERO_ADMIN_KEY")
		}

		if effectiveKey == "" || subtle.ConstantTimeCompare([]byte(reqKey), []byte(effectiveKey)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="aero-admin"`)
			writeJSON(w, http.StatusUnauthorized, MeteringReportResponse{
				Code:          1003,
				RevokedTokens: []string{},
				Message:       "unauthorized: invalid admin key",
			})
			return
		}

		if db == nil {
			writeJSON(w, http.StatusInternalServerError, MeteringReportResponse{
				Code:          1004,
				RevokedTokens: []string{},
				Message:       "database unavailable",
			})
			return
		}

		// 2. 解析 MeteringReportRequest
		var req MeteringReportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, MeteringReportResponse{
				Code:          1002,
				RevokedTokens: []string{},
				Message:       "invalid request body: " + err.Error(),
			})
			return
		}

		// 3. 批量更新流量并进行配额熔断检查（单事务原子刷盘）
		revokedMap, err := db.AddSubscriptionUsageBatch(req.Records)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, MeteringReportResponse{
				Code:          1004,
				RevokedTokens: []string{},
				Message:       "batch metering failed: " + err.Error(),
			})
			return
		}

		var revokedTokens []string
		for tok, isRevoked := range revokedMap {
			if isRevoked {
				revokedTokens = append(revokedTokens, tok)
			}
		}
		sort.Strings(revokedTokens)
		if revokedTokens == nil {
			revokedTokens = []string{}
		}

		// 4. 返回响应
		writeJSON(w, http.StatusOK, MeteringReportResponse{
			Code:          0,
			RevokedTokens: revokedTokens,
			Message:       "ok",
		})
	}
}
