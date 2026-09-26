// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ErrTier1AIExhausted Tier 1 纯净节点熔断保护错误 (Rule L7)
var ErrTier1AIExhausted = errors.New("TIER1_AI_NODES_EXHAUSTED: 全部 Tier 1 AI 纯净节点满载或下线")

// ServerNode 订阅中的单节点连接契约
type ServerNode struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Token       string `json:"token"`
	SNI         string `json:"sni"`
	Protocol    string `json:"protocol"`
	PurityScore int    `json:"purityScore,omitempty"`
	AIBlocked   bool   `json:"aiBlocked,omitempty"`
}

// Subscription 瘦客户端专属订阅结构 (aero/2.0)
type Subscription struct {
	Version      string         `json:"version"`
	UserID       string         `json:"userId"`
	Slug         string         `json:"slug"`
	ExpireAt     int64          `json:"expireAt"`
	CreatedAt    int64          `json:"createdAt"`
	RiskWarning  string         `json:"riskWarning,omitempty"`
	Optimization map[string]any `json:"optimization,omitempty"`
	Servers      []ServerNode   `json:"servers"`
}

// SubFetchOptions 订阅拉取参数
type SubFetchOptions struct {
	Purpose      string        // "ai" (请求纯净节点)
	AllowDegrade bool          // true 时允许降级
	ISPHint      string        // 运营商识别 (CT/CU/CM)
	Timeout      time.Duration // 请求超时
}

// FetchSubscription 从远端中台或本地拉取并解析订阅
func FetchSubscription(ctx context.Context, rawURL string, opt SubFetchOptions) (*Subscription, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("empty subscription URL")
	}

	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return nil, fmt.Errorf("invalid subscription URL scheme: %s (must be http:// or https://)", rawURL)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid subscription URL: %w", err)
	}

	// 动态注入 Thin Client 测速与意图参数
	q := u.Query()
	if opt.Purpose != "" {
		q.Set("purpose", opt.Purpose)
	}
	if opt.AllowDegrade {
		q.Set("allow_degrade", "true")
	}
	if opt.ISPHint != "" {
		q.Set("isp", opt.ISPHint)
	}
	u.RawQuery = q.Encode()

	timeout := 15 * time.Second
	if opt.Timeout > 0 {
		timeout = opt.Timeout
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AeroClient/2.0")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch subscription network error: %w", err)
	}
	defer resp.Body.Close()

	// 503 熔断保护识别 (Rule 2.4)
	if resp.StatusCode == http.StatusServiceUnavailable {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Error == "TIER1_AI_NODES_EXHAUSTED" {
			return nil, ErrTier1AIExhausted
		}
		return nil, fmt.Errorf("subscription service unavailable (503): %s", errBody.Error)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read subscription body failed: %w", err)
	}

	return ParseSubscriptionBytes(body)
}

// ParseSubscriptionBytes 解析 Base64 或原始 JSON 订阅报文
func ParseSubscriptionBytes(data []byte) (*Subscription, error) {
	dataStr := strings.TrimSpace(string(data))
	// 尝试 Base64 解码
	if decoded, err := base64.StdEncoding.DecodeString(dataStr); err == nil && len(decoded) > 0 {
		data = decoded
	} else if decoded, err := base64.RawStdEncoding.DecodeString(dataStr); err == nil && len(decoded) > 0 {
		data = decoded
	}

	var sub Subscription
	if err := json.Unmarshal(data, &sub); err != nil {
		return nil, fmt.Errorf("subscription json unmarshal failed: %w", err)
	}
	return &sub, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
