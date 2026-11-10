// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// CaptivePortalURL 探测强制门户的标准 204 端点
var captivePortalURL = "http://connectivitycheck.gstatic.com/generate_204"

// DetectCaptivePortal 通过物理直连拨号检测当前物理网络是否存在强制门户拦截 (Captive Portal)。
// 若检测到跳转 (301/302/307) 或非 204 状态码，返回 true (存在拦截)；若成功返回 204，返回 false (网络通畅)。
func DetectCaptivePortal(ctx context.Context) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	transport := &http.Transport{
		Proxy: nil, // 强制物理直连，不走任何代理
		DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
			return DialPhysicalDirect(c, network, addr)
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 5 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 捕获重定向，不跟随：重定向直接证明存在 Captive Portal
			return http.ErrUseLastResponse
		},
		Timeout: 6 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, captivePortalURL, nil)
	if err != nil {
		return false, fmt.Errorf("create captive portal request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("probe captive portal: %w", err)
	}
	defer resp.Body.Close()

	// 204 No Content 代表无 Captive Portal 拦截
	if resp.StatusCode == http.StatusNoContent {
		return false, nil
	}

	// 发生重定向或返回 200/其他状态码代表被劫持到登录认证页
	return true, nil
}
