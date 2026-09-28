// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package sub

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FetchOptions 拉取选项
type FetchOptions struct {
	// InsecureSkipVerify 仅开发/自签场景；生产应由调用方注入 CA
	InsecureSkipVerify bool
	Timeout            time.Duration
	DisableCache       bool
	ISPHint            string
}

// Fetch 从 URL 或本地 file:// / 路径加载订阅
func Fetch(src string, opt FetchOptions) (*Subscription, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 15 * time.Second
	}
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, fmt.Errorf("empty subscription source")
	}

	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		return nil, fmt.Errorf("invalid subscription URL scheme: %s (must be http:// or https://)", src)
	}

	// 1. 首先尝试主订阅 URL
	sub, body, err := tryFetchSingleURL(src, opt)
	if err == nil && sub != nil {
		SaveLastBody(body)
		return sub, nil
	}

	// 关键判定：若中台明确返回 403 (订阅到期/停用) 或 404 (订阅已删除/销毁)，必须立即清理本地缓存，严禁降级回退旧节点
	if err != nil && (strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "HTTP 404")) {
		ClearLastBody()
		return nil, fmt.Errorf("subscription revoked or expired: %w", err)
	}

	// 2. 主 URL 失败时，尝试从缓存的历史服务器列表进行多源故障漂移 (Failover Fetch)
	u, parseErr := url.Parse(src)
	if parseErr == nil && u.Path != "" && strings.HasPrefix(u.Path, "/sub/") {
		if cached := LoadLastBody(); len(cached) > 0 {
			if lastSub, perr := ParseBytes(cached); perr == nil && len(lastSub.Servers) > 0 {
				scheme := u.Scheme
				if scheme == "" {
					scheme = "https"
				}
				for _, srv := range lastSub.Servers {
					altAddr := srv.Address
					if altAddr == "" || altAddr == u.Host {
						continue
					}
					// 构造备选 VPS 订阅链接
					altURL := fmt.Sprintf("%s://%s%s", scheme, altAddr, u.Path)
					if altSub, altBody, altErr := tryFetchSingleURL(altURL, opt); altErr == nil && altSub != nil {
						SaveLastBody(altBody)
						return altSub, nil
					}
				}
			}
		}
	}

	// 3. 所有网络源均不可达时，回退至本地最后一次有效缓存
	if !opt.DisableCache {
		if cached := LoadLastBody(); len(cached) > 0 {
			if sub, perr := ParseBytes(cached); perr == nil {
				return sub, nil
			}
		}
	}
	return nil, fmt.Errorf("fetch subscription (all sources failed): %w", err)
}

func tryFetchSingleURL(targetURL string, opt FetchOptions) (*Subscription, []byte, error) {
	sub, body, err := doFetchSingleURL(targetURL, opt)
	if err == nil && sub != nil {
		return sub, body, nil
	}

	// 端口自适应智能轮试：若标准 HTTPS (443) 获取失败或被第三方霸占 (非 200)，
	// 客户端在后台对标准候选 HTTPS 端口进行静默轮试探测，保持外部订阅 URL 绝对纯净
	u, uerr := url.Parse(targetURL)
	if uerr == nil && u.Port() == "" && strings.HasPrefix(u.Path, "/sub/") {
		candidatePorts := []string{"8443", "2053", "2083", "2087", "2096"}
		for _, cp := range candidatePorts {
			altU := *u
			altU.Host = net.JoinHostPort(u.Hostname(), cp)
			if altSub, altBody, altErr := doFetchSingleURL(altU.String(), opt); altErr == nil && altSub != nil {
				return altSub, altBody, nil
			}
		}
	}
	return nil, nil, err
}

func doFetchSingleURL(targetURL string, opt FetchOptions) (*Subscription, []byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, err
	}
	if opt.ISPHint != "" && !strings.Contains(u.RawQuery, "isp=") {
		q := u.Query()
		q.Set("isp", opt.ISPHint)
		u.RawQuery = q.Encode()
		targetURL = u.String()
	}
	client := &http.Client{
		Timeout: opt.Timeout,
		Transport: &http.Transport{
			Proxy:       func(*http.Request) (*url.URL, error) { return nil, nil },
			DialContext: dialWithHostCache,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: opt.InsecureSkipVerify,
				ServerName:         u.Hostname(),
			},
		},
	}
	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	sub, err := ParseBytes(body)
	if err != nil {
		return nil, nil, err
	}
	if host := u.Hostname(); host != "" {
		if ips, lerr := net.DefaultResolver.LookupHost(context.Background(), host); lerr == nil {
			saveHostIPs(host, ips)
		}
	}
	return sub, body, nil
}

var hostCacheMu sync.Mutex

func cacheFile(name string) []string {
	var out []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		out = append(out, filepath.Join(dir, name), filepath.Join(dir, "..", name))
	}
	if wd, err := os.Getwd(); err == nil {
		out = append(out, filepath.Join(wd, name))
	}
	return out
}

func saveHostIPs(host string, ips []string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(ips) == 0 {
		return
	}
	hostCacheMu.Lock()
	defer hostCacheMu.Unlock()
	m := map[string][]string{}
	for _, p := range cacheFile(".host-ip-cache.json") {
		if b, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(b, &m)
			break
		}
	}
	m[host] = ips
	raw, err := json.Marshal(m)
	if err != nil {
		return
	}
	for _, p := range cacheFile(".host-ip-cache.json") {
		_ = os.WriteFile(p, raw, 0o600)
	}
}

func loadHostIPs(host string) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	hostCacheMu.Lock()
	defer hostCacheMu.Unlock()
	for _, p := range cacheFile(".host-ip-cache.json") {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		m := map[string][]string{}
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		if ips := m[host]; len(ips) > 0 {
			return ips
		}
	}
	return nil
}

func SaveLastBody(body []byte) {
	if len(body) == 0 {
		return
	}
	for _, p := range cacheFile(".last-sub-body") {
		_ = os.WriteFile(p, body, 0o600)
	}
}

func LoadLastBody() []byte {
	for _, p := range cacheFile(".last-sub-body") {
		b, err := os.ReadFile(p)
		if err == nil && len(b) > 0 {
			return b
		}
	}
	return nil
}

func ClearLastBody() {
	for _, p := range cacheFile(".last-sub-body") {
		_ = os.Remove(p)
	}
}

func dialWithHostCache(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []string
	if parsed := net.ParseIP(host); parsed != nil {
		ips = []string{host}
	} else if resolved, lerr := net.DefaultResolver.LookupHost(ctx, host); lerr == nil && len(resolved) > 0 {
		ips = resolved
		saveHostIPs(host, resolved)
	} else {
		ips = loadHostIPs(host)
		if len(ips) == 0 {
			if lerr != nil {
				return nil, lerr
			}
			return nil, fmt.Errorf("lookup %s: no such host", host)
		}
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	var last error
	for _, ip := range ips {
		c, derr := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if derr == nil {
			return c, nil
		}
		last = derr
	}
	return nil, last
}

func loadFile(path string) (*Subscription, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseBytes(data)
}

// ParseBytes 解析 JSON 或 base64(JSON)
func ParseBytes(body []byte) (*Subscription, error) {
	body = trimSpaceBytes(body)
	// 尝试 base64
	if sub, err := ParseBase64(string(body)); err == nil && len(sub.Servers) > 0 {
		return sub, nil
	}
	var sub Subscription
	if err := json.Unmarshal(body, &sub); err != nil {
		return nil, fmt.Errorf("parse subscription: %w", err)
	}
	if len(sub.Servers) == 0 {
		return nil, fmt.Errorf("no servers in subscription")
	}
	return &sub, nil
}

func trimSpaceBytes(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
