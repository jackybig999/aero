//go:build windows

package main

import (
	"os"
	"strconv"
	"strings"

	"aisys/connect/os/internal/domain/proxy"
	"golang.org/x/sys/windows/registry"
)

// WindowsSysProxyDetector 探测 Windows 注册表与系统代理配置
type WindowsSysProxyDetector struct{}

func NewWindowsSysProxyDetector() *WindowsSysProxyDetector {
	return &WindowsSysProxyDetector{}
}

// Detect 检查 Windows 系统代理设置
func (d *WindowsSysProxyDetector) Detect() (*proxy.ProxyConfig, error) {
	// 1. 读取注册表 Internet Settings
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()

		enable, _, err := k.GetIntegerValue("ProxyEnable")
		if err == nil && enable == 1 {
			proxyServer, _, err := k.GetStringValue("ProxyServer")
			if err == nil && proxyServer != "" {
				cfg := parseWindowsProxyString(proxyServer)
				if cfg != nil {
					cfg.Enabled = true
					return cfg, nil
				}
			}
		}
	}

	// 2. 环境变量兜底检查 (HTTP_PROXY / ALL_PROXY)
	for _, envKey := range []string{"HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		val := os.Getenv(envKey)
		if val != "" {
			cfg, err := proxy.ParseProxyString(val)
			if err == nil {
				cfg.Enabled = true
				return cfg, nil
			}
		}
	}

	return &proxy.ProxyConfig{Enabled: false}, nil
}

// parseWindowsProxyString 解析类似 "127.0.0.1:7890" 或 "http=127.0.0.1:8080;https=...;socks=..."
func parseWindowsProxyString(raw string) *proxy.ProxyConfig {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "=") {
		cfg, err := proxy.ParseProxyString(raw)
		if err == nil {
			return cfg
		}
		return nil
	}

	parts := strings.Split(raw, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "socks=") {
			endpoint := strings.TrimPrefix(p, "socks=")
			return buildProxy("socks5", endpoint)
		}
		if strings.HasPrefix(p, "http=") {
			endpoint := strings.TrimPrefix(p, "http=")
			return buildProxy("http", endpoint)
		}
	}
	return nil
}

func buildProxy(proto, endpoint string) *proxy.ProxyConfig {
	parts := strings.Split(endpoint, ":")
	if len(parts) == 2 {
		port, err := strconv.Atoi(parts[1])
		if err == nil {
			return &proxy.ProxyConfig{
				Enabled:  true,
				Protocol: proto,
				Host:     parts[0],
				Port:     port,
			}
		}
	}
	return nil
}
