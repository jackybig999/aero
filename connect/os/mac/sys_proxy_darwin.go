//go:build darwin

package main

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"aisys/connect/os/internal/domain/proxy"
)

// MacSysProxyDetector 探测 macOS scutil --proxy 与系统环境变量
type MacSysProxyDetector struct{}

func NewMacSysProxyDetector() *MacSysProxyDetector {
	return &MacSysProxyDetector{}
}

// Detect 执行 scutil --proxy 并解析输出
func (d *MacSysProxyDetector) Detect() (*proxy.ProxyConfig, error) {
	cmd := exec.Command("scutil", "--proxy")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		cfg := parseScutilProxyOutput(out.String())
		if cfg != nil && cfg.Enabled {
			return cfg, nil
		}
	}

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

func parseScutilProxyOutput(output string) *proxy.ProxyConfig {
	props := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, ":") {
			kv := strings.SplitN(line, ":", 2)
			props[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	if props["SOCKSProxy"] != "" {
		port, _ := strconv.Atoi(props["SOCKSPort"])
		if port > 0 {
			return &proxy.ProxyConfig{
				Enabled:  true,
				Protocol: "socks5",
				Host:     props["SOCKSProxy"],
				Port:     port,
			}
		}
	}

	if props["HTTPProxy"] != "" {
		port, _ := strconv.Atoi(props["HTTPPort"])
		if port > 0 {
			return &proxy.ProxyConfig{
				Enabled:  true,
				Protocol: "http",
				Host:     props["HTTPProxy"],
				Port:     port,
			}
		}
	}

	return nil
}
