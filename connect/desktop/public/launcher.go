package public

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type LaunchParams struct {
	AppKey      string       `json:"appKey"`
	Proxy       *ProxyTarget `json:"proxy"`
	ProfileName string       `json:"profileName"`
	Cwd         string       `json:"cwd"`
	Command     string       `json:"command"`
	Type        string       `json:"type"` // "cli", "browser", "desktop"
}

// BuildProxyEnv generates environment variables injected with proxy settings.
func BuildProxyEnv(proxy *ProxyTarget) []string {
	env := os.Environ()
	if proxy == nil || proxy.Port == 0 {
		return env
	}

	filtered := make([]string, 0, len(env)+10)
	for _, e := range env {
		upper := strings.ToUpper(e)
		if strings.HasPrefix(upper, "HTTP_PROXY=") ||
			strings.HasPrefix(upper, "HTTPS_PROXY=") ||
			strings.HasPrefix(upper, "ALL_PROXY=") ||
			strings.HasPrefix(upper, "NO_PROXY=") {
			continue
		}
		filtered = append(filtered, e)
	}

	httpUrl := fmt.Sprintf("http://%s:%d", proxy.Host, proxy.Port)
	socksUrl := fmt.Sprintf("socks5://%s:%d", proxy.Host, proxy.Port)

	filtered = append(filtered,
		"HTTP_PROXY="+httpUrl,
		"http_proxy="+httpUrl,
		"HTTPS_PROXY="+httpUrl,
		"https_proxy="+httpUrl,
	)

	if proxy.Protocol == "socks5" {
		filtered = append(filtered, "ALL_PROXY="+socksUrl, "all_proxy="+socksUrl)
	} else {
		filtered = append(filtered, "ALL_PROXY="+httpUrl, "all_proxy="+httpUrl)
	}

	filtered = append(filtered, "NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1")
	return filtered
}

func Launch(p Platform, params LaunchParams) (string, error) {
	if p == nil {
		return "", fmt.Errorf("platform interface is nil")
	}

	cwd := params.Cwd
	if cwd == "" {
		cwd = GetToolCwdMap()[params.AppKey]
	}
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	env := BuildProxyEnv(params.Proxy)

	// Case 1: Desktop Application
	if params.Type == "desktop" && params.Command != "" {
		if err := p.LaunchDesktop(params.Command, cwd, env); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s 已启动", params.AppKey), nil
	}

	// Case 2: Browser
	if params.Type == "browser" || strings.Contains(strings.ToLower(params.AppKey), "chrome") || strings.Contains(strings.ToLower(params.AppKey), "edge") {
		userHome, _ := os.UserHomeDir()
		profileDir := filepath.Join(userHome, ".ai-runtime-manager", "profiles", params.ProfileName)
		_ = os.MkdirAll(profileDir, 0o755)

		var proxyUrl string
		if params.Proxy != nil && params.Proxy.Port > 0 {
			proxyUrl = fmt.Sprintf("%s://%s:%d", params.Proxy.Protocol, params.Proxy.Host, params.Proxy.Port)
		}

		cmdBin := params.Command
		if cmdBin == "" {
			cmdBin = params.AppKey
		}

		if err := p.LaunchBrowser(params.AppKey, cmdBin, profileDir, proxyUrl, cwd, env); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s 浏览器已启动", params.AppKey), nil
	}

	// Case 3: CLI tool (claude, codex)
	cmdName := params.AppKey
	if params.Command != "" {
		cmdName = params.Command
	}
	var args []string
	if cfg := GetConfig(); cfg != nil && cfg.Tools != nil {
		if t, ok := cfg.Tools[params.AppKey]; ok {
			if t.Command != "" {
				cmdName = t.Command
			}
			args = t.Args
		}
	}

	if err := p.LaunchCLI(params.AppKey, cmdName, args, cwd, env); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s 已在新控制台窗口启动", params.AppKey), nil
}
