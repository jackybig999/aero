package aitools

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"aisys/connect/os/internal/audit"
)

type Executor struct {
	scanner *Scanner
	proxy   string // e.g. "127.0.0.1:55555"
}

func NewExecutor(scanner *Scanner, proxyAddr string) *Executor {
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:55555"
	}
	return &Executor{
		scanner: scanner,
		proxy:   proxyAddr,
	}
}

func (e *Executor) BuildProxyEnv() []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env)+8)

	for _, kv := range env {
		upper := strings.ToUpper(kv)
		if strings.HasPrefix(upper, "HTTP_PROXY=") ||
			strings.HasPrefix(upper, "HTTPS_PROXY=") ||
			strings.HasPrefix(upper, "ALL_PROXY=") ||
			strings.HasPrefix(upper, "NO_PROXY=") {
			continue
		}
		filtered = append(filtered, kv)
	}

	httpProxy := fmt.Sprintf("http://%s", e.proxy)
	socksProxy := fmt.Sprintf("socks5://%s", e.proxy)

	filtered = append(filtered,
		"HTTP_PROXY="+httpProxy,
		"http_proxy="+httpProxy,
		"HTTPS_PROXY="+httpProxy,
		"https_proxy="+httpProxy,
		"ALL_PROXY="+socksProxy,
		"all_proxy="+socksProxy,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
	)

	return filtered
}

func (e *Executor) Launch(toolKey, cwdOverride string) (string, error) {
	path, installed := e.scanner.findExecutable(toolKey)
	if !installed || path == "" {
		return "", fmt.Errorf("未检测到 %s 安装路径，请先安装该工具", toolKey)
	}

	cwd := cwdOverride
	if cwd == "" {
		cwd = e.scanner.store.GetCWD(toolKey)
	}
	if fi, err := os.Stat(cwd); err != nil || !fi.IsDir() {
		cwd, _ = os.Getwd()
	}

	env := e.BuildProxyEnv()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		if toolKey == "claude" || toolKey == "terminal" {
			title := strings.ToUpper(toolKey[:1]) + toolKey[1:] + " [AERO OS Proxy: 55555]"
			args := []string{"/c", "start", title, "cmd", "/k", "title " + title}
			if toolKey == "claude" {
				args = append(args, "&&", path)
			}
			cmd = exec.Command("cmd.exe", args...)
			cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200} // CREATE_NEW_PROCESS_GROUP
		} else {
			cmd = exec.Command(path)
			cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200}
		}
	} else {
		// macOS
		if toolKey == "claude" || toolKey == "terminal" {
			cmd = exec.Command("open", "-a", "Terminal", cwd)
		} else {
			cmd = exec.Command("open", "-a", path)
		}
	}

	cmd.Dir = cwd
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		audit.GlobalLogger.Log("ERROR", "AITOOLS", fmt.Sprintf("启动 %s 失败: %v", toolKey, err))
		return "", fmt.Errorf("启动失败: %w", err)
	}

	msg := fmt.Sprintf("已成功启动 %s (已自动注入高速代理 %s, 工作目录: %s)", toolKey, e.proxy, cwd)
	audit.GlobalLogger.Log("INFO", "AITOOLS", msg)
	return msg, nil
}
