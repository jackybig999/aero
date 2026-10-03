//go:build !windows

package desk

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// isProcessAlive 检查指定 PID 进程是否仍在活跃运行
func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// FindChildProcess 在非 Windows 平台直接返回 parentPID
func FindChildProcess(parentPID int) int {
	return parentPID
}

// GracefulStopPID 通过 PID 优雅终止浏览器进程
func GracefulStopPID(pid int, timeout time.Duration) error {
	if !isProcessAlive(pid) {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = p.Signal(syscall.SIGTERM)

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !isProcessAlive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return p.Kill()
}

// GracefulStopProcess 优雅终止浏览器进程
func GracefulStopProcess(cmd *exec.Cmd, timeout time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return GracefulStopPID(cmd.Process.Pid, timeout)
}

func getDarwinLocale() string {
	out, err := exec.Command("defaults", "read", "-g", "AppleLocale").Output()
	if err == nil {
		loc := strings.TrimSpace(string(out))
		if loc != "" {
			return loc
		}
	}
	outLang, errLang := exec.Command("defaults", "read", "-g", "AppleLanguages").Output()
	if errLang == nil {
		str := string(outLang)
		if idx := strings.Index(str, "\""); idx != -1 {
			if endIdx := strings.Index(str[idx+1:], "\""); endIdx != -1 {
				lang := str[idx+1 : idx+1+endIdx]
				if lang != "" {
					return lang
				}
			}
		}
	}
	return ""
}

// GetHostSystemLocale 动态检测宿主操作系统当前的真实显示语言 (macOS/Linux 原生系统探测)
func GetHostSystemLocale() string {
	if runtime.GOOS == "darwin" {
		if loc := getDarwinLocale(); loc != "" {
			return NormalizeLocale(loc)
		}
	}
	for _, env := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(env); v != "" {
			parts := strings.Split(v, ".")
			return NormalizeLocale(parts[0])
		}
	}
	return "en-US"
}

func hideProcessWindow(cmd *exec.Cmd) {}

func setSysProcAttr(cmd *exec.Cmd) {}
