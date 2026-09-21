//go:build !windows

package kernel

import (
	"os"
	"os/exec"
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

// GracefulStopProcess 优雅终止浏览器进程 (支持会话恢复与 Cookie 持久化)
func GracefulStopProcess(cmd *exec.Cmd, timeout time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return GracefulStopPID(cmd.Process.Pid, timeout)
}
