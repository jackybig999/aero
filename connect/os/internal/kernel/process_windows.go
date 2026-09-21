//go:build windows

package kernel

import (
	"os/exec"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

// isProcessAlive 检查指定 PID 进程是否仍在活跃运行
func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var exitCode uint32
	if err := syscall.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	return exitCode == 259 // 259 = STILL_ACTIVE
}

// FindChildProcess 查找指定父进程衍生的子进程 PID (解决 Windows 下 Firefox Launcher 派生主进程问题)
func FindChildProcess(parentPID int) int {
	if parentPID <= 0 {
		return 0
	}
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer syscall.CloseHandle(snapshot)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := syscall.Process32First(snapshot, &entry); err != nil {
		return 0
	}
	for {
		if entry.ParentProcessID == uint32(parentPID) {
			return int(entry.ProcessID)
		}
		if err := syscall.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return 0
}

// GracefulStopPID 通过 PID 优雅终止浏览器进程 (支持会话恢复与 Cookie 持久化)
func GracefulStopPID(pid int, timeout time.Duration) error {
	if !isProcessAlive(pid) {
		return nil
	}

	if timeout > 1200*time.Millisecond {
		timeout = 1200 * time.Millisecond
	}

	// 1. 发送 WM_CLOSE 软关闭信号，通知浏览器保存打开的标签页、刷新 SQLite Cookies WAL 与缓存
	softCmd := exec.Command("taskkill", "/pid", strconv.Itoa(pid))
	softCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = softCmd.Run()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !isProcessAlive(pid) {
			return nil
		}
		time.Sleep(80 * time.Millisecond)
	}

	// 2. 超时后若仍未退出，则强制 Kill 进程树
	forceCmd := exec.Command("taskkill", "/f", "/t", "/pid", strconv.Itoa(pid))
	forceCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return forceCmd.Run()
}

// GracefulStopProcess 优雅终止浏览器进程
func GracefulStopProcess(cmd *exec.Cmd, timeout time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return GracefulStopPID(cmd.Process.Pid, timeout)
}
