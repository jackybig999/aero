//go:build windows

package desk

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
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

// FindChildProcess 查找指定父进程衍生的子进程 PID
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

// GracefulStopPID 通过 PID 优雅终止浏览器进程
func GracefulStopPID(pid int, timeout time.Duration) error {
	if !isProcessAlive(pid) {
		return nil
	}

	if timeout > 1200*time.Millisecond {
		timeout = 1200 * time.Millisecond
	}

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

// GetHostSystemLocale 动态检测宿主操作系统当前的真实显示语言 (Windows 原生系统探测)
func GetHostSystemLocale() string {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	proc := k32.NewProc("GetUserDefaultLocaleName")
	b := make([]uint16, 85)
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if r > 0 {
		name := syscall.UTF16ToString(b)
		if name != "" {
			return NormalizeLocale(name)
		}
	}
	procUI := k32.NewProc("GetUserDefaultUILanguage")
	if rUI, _, _ := procUI.Call(); rUI > 0 {
		switch uint16(rUI) {
		case 0x0804:
			return "zh-CN"
		case 0x0404:
			return "zh-TW"
		case 0x0c04:
			return "zh-HK"
		case 0x0411:
			return "ja"
		case 0x0407:
			return "de"
		case 0x040c:
			return "fr"
		case 0x0419:
			return "ru"
		case 0x0409:
			return "en-US"
		case 0x0809:
			return "en-GB"
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

func hideProcessWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000 | 0x00000200, // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
	}
}

func setSysProcAttr(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200} // CREATE_NEW_PROCESS_GROUP
}
