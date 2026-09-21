package kernel

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// CleanKernelDir 强制安全清理内核目录 (包含跨进程查杀锁定与多重重试)
func CleanKernelDir(targetDir string) error {
	if targetDir == "" {
		return nil
	}
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		return nil
	}

	if runtime.GOOS == "windows" {
		abs, err := filepath.Abs(targetDir)
		if err == nil {
			psCmd := fmt.Sprintf(`Get-Process | Where-Object { $_.Path -and ($_.Path.ToLower().StartsWith('%s')) } | Stop-Process -Force -ErrorAction SilentlyContinue`, strings.ToLower(strings.ReplaceAll(abs, `'`, `''`)))
			_ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).Run()
		}
	}

	time.Sleep(100 * time.Millisecond)

	var lastErr error
	for i := 0; i < 4; i++ {
		lastErr = os.RemoveAll(targetDir)
		if lastErr == nil || os.IsNotExist(lastErr) {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return lastErr
}

// DeleteKernel 彻底清理删除指定的便携内核目录及运行锁
func DeleteKernel(dataDir, kernelType, milestone string) error {
	key := fmt.Sprintf("%s_%s", kernelType, milestone)
	targetDir := filepath.Join(dataDir, "kernels", key)
	SetKernelProgress(key, 0)
	return CleanKernelDir(targetDir)
}

// CleanInstallerArtifacts 仅清理项目内核目录下的安装器残留文件，严禁触碰任何系统目录
func CleanInstallerArtifacts(targetDir string) {
	junkList := []string{
		"maintenanceservice.exe",
		"maintenanceservice_installer.exe",
		"install.log",
		"installation_telemetry.json",
		"uninstall",
		"desktop-launcher",
		"setup.tmp.exe",
		"download.tmp.zip",
		"setup.exe",
		"package.tmp",
	}
	for _, j := range junkList {
		_ = os.RemoveAll(filepath.Join(targetDir, j))
	}
}
