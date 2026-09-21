package kernel

import (
	"os"
	"path/filepath"
	"runtime"
)

// isKernelExecutableValid 严格校验内核主程序及必备动态链接库完整性，杜绝空壳、残缺文件
func isKernelExecutableValid(path, kernelType string) bool {
	if path == "" {
		return false
	}
	if kernelType == "safari" && path == "emulated" {
		return true
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if info.Size() < 100*1024 {
		return false
	}

	dir := filepath.Dir(path)

	if runtime.GOOS == "windows" {
		if kernelType == "firefox" {
			hasXul := fileExistsAndNonEmpty(filepath.Join(dir, "xul.dll"))
			hasOmni := fileExistsAndNonEmpty(filepath.Join(dir, "omni.ja")) ||
				fileExistsAndNonEmpty(filepath.Join(dir, "browser", "omni.ja"))
			if !hasXul && !hasOmni {
				return false
			}
		} else if kernelType == "chrome" || kernelType == "safari" {
			hasDll := fileExistsAndNonEmpty(filepath.Join(dir, "chrome.dll"))
			hasPak := fileExistsAndNonEmpty(filepath.Join(dir, "resources.pak")) ||
				fileExistsAndNonEmpty(filepath.Join(dir, "chrome_100_percent.pak"))
			if !hasDll && !hasPak && kernelType != "safari" {
				return false
			}
		}
	}
	return true
}

func fileExistsAndNonEmpty(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Size() > 0
}
