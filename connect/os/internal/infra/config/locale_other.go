//go:build !windows

package config

import (
	"os"
	"runtime"
	"strings"
)

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
