//go:build windows

package config

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

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
