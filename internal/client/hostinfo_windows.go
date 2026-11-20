//go:build windows

package client

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// ProcessElevated 报告当前进程是否以管理员权限（UAC 已提权）运行。创建 wintun 网卡需要它。
func ProcessElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// HostDescription 返回用于日志的系统描述（排查“换了一台机器就不行”时需要）。
func HostDescription() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("Windows %d.%d build %d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}
