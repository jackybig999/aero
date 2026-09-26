// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

//go:build windows

package public

import (
	"log"
	"syscall"
	"unsafe"

	"github.com/aero-protocol/aero-ech/internal/tun"
)

var (
	modiphlpapi                 = syscall.NewLazyDLL("iphlpapi.dll")
	procNotifyIpInterfaceChange = modiphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2  = modiphlpapi.NewProc("CancelMibChangeNotify2")
)

// StartPlatformMonitor 启动 Windows 平台原生网络变化监听
// 使用 NotifyIpInterfaceChange API 接收系统级网络接口变更事件
func (m *Monitor) StartPlatformMonitor() {
	// Windows Vista+ 支持 NotifyIpInterfaceChange
	// 如果 API 不可用，回退到通用轮询（已在 loop() 中实现）
	if procNotifyIpInterfaceChange.Find() != nil {
		log.Printf("[MONITOR] NotifyIpInterfaceChange not available, using polling fallback")
		return
	}

	m.wg.Add(1)
	go m.windowsEventLoop()
}

// windowsEventLoop Windows 原生事件循环
func (m *Monitor) windowsEventLoop() {
	defer m.wg.Done()

	// 创建事件通知句柄
	var handle uintptr

	callback := syscall.NewCallback(func(callerContext, row, notificationType uintptr) uintptr {
		// type 0 (parameter) storms when we add /1 routes. Only emit if the
		// physical NIC address changed; polling detect() is the backup.
		m.emitIfPhysicalChanged()
		return 0
	})

	ret, _, _ := procNotifyIpInterfaceChange.Call(
		0,                                // Family: AF_UNSPEC (IPv4 + IPv6)
		callback,                         // Callback
		0,                                // CallerContext
		0,                                // InitialNotification: FALSE
		uintptr(unsafe.Pointer(&handle)), // NotificationHandle
	)

	if ret != 0 {
		log.Printf("[MONITOR] NotifyIpInterfaceChange failed: %d, using polling fallback", ret)
		return
	}

	log.Printf("[MONITOR] Windows native IP interface monitoring active")

	// 等待停止信号
	<-m.stopCh

	// 取消通知
	procCancelMibChangeNotify2.Call(handle)
	log.Printf("[MONITOR] Windows native monitoring stopped")
}

func platformDefaultSource() string {
	if ip := tun.PhysicalIfaceIPv4(); ip != nil {
		return ip.String()
	}
	return ""
}
