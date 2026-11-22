//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"log"
	"sync"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// windowsNetworkMonitor 基于 winipcfg 的接口/路由变化回调。
// winipcfg 在包级只建一次系统回调（windows.NewCallback 不可释放且总数有上限），
// 这里每次 Start 只登记/撤销自己的处理函数，可被 engine 反复 Start/Stop。
type windowsNetworkMonitor struct {
	watcher *debounceWatcher

	mu      sync.Mutex
	ifCb    *winipcfg.InterfaceChangeCallback
	routeCb *winipcfg.RouteChangeCallback
}

func newPlatformNetworkMonitor() NetworkMonitor {
	return &windowsNetworkMonitor{
		watcher: newDebounceWatcher(),
	}
}

func (m *windowsNetworkMonitor) Start(onChange func(newGW, ifName string)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 已登记则不重复注册（重复 Start）
	if m.ifCb != nil || m.routeCb != nil {
		return
	}

	m.watcher.start(onChange)

	// 回调只做非阻塞 trigger，评估在防抖 loop 中完成
	ifCb, err := winipcfg.RegisterInterfaceChangeCallback(func(_ winipcfg.MibNotificationType, _ *winipcfg.MibIPInterfaceRow) {
		m.watcher.trigger()
	})
	if err != nil {
		log.Printf("[NETMON] Windows RegisterInterfaceChangeCallback failed: %v", err)
		m.watcher.stop()
		return
	}

	routeCb, err := winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		// 只关心默认路由（IPv4 0.0.0.0/0 或 IPv6 ::/0）：前缀长度为 0
		if route != nil && route.DestinationPrefix.PrefixLength == 0 {
			m.watcher.trigger()
		}
	})
	if err != nil {
		log.Printf("[NETMON] Windows RegisterRouteChangeCallback failed: %v", err)
		if uerr := ifCb.Unregister(); uerr != nil {
			log.Printf("[NETMON] Windows interface change callback unregister failed: %v", uerr)
		}
		m.watcher.stop()
		return
	}

	m.ifCb = ifCb
	m.routeCb = routeCb
}

func (m *windowsNetworkMonitor) Stop() {
	m.mu.Lock()
	ifCb, routeCb := m.ifCb, m.routeCb
	m.ifCb, m.routeCb = nil, nil
	m.mu.Unlock()

	// 先撤销回调（Unregister 会等待在途回调返回），再停 watcher
	if ifCb != nil {
		if err := ifCb.Unregister(); err != nil {
			log.Printf("[NETMON] Windows interface change callback unregister failed: %v", err)
		}
	}
	if routeCb != nil {
		if err := routeCb.Unregister(); err != nil {
			log.Printf("[NETMON] Windows route change callback unregister failed: %v", err)
		}
	}
	m.watcher.stop()
}
