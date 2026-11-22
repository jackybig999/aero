// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"log"
	"strings"
	"sync"
	"time"
)

// NetworkMonitor 监听物理网络接口与默认网关变动
type NetworkMonitor interface {
	Start(onChange func(newGW, ifName string))
	Stop()
}

// NewNetworkMonitor 创建针对当前平台的网络监控器
func NewNetworkMonitor() NetworkMonitor {
	return newPlatformNetworkMonitor()
}

// debounceWatcher 通用 300ms 防抖与网络指纹去重器
type debounceWatcher struct {
	mu              sync.Mutex
	lastFingerprint string
	onChange        func(newGW, ifName string)
	triggerCh       chan struct{}
	stopCh          chan struct{}
	doneCh          chan struct{}
	running         bool
	debounce        time.Duration
}

func newDebounceWatcher() *debounceWatcher {
	return &debounceWatcher{
		triggerCh: make(chan struct{}, 1),
		debounce:  300 * time.Millisecond,
	}
}

func (w *debounceWatcher) start(onChange func(newGW, ifName string)) {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	w.onChange = onChange
	// 每次 start 重建退出通道：engine 会对同一个监控器反复 Start/Stop，
	// 复用已关闭的通道会让新 loop 立即退出并重复 close(doneCh) 而 panic
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	w.stopCh = stopCh
	w.doneCh = doneCh

	// 初始指纹采样，防止启动阶段无意义自触发；先失效缓存，避免以过期网关作基线
	invalidateGatewayCache()
	if gw, ifName, err := PhysicalDefaultGateway(); err == nil && gw != "" {
		w.lastFingerprint = gw + "@" + ifName
	}
	w.mu.Unlock()

	go w.loop(stopCh, doneCh)
}

func (w *debounceWatcher) trigger() {
	select {
	case w.triggerCh <- struct{}{}:
	default:
	}
}

func (w *debounceWatcher) stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	stopCh, doneCh := w.stopCh, w.doneCh
	w.mu.Unlock()

	close(stopCh)
	<-doneCh
}

func (w *debounceWatcher) loop(stopCh <-chan struct{}, doneCh chan<- struct{}) {
	defer close(doneCh)
	var timer *time.Timer
	var timerCh <-chan time.Time

	for {
		select {
		case <-stopCh:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-w.triggerCh:
			if timer == nil {
				timer = time.NewTimer(w.debounce)
				timerCh = timer.C
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(w.debounce)
			}
		case <-timerCh:
			timer = nil
			timerCh = nil
			w.evaluate()
		}
	}
}

func (w *debounceWatcher) evaluate() {
	// PhysicalDefaultGateway 有 15 秒缓存；防抖后若恰在缓存期内会读到旧网关，
	// 指纹不变且之后不再有事件，这次切换就永久漏检。读取前必须先失效缓存。
	invalidateGatewayCache()
	gw, ifName, err := PhysicalDefaultGateway()
	if err != nil || gw == "" {
		return
	}
	// 严格阻断针对虚拟网卡自身的路由/接口变动自触发循环
	if strings.Contains(strings.ToLower(ifName), "aero") {
		return
	}
	fp := gw + "@" + ifName

	w.mu.Lock()
	if fp == w.lastFingerprint {
		w.mu.Unlock()
		return
	}
	w.lastFingerprint = fp
	cb := w.onChange
	w.mu.Unlock()

	log.Printf("[NETMON] Physical network change confirmed: gw=%s, iface=%s", gw, ifName)
	if cb != nil {
		cb(gw, ifName)
	}
}
