// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

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
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
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

	// 初始指纹采样，防止启动阶段无意义自触发
	if gw, ifName, err := PhysicalDefaultGateway(); err == nil && gw != "" {
		w.lastFingerprint = gw + "@" + ifName
	}
	w.mu.Unlock()

	go w.loop()
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
	close(w.stopCh)
	w.mu.Unlock()

	<-w.doneCh
}

func (w *debounceWatcher) loop() {
	defer close(w.doneCh)
	var timer *time.Timer
	var timerCh <-chan time.Time

	for {
		select {
		case <-w.stopCh:
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
