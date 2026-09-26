// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package monitor 实现网络变化监听，检测默认网关/接口/DNS 变化。
//
// 原理：定期检查 UDP Dial 到公网地址的本地源地址，该地址由系统路由表决定。
// 当默认网关变化（如 WiFi->4G），本地源地址通常会发生变化。
package public

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Monitor 网络变化监听器
type Monitor struct {
	checkInterval time.Duration
	onChange      func(Event)
	stopCh        chan struct{}
	wg            sync.WaitGroup

	// 上次检测状态
	lastLocalAddr   string
	lastInterfaceIP string
	lastDNS         string
	mu              sync.RWMutex
}

// Event 网络变化事件类型
type Event int

const (
	NoChange         Event = iota
	GatewayChanged         // 默认网关变化
	InterfaceChanged       // 网络接口变化（WiFi<->4G）
	DNSChanged             // DNS 服务器变化
)

func (e Event) String() string {
	switch e {
	case GatewayChanged:
		return "gateway_changed"
	case InterfaceChanged:
		return "interface_changed"
	case DNSChanged:
		return "dns_changed"
	default:
		return "no_change"
	}
}

// Config 监听器配置
type Config struct {
	CheckInterval time.Duration
}

// DefaultConfig 默认配置
func DefaultConfig() Config {
	return Config{
		CheckInterval: 5 * time.Second,
	}
}

// New 创建网络变化监听器
func NewMonitor(onChange func(Event)) *Monitor {
	return &Monitor{
		checkInterval: DefaultConfig().CheckInterval,
		onChange:      onChange,
		stopCh:        make(chan struct{}),
	}
}

// Start 启动监听
func (m *Monitor) Start() {
	m.wg.Add(1)
	go m.loop()
}

// Stop 停止监听
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

// loop 主循环
func (m *Monitor) loop() {
	defer m.wg.Done()

	// 初始状态采样
	m.snapshot()
	log.Printf("[MONITOR] Started on %s, initial gateway=%s", runtime.GOOS, m.lastLocalAddr)

	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			ev := m.detect()
			if ev != NoChange {
				log.Printf("[MONITOR] Network change detected: %s src=%s", ev.String(), m.getDefaultRouteAddr())
				m.onChange(ev)
			}
		}
	}
}

// snapshot 保存当前网络状态
func (m *Monitor) snapshot() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastLocalAddr = m.getDefaultRouteAddr()
	m.lastInterfaceIP = m.getPrimaryInterfaceIP()
	m.lastDNS = m.getPrimaryDNS()
}

// detect 检测网络变化，返回变化事件
func (m *Monitor) detect() Event {
	// 1. 检测默认路由源地址变化
	currentAddr := m.getDefaultRouteAddr()
	m.mu.RLock()
	lastAddr := m.lastLocalAddr
	m.mu.RUnlock()

	if currentAddr != "" && currentAddr != lastAddr {
		m.mu.Lock()
		m.lastLocalAddr = currentAddr
		m.mu.Unlock()
		return GatewayChanged
	}

	// 2. 检测主接口 IP 变化
	currentIP := m.getPrimaryInterfaceIP()
	m.mu.RLock()
	lastIP := m.lastInterfaceIP
	m.mu.RUnlock()

	if currentIP != "" && currentIP != lastIP {
		m.mu.Lock()
		m.lastInterfaceIP = currentIP
		m.mu.Unlock()
		return InterfaceChanged
	}

	return NoChange
}

// emitIfPhysicalChanged is for OS event callbacks. Only fires onChange when
// the physical NIC address actually moved (Wi-Fi switch). Adapter noise
// (TUN up, metric, IPv6 RA) must not reset the tunnel.
func (m *Monitor) emitIfPhysicalChanged() {
	src := m.getDefaultRouteAddr()
	if src == "" {
		return
	}
	m.mu.Lock()
	if src == m.lastLocalAddr {
		m.mu.Unlock()
		return
	}
	prev := m.lastLocalAddr
	m.lastLocalAddr = src
	cb := m.onChange
	m.mu.Unlock()
	log.Printf("[MONITOR] physical source %s -> %s", prev, src)
	if cb != nil {
		cb(InterfaceChanged)
	}
}

// getDefaultRouteAddr 通过 UDP Dial 获取默认路由选择的本地地址
// 原理：UDP 不需要实际发送数据，Dial 时系统就会根据路由表选择接口
func (m *Monitor) getDefaultRouteAddr() string {
	if src := platformDefaultSource(); src != "" {
		return src
	}
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		ip := udpAddr.IP.String()
		if strings.HasPrefix(ip, "10.88.") {
			return ""
		}
		return ip
	}
	return ""
}

// getPrimaryInterfaceIP 获取主网络接口的 IP
func (m *Monitor) getPrimaryInterfaceIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		n := strings.ToLower(iface.Name)
		if strings.Contains(n, "aero") || strings.Contains(n, "wintun") || strings.Contains(n, "tun") {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				ip := ipnet.IP.To4()
				if ip == nil {
					continue
				}
				if ip[0] == 10 && ip[1] == 88 {
					continue
				}
				return ip.String()
			}
		}
	}
	return ""
}

// getPrimaryDNS 获取主 DNS 服务器（平台相关）
func (m *Monitor) getPrimaryDNS() string {
	// 通用实现：使用系统默认解析器查询
	// 实际 DNS 服务器获取需要平台特定代码
	return ""
}

// String 返回当前网络状态描述
func (m *Monitor) String() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return fmt.Sprintf("gateway=%s interface=%s", m.lastLocalAddr, m.lastInterfaceIP)
}

// monitor compatibility wrapper
var monitor = struct {
	New func(func(Event)) *Monitor
}{
	New: NewMonitor,
}
