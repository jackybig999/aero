// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package clienttunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aero-protocol/aero-ech/internal/split"
	"github.com/aero-protocol/aero-ech/internal/sub"
	"github.com/aero-protocol/aero-ech/internal/tun"
)

// Stats 隧道实时运行统计
type Stats struct {
	IsRunning      bool          `json:"isRunning"`
	ServerAddress  string        `json:"serverAddress"`
	BytesSent      uint64        `json:"bytesSent"`
	BytesRecv      uint64        `json:"bytesRecv"`
	PacketsSent    uint64        `json:"packetsSent"`
	PacketsRecv    uint64        `json:"packetsRecv"`
	CurrentPath    string        `json:"currentPath"`
	RTT            time.Duration `json:"rtt"`
	AiTokensTotal  uint32        `json:"aiTokensTotal"`
	AiFirstTokenMs uint64        `json:"aiFirstTokenMs"`
}

// Engine 跨平台客户端核心协议与隧道引擎
type Engine struct {
	cfg       Config
	cfgMu     sync.RWMutex
	split     *split.Engine
	dialer    *AERODialer
	tunEngine *tun.Engine
	device    tun.Device
	memDev    *tun.MemDevice

	isRunning atomic.Bool
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	pktsIn  atomic.Uint64
	pktsOut atomic.Uint64
}

// NewEngine 创建跨平台统一隧道引擎实例
func NewEngine(cfg Config) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	splitEng := split.NewEngine()
	dialer := NewAERODialer(cfg, splitEng)

	ctx, cancel := context.WithCancel(context.Background())

	return &Engine{
		cfg:    cfg,
		split:  splitEng,
		dialer: dialer,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// StartWithDevice 绑定平台硬件/虚拟网卡设备启动（适用于 Windows wintun、macOS utun、Linux tun）
func (e *Engine) StartWithDevice(dev tun.Device) error {
	if e.isRunning.Swap(true) {
		return fmt.Errorf("tunnel engine already running")
	}

	e.device = dev
	cfg := e.GetConfig()

	tunCfg := tun.Config{
		MTU:          cfg.MTU,
		IPv4:         "10.88.0.2/24",
		IPv6:         "fd00:aero::2/64",
		Routes:       []string{"0.0.0.0/0"},
		DNSServers:   cfg.DNS,
		FakeIPRange:  "198.18.0.0/15",
		FakeIPEnable: false, // 纯 gVisor 真实目的 IP 模式，避免 fake-ip 黑洞
	}

	eng := tun.New(dev, tunCfg, &tunSplitAdapter{engine: e.split}, e.dialer)
	e.tunEngine = eng

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		log.Printf("[ENGINE] Start TUN data plane on device %s (mtu=%d)", dev.Name(), cfg.MTU)
		_ = eng.Start()
	}()

	// 若提供了订阅 URL，启动后台订阅自愈
	if cfg.SubscriptionURL != "" {
		go e.subscriptionLoop(e.ctx, cfg.SubscriptionURL)
	}

	return nil
}

// StartPacketTunnel 纯内存包模式启动（适用于 iOS NEPacketTunnelProvider / Android VpnService 内存注入）
// onPacketOut 为 gVisor 产出下行数据包时写回系统的回调
func (e *Engine) StartPacketTunnel(onPacketOut func([]byte)) error {
	mem := tun.NewMemDevice()
	if onPacketOut != nil {
		mem.SetOnPacket(func(pkt []byte) {
			e.pktsOut.Add(1)
			onPacketOut(pkt)
		})
	}
	e.memDev = mem
	return e.StartWithDevice(mem)
}

// HandlePacket 注入系统捕获的一个 IP 数据包（移动端使用）
func (e *Engine) HandlePacket(pkt []byte) error {
	if !e.isRunning.Load() {
		return fmt.Errorf("tunnel not running")
	}
	if len(pkt) == 0 {
		return nil
	}
	e.pktsIn.Add(1)
	if e.memDev != nil {
		e.memDev.Inject(pkt)
		return nil
	}
	if e.device != nil {
		_, err := e.device.Write(pkt)
		return err
	}
	return fmt.Errorf("no packet sink configured")
}

// Stop 停止隧道引擎
func (e *Engine) Stop() {
	if !e.isRunning.Swap(false) {
		return
	}
	if e.cancel != nil {
		e.cancel()
	}
	if e.tunEngine != nil {
		e.tunEngine.Stop()
	}
	if e.device != nil {
		_ = e.device.Close()
	}
	e.wg.Wait()
	log.Printf("[ENGINE] Tunnel stopped")
}

// IsRunning 返回是否正在运行
func (e *Engine) IsRunning() bool {
	return e.isRunning.Load()
}

// UpdateRules 动态更新分流规则（传入 JSON 格式规则）
func (e *Engine) UpdateRules(rulesJSON []byte) error {
	var rules []split.Rule
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		return fmt.Errorf("unmarshal rules: %w", err)
	}
	for _, r := range rules {
		e.split.AddRule(r)
	}
	return nil
}

// UpdateConfig 动态更新配置（热重载，如从订阅更新节点地址或 Token）
func (e *Engine) UpdateConfig(cfg Config) {
	e.cfgMu.Lock()
	e.cfg = cfg
	e.cfgMu.Unlock()
	e.dialer.UpdateConfig(cfg)
}

// GetConfig 获取当前配置快照
func (e *Engine) GetConfig() Config {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return e.cfg
}

// Stats 返回当前统计数据
func (e *Engine) Stats() Stats {
	cfg := e.GetConfig()
	return Stats{
		IsRunning:     e.isRunning.Load(),
		ServerAddress: cfg.ServerAddress,
		BytesSent:     e.dialer.bytesSent.Load(),
		BytesRecv:     e.dialer.bytesRecv.Load(),
		PacketsSent:   e.pktsIn.Load(),
		PacketsRecv:   e.pktsOut.Load(),
		CurrentPath:   "AERO/H2",
	}
}

// subscriptionLoop 定时拉取订阅并自愈节点
func (e *Engine) subscriptionLoop(ctx context.Context, subURL string) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	// 启动时先拉一次
	e.refreshSubscription(subURL)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.refreshSubscription(subURL)
		}
	}
}

func (e *Engine) refreshSubscription(subURL string) {
	s, err := sub.Fetch(subURL, sub.FetchOptions{Timeout: 15 * time.Second})
	if err != nil {
		log.Printf("[ENGINE] sub refresh failed: %v", err)
		return
	}
	if len(s.Servers) == 0 {
		return
	}

	best := s.Servers[0]
	curr := e.GetConfig()
	if best.Address != "" && (best.Address != curr.ServerAddress || (best.Token != "" && best.Token != curr.Token)) {
		log.Printf("[ENGINE] sub updated: server %s -> %s", curr.ServerAddress, best.Address)
		curr.ServerAddress = best.Address
		if best.Token != "" {
			curr.Token = best.Token
		}
		if best.SNI != "" {
			curr.SNIName = best.SNI
		}
		e.UpdateConfig(curr)
	}
}

type tunSplitAdapter struct {
	engine *split.Engine
}

func (a *tunSplitAdapter) Decide(domain string) string {
	if a.engine == nil {
		return "proxy"
	}
	return strings.ToLower(a.engine.MatchDomain(domain).String())
}
