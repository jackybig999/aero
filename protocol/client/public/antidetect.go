package public

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	mrand "math/rand"
	"sync"
	"time"
)

// --- fingerprint.go ---
// 抗检测：TLS 指纹随机化轮换
//
// 策略：每次重连时随机选择 Chrome/Firefox/Safari 指纹
// 避免长期使用同一指纹形成可被识别的固定特征


// FingerprintRotator 指纹轮换器
type FingerprintRotator struct {
	mu           sync.Mutex
	current      string
	fingerprints []string
}

// Available fingerprints
var (
	FingerprintChrome  = "chrome"
	FingerprintFirefox = "firefox"
	FingerprintSafari  = "safari"
	FingerprintRandom  = "random"
)

// NewFingerprintRotator 创建轮换器
func NewFingerprintRotator() *FingerprintRotator {
	return &FingerprintRotator{
		fingerprints: []string{"chrome", "firefox", "safari"},
		current:      "chrome",
	}
}

// Next 返回下一个随机指纹
func (r *FingerprintRotator) Next() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(r.fingerprints))))
	r.current = r.fingerprints[n.Int64()]
	return r.current
}

// Current 返回当前指纹
func (r *FingerprintRotator) Current() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}

// --- padding.go ---
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package antidetect 抗检测辅助。
// 主路径（SOCKS 隧道）禁止使用不可剥离的填充；见 Encode/Decode 协议级帧。


// PaddingConfig 协议级填充配置（双方必须一致启用才可开启）
type PaddingConfig struct {
	// Enabled 为 true 时 Encode 输出 [u32be len][payload][random pad]
	Enabled   bool
	BlockSize int // 对齐块，默认 256
	MinSize   int // 最小帧总长，默认 0（不对齐到 Min）
}

// DefaultPaddingConfig 主路径默认：关闭。
// 未实现端到端协商前不得默认开启。
func DefaultPaddingConfig() PaddingConfig {
	return PaddingConfig{
		Enabled:   false,
		BlockSize: 256,
		MinSize:   0,
	}
}

// Padder 协议级可剥离填充器
type Padder struct {
	config PaddingConfig
}

// NewPadder 创建填充器
func NewPadder(cfg PaddingConfig) *Padder {
	if cfg.BlockSize <= 0 {
		cfg.BlockSize = 256
	}
	return &Padder{config: cfg}
}

// Encode 编码：关闭时原样返回；开启时长度前缀 + 随机填充（可 Decode 还原）
func (p *Padder) Encode(data []byte) ([]byte, error) {
	if p == nil || !p.config.Enabled {
		return data, nil
	}
	if len(data) > 16*1024*1024 {
		return nil, fmt.Errorf("payload too large: %d", len(data))
	}
	bodyLen := 4 + len(data)
	size := bodyLen
	if p.config.MinSize > size {
		size = p.config.MinSize
	}
	if rem := size % p.config.BlockSize; rem != 0 {
		size += p.config.BlockSize - rem
	}
	out := make([]byte, size)
	binary.BigEndian.PutUint32(out[0:4], uint32(len(data)))
	copy(out[4:], data)
	if size > bodyLen {
		if _, err := rand.Read(out[bodyLen:]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Decode 解码 Encode 结果；关闭模式下把输入视为裸 payload
func (p *Padder) Decode(data []byte) ([]byte, error) {
	if p == nil || !p.config.Enabled {
		return data, nil
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("framed payload too short")
	}
	n := binary.BigEndian.Uint32(data[0:4])
	if int(n) > len(data)-4 {
		return nil, fmt.Errorf("framed length %d exceeds buffer %d", n, len(data)-4)
	}
	out := make([]byte, n)
	copy(out, data[4:4+n])
	return out, nil
}

// Pad 兼容旧调用：等价于 Encode，失败时返回原数据（主路径应检查 error）
// Deprecated: 使用 Encode/Decode。
func (p *Padder) Pad(data []byte) []byte {
	out, err := p.Encode(data)
	if err != nil {
		return data
	}
	return out
}

// --- timing.go ---
// 抗检测：时序抖动
//
// 策略：在数据帧发送之间加入微随机延迟（1-10ms），
// 打破基于包间隔的流量特征分析


// TimingConfig 时序配置
type TimingConfig struct {
	Enabled    bool
	MinDelayMs int // 最小随机延迟（毫秒）
	MaxDelayMs int // 最大随机延迟（毫秒）
}

// DefaultTimingConfig 默认配置。
// Enabled=false：每帧 1–10ms 抖动伤延迟，且对稳定主路径无收益；隐蔽模式可显式开启。
func DefaultTimingConfig() TimingConfig {
	return TimingConfig{
		Enabled:    false,
		MinDelayMs: 1,
		MaxDelayMs: 10,
	}
}

// Jitter 返回随机延迟时长
func Jitter(cfg TimingConfig) time.Duration {
	if !cfg.Enabled {
		return 0
	}
	ms := cfg.MinDelayMs + mrand.Intn(cfg.MaxDelayMs-cfg.MinDelayMs+1)
	return time.Duration(ms) * time.Millisecond
}
