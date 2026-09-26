// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package aimetrics 记录可演示的 AI 隧道指标（首包延迟 FTL、流量、会话数）。
// FTL 定义：首字节上行发出 → 首字节下行到达（代理视角 TTFB，非模型 token 语义）。
package public

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const maxSamples = 64

// Snapshot 只读导出（JSON 友好）
type Snapshot struct {
	AISessions  uint64   `json:"ai_sessions"`
	FTLCount    uint64   `json:"ftl_count"`
	FTLAvgMs    uint64   `json:"ftl_avg_ms"`
	FTLLastMs   uint64   `json:"ftl_last_ms"`
	FTLP50Ms    uint64   `json:"ftl_p50_ms"`
	FTLP95Ms    uint64   `json:"ftl_p95_ms"`
	BytesSentAI uint64   `json:"bytes_sent_ai"`
	BytesRecvAI uint64   `json:"bytes_recv_ai"`
	LastHost    string   `json:"last_host,omitempty"`
	LastModel   string   `json:"last_model,omitempty"`
	LastAtUnix  int64    `json:"last_at_unix,omitempty"`
	RecentFTLMs []uint64 `json:"recent_ftl_ms,omitempty"`
	Note        string   `json:"note"`
}

// Recorder 线程安全指标器
type Recorder struct {
	mu        sync.Mutex
	sessions  atomic.Uint64
	ftlSum    atomic.Uint64
	ftlN      atomic.Uint64
	ftlLast   atomic.Uint64
	sent      atomic.Uint64
	recv      atomic.Uint64
	samples   []uint64
	lastHost  string
	lastModel string
	lastAt    time.Time
}

// Default 进程级单例（供 API 与隧道共用）
var Default = New()

// New 创建记录器
func New() *Recorder {
	return &Recorder{samples: make([]uint64, 0, maxSamples)}
}

// RecordSession 开始一次 AI 流
func (r *Recorder) RecordSession(host, model string) {
	r.sessions.Add(1)
	r.mu.Lock()
	r.lastHost = host
	r.lastModel = model
	r.lastAt = time.Now()
	r.mu.Unlock()
}

// RecordFTL 记录一次首包延迟（毫秒）
func (r *Recorder) RecordFTL(ms uint64, host, model string) {
	if ms == 0 {
		ms = 1
	}
	r.ftlSum.Add(ms)
	r.ftlN.Add(1)
	r.ftlLast.Store(ms)
	r.mu.Lock()
	r.samples = append(r.samples, ms)
	if len(r.samples) > maxSamples {
		r.samples = r.samples[len(r.samples)-maxSamples:]
	}
	if host != "" {
		r.lastHost = host
	}
	if model != "" {
		r.lastModel = model
	}
	r.lastAt = time.Now()
	r.mu.Unlock()
}

// AddBytes 累加 AI 流字节
func (r *Recorder) AddBytes(sent, recv uint64) {
	if sent > 0 {
		r.sent.Add(sent)
	}
	if recv > 0 {
		r.recv.Add(recv)
	}
}

// Snapshot 导出当前指标
func (r *Recorder) Snapshot() Snapshot {
	n := r.ftlN.Load()
	var avg uint64
	if n > 0 {
		avg = r.ftlSum.Load() / n
	}
	r.mu.Lock()
	samples := append([]uint64(nil), r.samples...)
	host, model := r.lastHost, r.lastModel
	var lastUnix int64
	if !r.lastAt.IsZero() {
		lastUnix = r.lastAt.Unix()
	}
	r.mu.Unlock()

	p50, p95 := percentile(samples, 50), percentile(samples, 95)
	return Snapshot{
		AISessions:  r.sessions.Load(),
		FTLCount:    n,
		FTLAvgMs:    avg,
		FTLLastMs:   r.ftlLast.Load(),
		FTLP50Ms:    p50,
		FTLP95Ms:    p95,
		BytesSentAI: r.sent.Load(),
		BytesRecvAI: r.recv.Load(),
		LastHost:    host,
		LastModel:   model,
		LastAtUnix:  lastUnix,
		RecentFTLMs: samples,
		Note:        "ftl = proxy first-byte latency (client uplink start -> first downlink byte), not model token latency",
	}
}

func percentile(samples []uint64, p int) uint64 {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]uint64(nil), samples...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	if p <= 0 {
		return cp[0]
	}
	if p >= 100 {
		return cp[len(cp)-1]
	}
	idx := (p * (len(cp) - 1)) / 100
	return cp[idx]
}

// aimetrics compatibility wrapper
var aimetrics = struct {
	Default *Recorder
}{
	Default: Default,
}
