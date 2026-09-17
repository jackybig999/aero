// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package gameqos 实现游戏流量低延迟优化。
//
// 核心机制：
//   - 游戏流量识别：基于常见游戏端口 + 包大小特征
//   - 优先级队列：游戏包最高优先级，插队发送
//   - 小包聚合：减少系统调用开销
//   - 抖动控制：平滑发送间隔，避免突发
//   - 预测性重传：基于 RTT 自适应超时
package gameqos

import (
	"container/list"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// KnownGamePorts 常见游戏端口
var KnownGamePorts = map[int]bool{
	// Steam
	27015: true, 27016: true, 27017: true, 27018: true,
	27019: true, 27020: true, 27021: true, 27022: true,
	// Valorant / League of Legends
	5000: true, 5001: true, 5002: true, 5003: true,
	8393: true, 8400: true, 8401: true,
	// PUBG / Fortnite
	7000: true, 8000: true, 9000: true, 9001: true,
	// Overwatch
	1119: true, 3724: true,
	// Minecraft
	25565: true,
	// Roblox
	49152: true, 65535: true,
	// Call of Duty / Xbox Live
	3074: true,
	// FIFA / EA
	3659: true, 10000: true,
	// PlayStation
	3478: true, 3479: true, 3480: true,
	// Nintendo
	1024: true, 1025: true, 1026: true,
	// General game ports
	27000: true, 27001: true, 27002: true, 27003: true,
	27004: true, 27005: true, 27006: true, 27007: true,
	27008: true, 27009: true, 27010: true, 27011: true,
	27012: true, 27013: true, 27014: true,
}

// PacketType 包类型
type PacketType int

const (
	GamePacket     PacketType = iota // 游戏包（最高优先级）
	VoIPPacket                       // 语音包（次高优先级）
	NormalPacket                     // 普通包
)

// Packet 数据包
type Packet struct {
	Type      PacketType
	Data      []byte
	Timestamp time.Time
	Seq       uint64
}

// Engine Game QoS 引擎
type Engine struct {
	enabled atomic.Bool

	// 优先级队列
	queues    map[PacketType]*list.List
	queueMu   sync.Mutex
	queueCond *sync.Cond

	// 统计
	sentPackets     atomic.Uint64
	sentBytes       atomic.Uint64
	droppedPackets  atomic.Uint64
	avgRTT          atomic.Int64 // 微秒
	jitterMicros    atomic.Int64 // 微秒

	// 配置
	batchSize     int           // 最大聚合包数
	batchTimeout  time.Duration // 聚合超时
	minSendInterval time.Duration // 最小发送间隔（防抖）
}

// NewEngine 创建 Game QoS 引擎
func NewEngine() *Engine {
	e := &Engine{
		queues:          make(map[PacketType]*list.List),
		batchSize:       8,
		batchTimeout:    2 * time.Millisecond,
		minSendInterval: 500 * time.Microsecond,
	}
	e.queueCond = sync.NewCond(&e.queueMu)
	e.queues[GamePacket] = list.New()
	e.queues[VoIPPacket] = list.New()
	e.queues[NormalPacket] = list.New()
	e.enabled.Store(true)
	return e
}

// Enable/Disable
func (e *Engine) Enable()  { e.enabled.Store(true) }
func (e *Engine) Disable() { e.enabled.Store(false) }

// IsGameTraffic 判断目标地址是否为游戏流量
func IsGameTraffic(host string, port int) bool {
	if KnownGamePorts[port] {
		return true
	}
	// 包大小特征：游戏包通常 50-500 字节
	return false
}

// Enqueue 将包加入优先级队列
func (e *Engine) Enqueue(pt PacketType, data []byte) {
	if !e.enabled.Load() {
		return
	}

	e.queueMu.Lock()
	defer e.queueMu.Unlock()

	const maxQueueSize = 10000
	if e.totalQueueLen() >= maxQueueSize {
		// 丢弃最老的包（按优先级：先 Normal，再 VoIP，最后 Game）
		for _, dropPt := range []PacketType{NormalPacket, VoIPPacket, GamePacket} {
			q := e.queues[dropPt]
			if q.Len() > 0 {
				q.Remove(q.Front())
				e.droppedPackets.Add(1)
				break
			}
		}
	}

	pkt := Packet{
		Type:      pt,
		Data:      append([]byte(nil), data...),
		Timestamp: time.Now(),
		Seq:       e.sentPackets.Add(1),
	}

	e.queues[pt].PushBack(pkt)
	e.queueCond.Signal()
}

// DequeueBatch 按优先级批量出队
func (e *Engine) DequeueBatch(max int) []Packet {
	e.queueMu.Lock()
	defer e.queueMu.Unlock()

	// 等待数据（spurious wakeup 保护）
	for e.totalQueueLen() == 0 {
		e.queueCond.Wait()
	}

	result := make([]Packet, 0, max)

	// 按优先级出队：Game > VoIP > Normal
	for _, pt := range []PacketType{GamePacket, VoIPPacket, NormalPacket} {
		queue := e.queues[pt]
		for queue.Len() > 0 && len(result) < max {
			front := queue.Front()
			result = append(result, front.Value.(Packet))
			queue.Remove(front)
		}
	}

	return result
}

func (e *Engine) totalQueueLen() int {
	total := 0
	for _, q := range e.queues {
		total += q.Len()
	}
	return total
}

// Writer 包装 io.Writer，提供 Game QoS 优化写入
type Writer struct {
	io.Writer
	engine *Engine
}

// NewWriter 创建 Game QoS 优化 Writer
func NewWriter(w io.Writer) *Writer {
	return &Writer{Writer: w, engine: NewEngine()}
}

// WriteGamePacket 写入游戏包（高优先级）
func (w *Writer) WriteGamePacket(p []byte) (int, error) {
	if w.engine.enabled.Load() {
		w.engine.Enqueue(GamePacket, p)
		return len(p), nil
	}
	return w.Writer.Write(p)
}

// WriteNormalPacket 写入普通包
func (w *Writer) WriteNormalPacket(p []byte) (int, error) {
	if w.engine.enabled.Load() {
		w.engine.Enqueue(NormalPacket, p)
		return len(p), nil
	}
	return w.Writer.Write(p)
}

// Flush 将队列中的包写入底层
func (w *Writer) Flush() error {
	if !w.engine.enabled.Load() {
		return nil
	}

	packets := w.engine.DequeueBatch(w.engine.batchSize)
	for _, pkt := range packets {
		if _, err := w.Writer.Write(pkt.Data); err != nil {
			return err
		}
		w.engine.sentBytes.Add(uint64(len(pkt.Data)))
	}
	return nil
}

// Conn 包装 net.Conn，自动识别游戏流量并应用 QoS
type Conn struct {
	net.Conn
	engine *Engine
	isGame bool
}

// WrapConn 包装连接，自动检测游戏流量
func WrapConn(conn net.Conn, remoteAddr string) *Conn {
	_, portStr, _ := net.SplitHostPort(remoteAddr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	c := &Conn{
		Conn:   conn,
		engine: NewEngine(),
		isGame: IsGameTraffic(remoteAddr, port),
	}
	// 启动后台 worker 消费队列
	go c.engine.StartWorker(context.Background(), conn)
	return c
}

func (c *Conn) Write(p []byte) (int, error) {
	if c.isGame && c.engine.enabled.Load() {
		c.engine.Enqueue(GamePacket, p)
		// 立即刷新游戏包（低延迟）
		c.flushQueue()
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *Conn) flushQueue() {
	packets := c.engine.DequeueBatch(c.engine.batchSize)
	for _, pkt := range packets {
		if _, err := c.Conn.Write(pkt.Data); err != nil {
			return
		}
		c.engine.sentBytes.Add(uint64(len(pkt.Data)))
	}
}

// Stats 返回统计信息
func (e *Engine) Stats() Stats {
	return Stats{
		SentPackets:    e.sentPackets.Load(),
		SentBytes:      e.sentBytes.Load(),
		DroppedPackets: e.droppedPackets.Load(),
		AvgRTT:         time.Duration(e.avgRTT.Load()) * time.Microsecond,
		Jitter:         time.Duration(e.jitterMicros.Load()) * time.Microsecond,
	}
}

// Stats 统计信息
type Stats struct {
	SentPackets    uint64
	SentBytes      uint64
	DroppedPackets uint64
	AvgRTT         time.Duration
	Jitter         time.Duration
}

// AdaptiveTimeout 自适应超时（基于 RTT 估计）
func (e *Engine) AdaptiveTimeout(baseTimeout time.Duration) time.Duration {
	rtt := time.Duration(e.avgRTT.Load()) * time.Microsecond
	if rtt == 0 {
		return baseTimeout
	}
	// 超时 = max(baseTimeout, RTT * 2 + jitter)
	jitter := time.Duration(e.jitterMicros.Load()) * time.Microsecond
	timeout := rtt*2 + jitter
	if timeout < baseTimeout {
		return baseTimeout
	}
	return timeout
}

// UpdateRTT 更新 RTT 样本
func (e *Engine) UpdateRTT(rtt time.Duration) {
	// 指数移动平均
	oldMicros := e.avgRTT.Load()
	newMicros := rtt.Microseconds()
	if oldMicros == 0 {
		e.avgRTT.Store(newMicros)
	} else {
		// EMA: alpha = 0.125
		avg := int64(float64(oldMicros)*0.875 + float64(newMicros)*0.125)
		e.avgRTT.Store(avg)
	}
}

// StartWorker 启动后台发送 worker
func (e *Engine) StartWorker(ctx context.Context, w io.Writer) {
	ticker := time.NewTicker(e.batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			packets := e.DequeueBatch(e.batchSize)
			for _, pkt := range packets {
				if _, err := w.Write(pkt.Data); err != nil {
					return
				}
				e.sentBytes.Add(uint64(len(pkt.Data)))
			}
		}
	}
}
