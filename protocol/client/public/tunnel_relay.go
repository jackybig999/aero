package public

import (
	"context"
	"fmt"
	"github.com/aero-protocol/aero-ech/internal/edgepool"
	"github.com/aero-protocol/aero-ech/internal/gameqos"
	"github.com/aero-protocol/aero-ech/internal/transport"
	protocol "github.com/aero-protocol/proto"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// -----------------------------------------------------------------------------
// Source: tunnel_relay.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// relayParams 单次隧道会话的转发参数（主路径纯字节，无填充）
type relayParams struct {
	Client     net.Conn
	Tunnel     net.Conn
	StreamID   uint32
	StreamType protocol.StreamType
	SessionID  string
	TargetHost string
	TargetPort uint16
	UsedProto  string
	HBInterval time.Duration
	Bridge     *BridgeClient
	Detector   *edgepool.Detector
	OnDegraded func()
}

// serialConn serializes Write. Heartbeat and payload share one tunnel;
// concurrent Write on a pipe/H2 body interleaves frames.
type serialConn struct {
	net.Conn
	mu sync.Mutex
}

func (c *serialConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *serialConn) Unwrap() net.Conn {
	return c.Conn
}

// optimizeTCP 针对 TCP 连接调优：全量禁用 Nagle 消除延迟，AI 流注入 15s 密集保活探针
func optimizeTCP(c net.Conn, isAI bool) {
	if c == nil {
		return
	}
	for {
		type unwrapper interface {
			Unwrap() net.Conn
		}
		if u, ok := c.(unwrapper); ok {
			c = u.Unwrap()
		} else {
			break
		}
	}
	type noDelayer interface {
		SetNoDelay(bool) error
	}
	type keepAliver interface {
		SetKeepAlive(bool) error
		SetKeepAlivePeriod(time.Duration) error
	}
	if nd, ok := c.(noDelayer); ok {
		_ = nd.SetNoDelay(true)
	}
	if ka, ok := c.(keepAliver); ok {
		_ = ka.SetKeepAlive(true)
		if isAI {
			_ = ka.SetKeepAlivePeriod(15 * time.Second)
		} else {
			_ = ka.SetKeepAlivePeriod(30 * time.Second)
		}
	}
}

// runTunnelRelay 阻塞直到会话结束；返回是否应重连切换
func runTunnelRelay(p relayParams) (shouldSwitch bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, ok := p.Tunnel.(*serialConn); !ok {
		p.Tunnel = &serialConn{Conn: p.Tunnel}
	}

	isAI := p.StreamType == protocol.StreamType_AI
	optimizeTCP(p.Client, isAI)
	optimizeTCP(p.Tunnel, isAI)

	var switchMu sync.Mutex
	markSwitch := func() {
		switchMu.Lock()
		shouldSwitch = true
		switchMu.Unlock()
		cancel()
	}
	if p.OnDegraded != nil {
		// caller may also call markSwitch via OnDegraded
	}

	var bytesSent, bytesRecv atomic.Uint64
	var aiStart time.Time
	var aiOnce, bridgeOnce sync.Once
	var lastAck time.Time
	var ackMu sync.Mutex
	lastAck = time.Now()

	var hbSent time.Time
	var rttMs uint32
	var rttMu sync.Mutex

	hbInterval := p.HBInterval
	if isAI {
		// AI 深度思考长会话（如 DeepSeek R1/o1）：15s 密集探针
		hbInterval = 15 * time.Second
	} else if hbInterval < 5*time.Second {
		hbInterval = 30 * time.Second
	}
	// 协议：常规 3 个心跳周期无 ACK 判定超时；AI 深度思考给足容限（6 个周期 90s）
	hbTimeout := 3 * hbInterval
	if isAI {
		hbTimeout = 6 * hbInterval
	}

	model := inferModelName(p.TargetHost)
	if p.StreamType == protocol.StreamType_AI {
		aimetrics.Default.RecordSession(p.TargetHost, model)
		if p.Bridge != nil {
			if dec, err := p.Bridge.SendStreamOpened(
				p.SessionID, p.StreamID, p.TargetHost, p.TargetPort,
				p.StreamType.String(), p.UsedProto,
			); err != nil {
				log.Printf("[BRIDGE] SendStreamOpened: %v", err)
			} else if dec != nil && dec.Action == "switch" {
				markSwitch()
				return true
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(4)

	// A: client -> tunnel（裸 payload）
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 32768)
		seq := uint64(1)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := p.Client.Read(buf)
			if err != nil {
				return
			}
			if p.StreamType == protocol.StreamType_AI {
				aiOnce.Do(func() { aiStart = time.Now() })
			}
			frame := &protocol.TcpFrame{
				StreamId: p.StreamID,
				Payload:  buf[:n],
				Sequence: seq,
			}
			if err := protocol.TypedWriteMessage(p.Tunnel, protocol.MsgTypeTcpFrame, frame); err != nil {
				return
			}
			bytesSent.Add(uint64(n))
			seq++
		}
	}()

	// B: tunnel -> client
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			msgType, msg, err := protocol.TypedReadMessage(p.Tunnel)
			if err != nil {
				return
			}
			switch msgType {
			case protocol.MsgTypeTcpFrame:
				frame := msg.(*protocol.TcpFrame)
				if _, err := p.Client.Write(frame.Payload); err != nil {
					return
				}
				bytesRecv.Add(uint64(len(frame.Payload)))
				if p.StreamType == protocol.StreamType_AI {
					bridgeOnce.Do(func() {
						if aiStart.IsZero() {
							return
						}
						lat := uint64(time.Since(aiStart).Milliseconds())
						aimetrics.Default.RecordFTL(lat, p.TargetHost, model)
						log.Printf("[AI] FTL=%dms host=%s model=%s", lat, p.TargetHost, model)
						reportAIFTL(lat)
						if p.Bridge != nil {
							if dec, err := p.Bridge.SendFirstToken(p.SessionID, p.StreamID, lat, model); err == nil && dec != nil && dec.Action == "switch" {
								markSwitch()
							}
						}
					})
				}
			case protocol.MsgTypeHeartbeatAck:
				_ = msg.(*protocol.HeartbeatAck)
				ackMu.Lock()
				lastAck = time.Now()
				ackMu.Unlock()
				rttMu.Lock()
				if !hbSent.IsZero() {
					rttMs = uint32(time.Since(hbSent).Milliseconds())
				}
				cur := time.Duration(rttMs) * time.Millisecond
				rttMu.Unlock()
				// Do not auto-SWITCH on minor RTT jitter — kills live browser tabs.
				if p.Detector != nil {
					p.Detector.RecordRTT(cur)
				}
			case protocol.MsgTypeAiStreamFrame:
				frame := msg.(*protocol.AiStreamFrame)
				if _, err := p.Client.Write(frame.Payload); err != nil {
					return
				}
			default:
				log.Printf("[ROUTER] unknown msg 0x%02x", msgType)
			}
		}
	}()

	// C: heartbeat  D: metrics
	go func() {
		defer wg.Done()
		runHeartbeatLoop(ctx, cancel, p.Tunnel, hbInterval, hbTimeout, &lastAck, &ackMu, &hbSent, &rttMu, func() {
			if p.StreamType == protocol.StreamType_AI {
				transport.GlobalSessionPool.Reset()
				markSwitch()
			}
		})
	}()
	go func() {
		defer wg.Done()
		runMetricsLoop(ctx, p.Tunnel, p.SessionID, p.StreamID, p.StreamType,
			&bytesSent, &bytesRecv, &rttMs, &rttMu, p.Bridge)
	}()

	wg.Wait()
	if p.StreamType == protocol.StreamType_AI {
		aimetrics.Default.AddBytes(bytesSent.Load(), bytesRecv.Load())
		reportTraffic(bytesSent.Load(), bytesRecv.Load())
	} else {
		reportTraffic(bytesSent.Load(), bytesRecv.Load())
	}
	switchMu.Lock()
	defer switchMu.Unlock()
	return shouldSwitch
}

// -----------------------------------------------------------------------------
// Source: tunnel_classify.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// streamTarget 解析后的出站目标与流类型
type streamTarget struct {
	Raw        string
	Host       string
	Port       uint32
	StreamType protocol.StreamType
	IsGame     bool
}

// classifyTarget 根据地址判定 GENERAL / AI / UDP(游戏)
func classifyTarget(raw string) streamTarget {
	st := streamTarget{Raw: raw, StreamType: protocol.StreamType_GENERAL}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		st.Host = raw
		return st
	}
	st.Host = host
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	st.Port = uint32(port)

	if gameqos.IsGameTraffic(raw, port) {
		st.IsGame = true
		st.StreamType = protocol.StreamType_UDP
		return st
	}
	if isAITraffic(host) {
		st.StreamType = protocol.StreamType_AI
	}
	return st
}

// -----------------------------------------------------------------------------
// Source: tunnel_metrics.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

func runMetricsLoop(
	ctx context.Context,
	tunnel net.Conn,
	sessionID string,
	streamID uint32,
	streamType protocol.StreamType,
	bytesSent, bytesRecv *atomic.Uint64,
	rttMs *uint32,
	rttMu *sync.Mutex,
	bridgeClient *BridgeClient,
) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report := &protocol.MetricsReport{
				SessionId: sessionID,
				Timestamp: uint64(time.Now().UnixMilli()),
			}
			report.Streams = append(report.Streams, &protocol.MetricsReport_StreamMetrics{
				StreamId:   streamID,
				StreamType: streamType,
				BytesSent:  bytesSent.Load(),
				BytesRecv:  bytesRecv.Load(),
			})
			_ = protocol.TypedWriteMessage(tunnel, protocol.MsgTypeMetricsReport, report)
			if bridgeClient != nil {
				rttMu.Lock()
				r := *rttMs
				rttMu.Unlock()
				_ = bridgeClient.SendMetrics(sessionID, r, 0, 0, bytesSent.Load(), bytesRecv.Load())
			}
		}
	}
}
