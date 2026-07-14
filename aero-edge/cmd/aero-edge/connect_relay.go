// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	aeroproto "github.com/aero-protocol/proto"
	"github.com/aero-protocol/aero-edge/internal/contextstore"
	"github.com/aero-protocol/aero-edge/internal/protocol"
)

var frameBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// runConnectRelay：空闲/最大寿命/带宽；结束必 onDone 释槽
func (h *edgeHandler) runConnectRelay(p connectRelayParams) {
	if p.onDone != nil {
		defer p.onDone()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer p.Target.Close()

	started := time.Now()
	var lastHB, lastAct atomic.Int64
	ns := started.UnixNano()
	lastHB.Store(ns)
	lastAct.Store(ns)

	udpConns := make(map[string]*net.UDPConn)
	var udpMu sync.Mutex
	defer func() {
		udpMu.Lock()
		for a, c := range udpConns {
			c.Close()
			delete(udpConns, a)
		}
		udpMu.Unlock()
	}()

	var aiContextID string
	var bytesTo, bytesFrom atomic.Uint64
	var lastSeq atomic.Uint64

	hbInterval := time.Duration(p.Resp.HeartbeatInterval) * time.Second
	if hbInterval < 5*time.Second {
		hbInterval = 30 * time.Second
	}
	hbTimeout := 3 * hbInterval
	idleTO := h.idleTimeout
	if idleTO <= 0 {
		idleTO = 15 * time.Minute
	}
	maxLife := h.maxLife

	lowLatency := p.StreamType == aeroproto.StreamType_AI ||
		p.StreamType == aeroproto.StreamType_UDP ||
		p.StreamType == aeroproto.StreamType_CONTROL

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer cancel()
		bp := frameBufPool.Get().(*[]byte)
		buf := *bp
		defer frameBufPool.Put(bp)
		seq := uint64(1)
		var sinceFlush int
		defer p.SF.Flush()

		for {
			if ctx.Err() != nil {
				return
			}
			n, err := p.Target.Read(buf)
			if err != nil {
				return
			}
			if h.bwLimit != nil {
				h.bwLimit.Take(p.Token, n)
			}
			lastAct.Store(time.Now().UnixNano())
			payload := make([]byte, n)
			copy(payload, buf[:n])
			frame := &aeroproto.TcpFrame{StreamId: p.StreamID, Payload: payload, Sequence: seq}
			if err := protocol.TypedWriteMessage(p.SF, protocol.MsgTypeTcpFrame, frame); err != nil {
				return
			}
			sinceFlush += n
			if lowLatency || n < 24*1024 || sinceFlush >= 64*1024 {
				p.SF.Flush()
				sinceFlush = 0
			}
			bytesFrom.Add(uint64(n))
			if p.StreamType == aeroproto.StreamType_AI {
				lastSeq.Store(seq)
			}
			seq++
		}
	}()

	go func() {
		defer wg.Done()
		defer cancel()
		for {
			if ctx.Err() != nil {
				return
			}
			msgType, msg, err := protocol.TypedReadMessage(p.Body)
			if err != nil {
				return
			}
			switch msgType {
			case protocol.MsgTypeTcpFrame:
				frame := msg.(*aeroproto.TcpFrame)
				n := len(frame.Payload)
				if h.bwLimit != nil {
					h.bwLimit.Take(p.Token, n)
				}
				lastAct.Store(time.Now().UnixNano())
				if _, err := p.Target.Write(frame.Payload); err != nil {
					return
				}
				bytesTo.Add(uint64(n))
			case protocol.MsgTypeHeartbeat:
				hb := msg.(*aeroproto.Heartbeat)
				now := time.Now().UnixNano()
				lastHB.Store(now)
				lastAct.Store(now)
				ack := &aeroproto.HeartbeatAck{Timestamp: hb.Timestamp, Sequence: hb.Sequence}
				if err := protocol.TypedWriteMessage(p.SF, protocol.MsgTypeHeartbeatAck, ack); err != nil {
					return
				}
				p.SF.Flush()
			case protocol.MsgTypeUdpFrame:
				lastAct.Store(time.Now().UnixNano())
				handleUDPFrame(ctx, p, msg.(*aeroproto.UdpFrame), udpConns, &udpMu)
			case protocol.MsgTypeAiStreamHeader:
				header := msg.(*aeroproto.AiStreamHeader)
				aiContextID = header.ContextId
				lastAct.Store(time.Now().UnixNano())
				if header.Resume && header.ContextId != "" && h.contextStore != nil {
					if c, err := h.contextStore.Get(header.ContextId); err == nil && c != nil {
						log.Printf("[AI] resume %s seq=%d", header.ContextId, c.LastSequence)
					}
				}
			default:
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				if now.Sub(time.Unix(0, lastHB.Load())) > hbTimeout {
					if !h.quiet {
						log.Printf("[HEARTBEAT] timeout %s", p.Remote)
					}
					h.metrics.HeartbeatTimeout()
					cancel()
					return
				}
				if now.Sub(time.Unix(0, lastAct.Load())) > idleTO {
					if !h.quiet {
						log.Printf("[IDLE] timeout %s", p.Remote)
					}
					h.metrics.IdleTimeout()
					cancel()
					return
				}
				if maxLife > 0 && now.Sub(started) > maxLife {
					if !h.quiet {
						log.Printf("[LIFE] max life %s after %v", p.Remote, maxLife)
					}
					cancel()
					return
				}
			}
		}
	}()

	wg.Wait()

	if p.StreamType == aeroproto.StreamType_AI && aiContextID != "" && h.contextStore != nil {
		var sid uint32
		var host string
		var port uint32
		if len(p.Req.GetStreams()) > 0 {
			s := p.Req.GetStreams()[0]
			sid, host, port = s.GetStreamId(), s.GetTargetHost(), s.GetTargetPort()
		}
		_ = h.contextStore.Save(contextstore.StreamContext{
			ContextID: aiContextID, SessionID: p.Resp.SessionId,
			StreamID: sid, TargetHost: host, TargetPort: port,
			LastSequence: lastSeq.Load(), BytesTransferred: bytesTo.Load() + bytesFrom.Load(),
		})
	}
	h.metrics.AddBytesReceived(bytesTo.Load())
	h.metrics.AddBytesSent(bytesFrom.Load())
}
