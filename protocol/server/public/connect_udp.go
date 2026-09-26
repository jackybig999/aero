// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aero-protocol/aero-edge/public/internal/traffic"
	protocol "github.com/aero-protocol/proto"
)

// runUDPRelay forwards only UdpFrame + heartbeat (no TCP dial).
func (h *edgeHandler) runUDPRelay(p connectRelayParams) {
	if p.onDone != nil {
		defer p.onDone()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	udpConns := make(map[string]*net.UDPConn)
	var udpMu sync.Mutex
	defer func() {
		udpMu.Lock()
		for _, c := range udpConns {
			_ = c.Close()
		}
		udpMu.Unlock()
	}()

	var lastHB atomic.Int64
	lastHB.Store(time.Now().UnixNano())
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, lastHB.Load())) > 90*time.Second {
					cancel()
					return
				}
			}
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}
		msgType, msg, err := protocol.TypedReadMessage(p.Body)
		if err != nil {
			return
		}
		switch msgType {
		case protocol.MsgTypeUdpFrame:
			handleUDPFrame(ctx, p, msg.(*protocol.UdpFrame), udpConns, &udpMu)
		case protocol.MsgTypeHeartbeat:
			hb := msg.(*protocol.Heartbeat)
			lastHB.Store(time.Now().UnixNano())
			ack := &protocol.HeartbeatAck{Timestamp: hb.Timestamp, Sequence: hb.Sequence}
			if err := protocol.TypedWriteMessage(p.SF, protocol.MsgTypeHeartbeatAck, ack); err != nil {
				return
			}
			p.SF.Flush()
		default:
		}
	}
}

func handleUDPFrame(
	ctx context.Context,
	p connectRelayParams,
	frame *protocol.UdpFrame,
	udpConns map[string]*net.UDPConn,
	udpMu *sync.Mutex,
) {
	dstAddr := frame.SrcAddr
	if dstAddr == "" {
		dstAddr = p.TargetAddr
	}
	if blocked, why := traffic.IsBlockedTarget(dstAddr); blocked {
		log.Printf("[UDP] blocked target %s (%s)", dstAddr, why)
		return
	}
	udpMu.Lock()
	uconn, ok := udpConns[dstAddr]
	if !ok {
		udpAddr, err := net.ResolveUDPAddr("udp", dstAddr)
		if err == nil {
			if blocked, why := traffic.IsBlockedIP(udpAddr.IP); blocked {
				udpMu.Unlock()
				log.Printf("[UDP] blocked resolved target %s -> %s (%s)", dstAddr, udpAddr.IP, why)
				return
			}
			uconn, _ = net.DialUDP("udp", nil, udpAddr)
		}
		if uconn != nil {
			udpConns[dstAddr] = uconn
			go udpReadLoop(ctx, p, dstAddr, uconn, frame.StreamId)
		}
	}
	udpMu.Unlock()
	if uconn != nil {
		if _, err := uconn.Write(frame.Payload); err != nil {
			log.Printf("[UDP] write %s: %v", dstAddr, err)
		}
	}
}

func udpReadLoop(ctx context.Context, p connectRelayParams, addr string, conn *net.UDPConn, sid uint32) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			conn.Close()
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		resp := &protocol.UdpFrame{
			StreamId: sid,
			Payload:  payload,
			SrcAddr:  addr,
		}
		if err := protocol.TypedWriteMessage(p.SF, protocol.MsgTypeUdpFrame, resp); err != nil {
			return
		}
		p.SF.Flush()
	}
}
