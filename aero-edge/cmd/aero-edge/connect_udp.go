// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	aeroproto "github.com/aero-protocol/proto"
	"github.com/aero-protocol/aero-edge/internal/protocol"
)

func handleUDPFrame(
	ctx context.Context,
	p connectRelayParams,
	frame *aeroproto.UdpFrame,
	udpConns map[string]*net.UDPConn,
	udpMu *sync.Mutex,
) {
	dstAddr := frame.SrcAddr
	if dstAddr == "" {
		dstAddr = p.TargetAddr
	}
	udpMu.Lock()
	uconn, ok := udpConns[dstAddr]
	if !ok {
		udpAddr, err := net.ResolveUDPAddr("udp", dstAddr)
		if err == nil {
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
		resp := &aeroproto.UdpFrame{
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
