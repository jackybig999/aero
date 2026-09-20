// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package clienttunnel

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	protocol "github.com/aero-protocol/proto"
)

// StreamConn 包装底层网络连接为 AERO 流连接（TCP 或 UDP 帧通信）
type StreamConn struct {
	raw       net.Conn
	streamID  uint32
	target    string
	udp       bool
	readBuf   []byte
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closed    atomic.Bool
	seq       uint64
	stopHB    chan struct{}
	bytesSent *atomic.Uint64
	bytesRecv *atomic.Uint64
}

// NewStreamConn 创建 AERO 数据流
func NewStreamConn(raw net.Conn, streamID uint32, target string, udp bool, bytesSent, bytesRecv *atomic.Uint64) *StreamConn {
	if bytesSent == nil {
		bytesSent = &atomic.Uint64{}
	}
	if bytesRecv == nil {
		bytesRecv = &atomic.Uint64{}
	}
	c := &StreamConn{
		raw:       raw,
		streamID:  streamID,
		target:    target,
		udp:       udp,
		seq:       1,
		stopHB:    make(chan struct{}),
		bytesSent: bytesSent,
		bytesRecv: bytesRecv,
	}
	go c.heartbeatLoop()
	return c
}

func (c *StreamConn) heartbeatLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	var seq uint32
	for {
		select {
		case <-c.stopHB:
			return
		case <-ticker.C:
			if c.closed.Load() {
				return
			}
			seq++
			c.writeMu.Lock()
			_ = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeHeartbeat, &protocol.Heartbeat{
				Timestamp: uint64(time.Now().UnixMilli()),
				Sequence:  seq,
			})
			c.writeMu.Unlock()
		}
	}
}

func (c *StreamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.closed.Load() {
		return 0, io.EOF
	}

	for len(c.readBuf) == 0 {
		msgType, msg, err := protocol.TypedReadMessage(c.raw)
		if err != nil {
			return 0, err
		}

		switch msgType {
		case protocol.MsgTypeTcpFrame:
			f := msg.(*protocol.TcpFrame)
			c.readBuf = append(c.readBuf, f.Payload...)
		case protocol.MsgTypeUdpFrame:
			f := msg.(*protocol.UdpFrame)
			c.readBuf = append(c.readBuf, f.Payload...)
		case protocol.MsgTypeAiStreamFrame:
			f := msg.(*protocol.AiStreamFrame)
			c.readBuf = append(c.readBuf, f.Payload...)
		case protocol.MsgTypeHeartbeat:
			hb := msg.(*protocol.Heartbeat)
			c.writeMu.Lock()
			_ = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeHeartbeatAck, &protocol.HeartbeatAck{
				Timestamp: hb.Timestamp,
				Sequence:  hb.Sequence,
			})
			c.writeMu.Unlock()
		case protocol.MsgTypeHeartbeatAck:
			// 保活 ACK，无需向下游写入数据
		default:
		}
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	c.bytesRecv.Add(uint64(n))
	return n, nil
}

func (c *StreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}

	const maxChunk = 24 * 1024
	sent := 0
	for sent < len(p) {
		end := sent + maxChunk
		if end > len(p) {
			end = len(p)
		}
		var err error
		if c.udp {
			err = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeUdpFrame, &protocol.UdpFrame{
				StreamId: c.streamID,
				Payload:  p[sent:end],
				SrcAddr:  c.target,
			})
		} else {
			c.seq++
			err = protocol.TypedWriteMessage(c.raw, protocol.MsgTypeTcpFrame, &protocol.TcpFrame{
				StreamId: c.streamID,
				Payload:  p[sent:end],
				Sequence: c.seq,
			})
		}
		if err != nil {
			return sent, err
		}
		sent = end
	}

	c.bytesSent.Add(uint64(len(p)))
	return len(p), nil
}

func (c *StreamConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	select {
	case <-c.stopHB:
	default:
		close(c.stopHB)
	}
	return c.raw.Close()
}

func (c *StreamConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *StreamConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *StreamConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *StreamConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *StreamConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
