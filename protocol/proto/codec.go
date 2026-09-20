// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package aero

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"google.golang.org/protobuf/proto"
)

// 消息类型标识符（1 字节前缀）
const (
	MsgTypeTcpFrame       = 0x01
	MsgTypeUdpFrame       = 0x02
	MsgTypeHeartbeat      = 0x03
	MsgTypeHeartbeatAck   = 0x04
	MsgTypeAiStreamHeader = 0x05
	MsgTypeAiStreamFrame  = 0x06
	MsgTypeMetricsReport  = 0x07
)

const maxMessageSize = 16 * 1024 * 1024 // 16MB max message safety bound

// bufPool 提供可复用的字节切片缓冲区，实现 0-Alloc 封包
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

func getBuffer() *[]byte {
	bp := bufPool.Get().(*[]byte)
	*bp = (*bp)[:0]
	return bp
}

func putBuffer(bp *[]byte) {
	if cap(*bp) > 65536 {
		return // 防止大缓冲区长久驻留造成内存慢性膨胀
	}
	bufPool.Put(bp)
}

// ReadMessage 从 reader 读取 4 字节大端长度 + Protobuf 消息
func ReadMessage(r io.Reader, msg proto.Message) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return fmt.Errorf("read length: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > maxMessageSize {
		return fmt.Errorf("message too large: %d", length)
	}

	bp := getBuffer()
	defer putBuffer(bp)

	if cap(*bp) < int(length) {
		*bp = make([]byte, length)
	} else {
		*bp = (*bp)[:length]
	}

	if _, err := io.ReadFull(r, *bp); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	if err := proto.Unmarshal(*bp, msg); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}

// TypedWriteMessage 整帧一次性 Write，避免多路复用时交错破坏帧结构。
// 严格按照 0-Alloc 规范：利用 sync.Pool 与 proto.MarshalOptions{}.MarshalAppend，
// 借出的缓冲切片在同步栈帧内归还（L3 / R4）。
func TypedWriteMessage(w io.Writer, msgType byte, msg proto.Message) error {
	bp := getBuffer()
	defer putBuffer(bp)

	// 预置 5 字节帧头：[1 字节 msgType] + [4 字节大端长度占位符]
	*bp = append(*bp, msgType, 0, 0, 0, 0)

	var err error
	*bp, err = proto.MarshalOptions{}.MarshalAppend(*bp, msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// 填充实际 Protobuf payload 长度
	payloadLen := len(*bp) - 5
	binary.BigEndian.PutUint32((*bp)[1:5], uint32(payloadLen))

	if _, err := w.Write(*bp); err != nil {
		return fmt.Errorf("write typed message: %w", err)
	}
	return nil
}

// TypedReadMessage 读取 1 字节类型 + 4 字节长度 + Protobuf 消息
func TypedReadMessage(r io.Reader) (byte, proto.Message, error) {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return 0, nil, fmt.Errorf("read type: %w", err)
	}
	msgType := typeBuf[0]

	msg, err := NewMessageByType(msgType)
	if err != nil {
		// 未知类型：跳过未知 payload，保障协议向前兼容
		var lenBuf [4]byte
		if _, readErr := io.ReadFull(r, lenBuf[:]); readErr != nil {
			return msgType, nil, fmt.Errorf("unknown type 0x%02x, skip len failed: %w", msgType, readErr)
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		if length > 0 && length <= maxMessageSize {
			if _, copyErr := io.CopyN(io.Discard, r, int64(length)); copyErr != nil {
				return msgType, nil, fmt.Errorf("unknown type 0x%02x, skip payload failed: %w", msgType, copyErr)
			}
		}
		return msgType, nil, err
	}

	if err := ReadMessage(r, msg); err != nil {
		return msgType, nil, err
	}
	return msgType, msg, nil
}

// NewMessageByType 根据 1 字节类型标识创建对应的具体 proto.Message 结构体实例
func NewMessageByType(msgType byte) (proto.Message, error) {
	switch msgType {
	case MsgTypeTcpFrame:
		return &TcpFrame{}, nil
	case MsgTypeUdpFrame:
		return &UdpFrame{}, nil
	case MsgTypeHeartbeat:
		return &Heartbeat{}, nil
	case MsgTypeHeartbeatAck:
		return &HeartbeatAck{}, nil
	case MsgTypeAiStreamHeader:
		return &AiStreamHeader{}, nil
	case MsgTypeAiStreamFrame:
		return &AiStreamFrame{}, nil
	case MsgTypeMetricsReport:
		return &MetricsReport{}, nil
	default:
		return nil, fmt.Errorf("unknown message type: 0x%02x", msgType)
	}
}
