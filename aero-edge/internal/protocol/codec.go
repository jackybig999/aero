// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package protocol

import (
	"encoding/binary"
	"fmt"
	"io"

	aeroproto "github.com/aero-protocol/proto"
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

// ReadMessage 从 reader 读取 4 字节大端长度 + Protobuf 消息
func ReadMessage(r io.Reader, msg proto.Message) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return fmt.Errorf("read length: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > 16*1024*1024 { // 16MB max
		return fmt.Errorf("message too large: %d", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	if err := proto.Unmarshal(data, msg); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}

// WriteMessage 写入 4 字节大端长度 + Protobuf 消息
func WriteMessage(w io.Writer, msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))

	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// TypedWriteMessage 写入 1 字节类型 + 4 字节长度 + Protobuf 消息
func TypedWriteMessage(w io.Writer, msgType byte, msg proto.Message) error {
	if _, err := w.Write([]byte{msgType}); err != nil {
		return fmt.Errorf("write type: %w", err)
	}
	return WriteMessage(w, msg)
}

// TypedReadMessage 读取 1 字节类型 + 4 字节长度 + Protobuf 消息
// 返回消息类型和解析后的 proto.Message
func TypedReadMessage(r io.Reader) (byte, proto.Message, error) {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return 0, nil, fmt.Errorf("read type: %w", err)
	}
	msgType := typeBuf[0]

	msg, err := NewMessageByType(msgType)
	if err != nil {
		// 未知类型：跳过 payload
		var lenBuf [4]byte
		if _, readErr := io.ReadFull(r, lenBuf[:]); readErr != nil {
			return msgType, nil, fmt.Errorf("unknown type 0x%02x, skip len failed: %w", msgType, readErr)
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		if length > 0 && length <= 16*1024*1024 {
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

// NewMessageByType 根据类型创建对应的 proto.Message
func NewMessageByType(msgType byte) (proto.Message, error) {
	switch msgType {
	case MsgTypeTcpFrame:
		return &aeroproto.TcpFrame{}, nil
	case MsgTypeUdpFrame:
		return &aeroproto.UdpFrame{}, nil
	case MsgTypeHeartbeat:
		return &aeroproto.Heartbeat{}, nil
	case MsgTypeHeartbeatAck:
		return &aeroproto.HeartbeatAck{}, nil
	case MsgTypeAiStreamHeader:
		return &aeroproto.AiStreamHeader{}, nil
	case MsgTypeAiStreamFrame:
		return &aeroproto.AiStreamFrame{}, nil
	case MsgTypeMetricsReport:
		return &aeroproto.MetricsReport{}, nil
	default:
		return nil, fmt.Errorf("unknown message type: 0x%02x", msgType)
	}
}
