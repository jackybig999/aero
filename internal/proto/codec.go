// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package proto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Message type identifiers (1 byte prefix)
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
		return
	}
	bufPool.Put(bp)
}

// ReadMessage reads 4-byte big-endian length + Protobuf message
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

// WriteMessage writes 4-byte big-endian length + Protobuf message with optional padding
func WriteMessage(w io.Writer, msg proto.Message) error {
	return WriteMessageWithPadding(w, msg, nil)
}

// WriteMessageWithPadding writes message with padding
func WriteMessageWithPadding(w io.Writer, msg proto.Message, padCount *uint8) error {
	bp := getBuffer()
	defer putBuffer(bp)

	*bp = append(*bp, 0, 0, 0, 0)

	var err error
	*bp, err = proto.MarshalOptions{}.MarshalAppend(*bp, msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	shouldPad := (padCount == nil) || (*padCount < 4)
	if shouldPad {
		var entropyBuf [257]byte
		_, _ = rand.Read(entropyBuf[:])
		padLen := 64 + int(entropyBuf[0])%193
		padBytes := entropyBuf[1 : 1+padLen]

		*bp = protowire.AppendTag(*bp, 15, protowire.BytesType)
		*bp = protowire.AppendBytes(*bp, padBytes)

		if padCount != nil {
			*padCount++
		}
	}

	payloadLen := len(*bp) - 4
	binary.BigEndian.PutUint32((*bp)[:4], uint32(payloadLen))

	if _, err := w.Write(*bp); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	return nil
}

// TypedWriteMessage writes 1 byte type + 4 byte length + Protobuf message
func TypedWriteMessage(w io.Writer, msgType byte, msg proto.Message) error {
	bp := getBuffer()
	defer putBuffer(bp)

	*bp = append(*bp, msgType, 0, 0, 0, 0)

	var err error
	*bp, err = proto.MarshalOptions{}.MarshalAppend(*bp, msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	payloadLen := len(*bp) - 5
	binary.BigEndian.PutUint32((*bp)[1:5], uint32(payloadLen))

	if _, err := w.Write(*bp); err != nil {
		return fmt.Errorf("write typed message: %w", err)
	}
	return nil
}

// TypedReadMessage reads 1 byte type + 4 byte length + Protobuf message
func TypedReadMessage(r io.Reader) (byte, proto.Message, error) {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return 0, nil, fmt.Errorf("read type: %w", err)
	}
	msgType := typeBuf[0]

	msg, err := NewMessageByType(msgType)
	if err != nil {
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

// NewMessageByType creates a proto.Message instance according to msgType
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
