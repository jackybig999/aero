// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package aero

import (
	"bytes"
	"io"
	"testing"
)

func TestTypedMessageRoundTrip(t *testing.T) {
	orig := &TcpFrame{
		StreamId: 1001,
		Payload:  []byte("hello aero 0-alloc protocol"),
		Sequence: 1,
	}

	var buf bytes.Buffer
	if err := TypedWriteMessage(&buf, MsgTypeTcpFrame, orig); err != nil {
		t.Fatalf("TypedWriteMessage failed: %v", err)
	}

	msgType, decoded, err := TypedReadMessage(&buf)
	if err != nil {
		t.Fatalf("TypedReadMessage failed: %v", err)
	}

	if msgType != MsgTypeTcpFrame {
		t.Fatalf("expected msgType %d, got %d", MsgTypeTcpFrame, msgType)
	}

	frame, ok := decoded.(*TcpFrame)
	if !ok {
		t.Fatalf("expected *TcpFrame, got %T", decoded)
	}

	if frame.StreamId != orig.StreamId || !bytes.Equal(frame.Payload, orig.Payload) || frame.Sequence != orig.Sequence {
		t.Fatalf("frame mismatch: got %+v, want %+v", frame, orig)
	}
}

func TestPaddingCutoffAfter4Packets(t *testing.T) {
	var padCount uint8
	msg := &Heartbeat{Timestamp: 123456789}

	var lengths []int
	for i := 0; i < 6; i++ {
		var buf bytes.Buffer
		if err := WriteMessageWithPadding(&buf, msg, &padCount); err != nil {
			t.Fatalf("write failed on step %d: %v", i, err)
		}
		lengths = append(lengths, buf.Len())
	}

	if padCount != 4 {
		t.Fatalf("expected padCount to stop at 4, got %d", padCount)
	}

	// 包 4 和 包 5 应该完全一致且没有高熵 padding（长度固定较短）
	if lengths[4] != lengths[5] {
		t.Fatalf("expected identical non-padded lengths for packets >= 4, got %d vs %d", lengths[4], lengths[5])
	}

	// 且未填充长度应明显小于前4包的最小填充长度 (基准消息很小，填充至少加 64 字节)
	for i := 0; i < 4; i++ {
		if lengths[i] <= lengths[4] {
			t.Fatalf("packet %d should be padded (len=%d) larger than unpadded (len=%d)", i, lengths[i], lengths[4])
		}
	}
}

func BenchmarkMarshalAppend(b *testing.B) {
	frame := &TcpFrame{
		StreamId: 42,
		Payload:  make([]byte, 1024),
		Sequence: 999,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := TypedWriteMessage(io.Discard, MsgTypeTcpFrame, frame); err != nil {
			b.Fatal(err)
		}
	}
}
