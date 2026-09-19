package protocol

import (
	"crypto/rand"
	"testing"

	aeroproto "github.com/aero-protocol/proto"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestDynamicPaddingUnmarshal(t *testing.T) {
	req := &aeroproto.ConnectRequest{
		Version:   "aero/2.0",
		Token:     "test-token",
		Timestamp: 1700000000,
		Nonce:     []byte("1234567890abcdef"),
	}

	baseData, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// 注入 Protobuf 规范的 Tag 15 (WireType 2) 随机 Padding (64~256 字节)
	padLen := 128
	padBytes := make([]byte, padLen)
	_, _ = rand.Read(padBytes)

	// 使用标准 protowire 追加 Tag 15 字段
	padded := protowire.AppendTag(baseData, 15, protowire.BytesType)
	padded = protowire.AppendBytes(padded, padBytes)

	// 服务端解包
	var decoded aeroproto.ConnectRequest
	if err := proto.Unmarshal(padded, &decoded); err != nil {
		t.Fatalf("unmarshal padded data failed: %v", err)
	}

	if decoded.Version != req.Version || decoded.Token != req.Token {
		t.Errorf("decoded content mismatch: got %v, want %v", decoded, req)
	}

	t.Logf("[SUCCESS] Base payload=%d bytes, Padded payload=%d bytes. Unmarshal successful without error!",
		len(baseData), len(padded))
}
