package public

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/aero-protocol/aero-ech/internal/transport"
	"github.com/aero-protocol/aero-ech/internal/tun"
	aeroproto "github.com/aero-protocol/proto"
)

func TestAIStreamDetectionAndQoS(t *testing.T) {
	cases := []struct {
		target   string
		expected aeroproto.StreamType
		model    string
	}{
		{"api.openai.com:443", aeroproto.StreamType_AI, "openai-gpt"},
		{"chatgpt.com:443", aeroproto.StreamType_AI, "openai-gpt"},
		{"api.deepseek.com:443", aeroproto.StreamType_AI, "deepseek-chat"},
		{"api.anthropic.com:443", aeroproto.StreamType_AI, "anthropic-claude"},
		{"cursor.com:443", aeroproto.StreamType_AI, "cursor-ai"},
		{"api.perplexity.ai:443", aeroproto.StreamType_AI, "perplexity"},
		{"api.groq.com:443", aeroproto.StreamType_AI, "groq-llama"},
		{"github.com:443", aeroproto.StreamType_GENERAL, "ai-service"},
	}

	for _, tc := range cases {
		st := classifyTarget(tc.target)
		if st.StreamType != tc.expected {
			t.Errorf("classifyTarget(%s) = %v, expected %v", tc.target, st.StreamType, tc.expected)
		}
		if tc.expected == aeroproto.StreamType_AI {
			m := inferModelName(st.Host)
			if m != tc.model {
				t.Errorf("inferModelName(%s) = %s, expected %s", st.Host, m, tc.model)
			}
		}
	}
}

func TestFakeIPTableResolution(t *testing.T) {
	domains := []string{
		"openai.com",
		"deepseek.com",
		"claude.ai",
		"cursor.com",
	}

	for _, domain := range domains {
		fakeIP := tun.DefaultFakeIPTable.Allocate(domain)
		if fakeIP == nil {
			t.Fatalf("Allocate(%s) returned nil", domain)
		}
		if !tun.DefaultFakeIPTable.IsFakeIP(fakeIP) {
			t.Errorf("IsFakeIP(%s) should be true for allocated fake-ip", fakeIP.String())
		}
		v4 := fakeIP.To4()
		if v4 == nil || v4[0] != 198 || (v4[1] != 18 && v4[1] != 19) {
			t.Errorf("allocated IP %s is not in 198.18.0.0/15", fakeIP.String())
		}

		// Reverse lookup in memory (0ms)
		resolved, ok := tun.DefaultFakeIPTable.Lookup(fakeIP)
		if !ok || resolved != domain {
			t.Errorf("Lookup(%s) = %s, %v; expected %s, true", fakeIP.String(), resolved, ok, domain)
		}
	}
}

func TestWebRTCSTUNArmorDetection(t *testing.T) {
	// Valid STUN Binding Request (RFC 5389):
	// Byte 0-1: 0x0001 (Binding Request)
	// Byte 2-3: 0x0000 (Message Length)
	// Byte 4-7: 0x2112A442 (Magic Cookie)
	// Byte 8-19: 12-byte Transaction ID
	stunPkt := make([]byte, 20)
	binary.BigEndian.PutUint16(stunPkt[0:2], 0x0001)
	binary.BigEndian.PutUint16(stunPkt[2:4], 0x0000)
	binary.BigEndian.PutUint32(stunPkt[4:8], 0x2112A442)
	for i := 8; i < 20; i++ {
		stunPkt[i] = byte(i)
	}

	if !isSTUNPacket(stunPkt) {
		t.Errorf("isSTUNPacket failed to recognize valid STUN Binding Request")
	}

	// Non-STUN packet
	nonStunPkt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10}
	if isSTUNPacket(nonStunPkt) {
		t.Errorf("isSTUNPacket false positive on arbitrary UDP packet")
	}

	// Corrupted magic cookie
	badCookiePkt := append([]byte(nil), stunPkt...)
	badCookiePkt[4] = 0x00
	if isSTUNPacket(badCookiePkt) {
		t.Errorf("isSTUNPacket false positive on corrupted magic cookie")
	}
}

func TestWhiteSNIPoolAndSelection(t *testing.T) {
	if len(WhiteSNIPool) == 0 {
		t.Fatalf("WhiteSNIPool must not be empty")
	}

	// 1. Without pins: currentEdgeSNI falls back to edge host or default
	transport.ClearPins()
	autoSNI := "auto"
	publicName = &autoSNI
	edgeHost := "edge.example.com:443"
	edgeAddr = &edgeHost

	sniWithoutPins := currentEdgeSNI()
	if sniWithoutPins != "edge.example.com" {
		t.Errorf("without pins, expected edge host fallback, got %s", sniWithoutPins)
	}

	// 2. With SPKI pins: currentEdgeSNI selects top-tier white SNI
	transport.AddPins("test-spki-pin-hash")
	defer transport.ClearPins()

	sniWithPins := currentEdgeSNI()
	if sniWithPins != WhiteSNIPool[0] {
		t.Errorf("with pins, expected WhiteSNIPool[0] (%s), got %s", WhiteSNIPool[0], sniWithPins)
	}
}

func TestOptimizeTCPLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		optimizeTCP(conn, true)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()
	optimizeTCP(client, true)
	<-done
}
