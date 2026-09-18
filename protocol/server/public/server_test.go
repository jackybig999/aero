// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"

	"github.com/aero-protocol/aero-edge/public/internal/transport"
	aeroproto "github.com/aero-protocol/proto"
)

func TestAutoProbeHTTPSPort_Free(t *testing.T) {
	// Find a free port by listening on port 0
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	chosen := AutoProbeHTTPSPort(port)
	if chosen != port {
		t.Fatalf("expected preferred port %d, got %d", port, chosen)
	}
}

func TestAutoProbeHTTPSPort_FallbackWhenBusy(t *testing.T) {
	// Temporarily occupy the first candidate from StandardHTTPSPorts if possible,
	// or occupy a custom preferred port
	dummyPreferred := 19999 // port not in StandardHTTPSPorts
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", dummyPreferred))
	if err != nil {
		t.Skipf("cannot listen on :%d: %v", dummyPreferred, err)
	}
	defer l.Close()

	// Since dummyPreferred is occupied, AutoProbeHTTPSPort should return one of StandardHTTPSPorts
	chosen := AutoProbeHTTPSPort(dummyPreferred)
	if chosen == dummyPreferred {
		t.Fatalf("expected fallback port, but got occupied port %d", dummyPreferred)
	}

	foundInStandard := false
	for _, p := range StandardHTTPSPorts {
		if chosen == p {
			foundInStandard = true
			break
		}
	}
	if !foundInStandard {
		t.Fatalf("chosen port %d is not in StandardHTTPSPorts %v", chosen, StandardHTTPSPorts)
	}
}

func TestServerStreamQoSAIDetection(t *testing.T) {
	cases := []struct {
		target   string
		expected aeroproto.StreamType
	}{
		{"api.deepseek.com:443", aeroproto.StreamType_AI},
		{"api.openai.com:443", aeroproto.StreamType_AI},
		{"cursor.com:443", aeroproto.StreamType_AI},
		{"api.groq.com:443", aeroproto.StreamType_AI},
		{"example.com:443", aeroproto.StreamType_BROWSER},
		{"example.com:8080", aeroproto.StreamType_GENERAL},
	}

	for _, tc := range cases {
		st := detectStreamType(tc.target)
		if st != tc.expected {
			t.Errorf("detectStreamType(%s) = %v, expected %v", tc.target, st, tc.expected)
		}
	}
}

func TestServerDisguisedSNICertMapping(t *testing.T) {
	mgr, err := transport.NewCertManager(transport.CertConfig{
		Source:  transport.SelfSigned,
		Domains: []string{"edge.example.com"},
	})
	if err != nil {
		t.Fatalf("failed to create cert manager: %v", err)
	}

	// 1. Direct match with primary domain
	cert1, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "edge.example.com"})
	if err != nil || cert1 == nil {
		t.Fatalf("GetCertificate for primary domain failed: %v", err)
	}

	// 2. Disguised white SNI (e.g. gateway.icloud.com)
	cert2, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "gateway.icloud.com"})
	if err != nil || cert2 == nil {
		t.Fatalf("GetCertificate for disguised white SNI failed: %v", err)
	}

	// 3. Empty SNI
	cert3, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: ""})
	if err != nil || cert3 == nil {
		t.Fatalf("GetCertificate for empty SNI failed: %v", err)
	}
}
