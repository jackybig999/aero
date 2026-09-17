// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"fmt"
	"net"
	"testing"
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
