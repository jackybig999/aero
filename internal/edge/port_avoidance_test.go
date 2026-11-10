// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"net"
	"testing"
)

func TestCheckPortAvailable_FreeAndBound(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on test port: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// While bound, checkPortAvailable must report false
	if checkPortAvailable(addr) {
		t.Fatalf("expected port %s to be reported occupied, got available", addr)
	}

	ln.Close()

	// Once closed, checkPortAvailable should report true
	if !checkPortAvailable(addr) {
		t.Fatalf("expected port %s to be reported available after close", addr)
	}
}

func TestGenerateSecureAdminKey(t *testing.T) {
	k1 := generateSecureAdminKey()
	k2 := generateSecureAdminKey()

	if len(k1) != 32 || len(k2) != 32 {
		t.Fatalf("expected 32-char hex admin key, got len(k1)=%d len(k2)=%d", len(k1), len(k2))
	}
	if k1 == k2 {
		t.Fatalf("expected randomly generated admin keys to be distinct")
	}
}

func TestNewServer_PortAutoAvoidanceAndAdminKey(t *testing.T) {
	// 1. Occupy a dummy port to simulate port conflict
	dummyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen dummy: %v", err)
	}
	defer dummyLn.Close()

	occupiedAddr := dummyLn.Addr().String()
	tmpDir := t.TempDir()

	cfg := ServerConfig{
		Listen:                     occupiedAddr,
		DataDir:                    tmpDir,
		AllowSelfSignedCertForTest: true,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	// Verify server avoided the occupied port
	if srv.cfg.Listen == occupiedAddr {
		t.Fatalf("expected srv.cfg.Listen to be avoided from %s, but remained identical", occupiedAddr)
	}

	// Verify AdminKey was either loaded from existing config or auto-generated
	if srv.cfg.AdminKey == "" {
		t.Fatalf("expected non-empty AdminKey, got empty")
	}
}
