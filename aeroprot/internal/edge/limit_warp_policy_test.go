// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialGuard_WarpPolicyConfigurableFailOpen(t *testing.T) {
	dg := NewDialGuard(64)
	defer dg.Close()
	dg.AllowLocal = true

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// 1. By default with dead WARP proxy, AI domain must fail closed
	dg.SetWarpProxy("127.0.0.1:59997", false)
	_, err = dg.DialTimeout("tcp", "chatgpt.com:443", 200*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "AERO_WARP_FAIL_CLOSED") {
		t.Fatalf("expected AERO_WARP_FAIL_CLOSED default, got: %v", err)
	}

	// 2. With FailOpen=true via policy, non-AI target falls back to direct dial smoothly
	dg.SetWarpProxyWithPolicy("127.0.0.1:59997", false, true)
	c, err := dg.DialTimeout("tcp", targetLn.Addr().String(), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("expected direct dial fallback on fail-open, got error: %v", err)
	}
	_ = c.Close()

	// 3. With AERO_WARP_MODE=fail-open via environment, fallback is permitted
	t.Setenv("AERO_WARP_MODE", "fail-open")
	c2, err := dg.DialTimeout("tcp", targetLn.Addr().String(), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("expected direct dial fallback on env fail-open, got error: %v", err)
	}
	_ = c2.Close()
}
