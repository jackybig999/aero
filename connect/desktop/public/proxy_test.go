// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package public

import (
	"net"
	"testing"
)

func TestDetectProxies(t *testing.T) {
	// 启动一个监听在 127.0.0.1:55555（AERO 混合代理默认端口）的 mock listener
	ln, err := net.Listen("tcp", "127.0.0.1:55555")
	if err != nil {
		t.Skipf("Port 55555 may already be occupied or restricted: %v", err)
		return
	}
	defer ln.Close()

	proxies, _ := DetectProxies(nil)
	var foundAero bool
	for _, p := range proxies {
		if p.Port == 55555 {
			foundAero = true
			if !p.Verified {
				t.Errorf("expected port 55555 to be verified")
			}
			t.Logf("[FOUND] Detected AERO proxy target: %+v", p)
			break
		}
	}

	if !foundAero {
		t.Fatalf("expected to detect AERO proxy on port 55555")
	}
}
