// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"testing"
)

func TestProbeHostPublicIPv6(t *testing.T) {
	prefix, err := ProbeHostPublicIPv6()
	if err != nil {
		t.Logf("ProbeHostPublicIPv6 returned error as expected on non-IPv6 host/container: %v", err)
		return
	}
	t.Logf("ProbeHostPublicIPv6 detected: %s", prefix)
	addr := prefix.Addr()
	if !addr.Is6() {
		t.Fatalf("expected IPv6 address, got %s", addr)
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		t.Fatalf("probed address is not a public routed IPv6: %s", addr)
	}
	if prefix.Bits() < 48 || prefix.Bits() > 64 {
		t.Fatalf("expected prefix length between 48 and 64, got /%d", prefix.Bits())
	}
}
