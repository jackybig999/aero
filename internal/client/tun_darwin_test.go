//go:build darwin

// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"path/filepath"
	"testing"
)

func TestValidUtunName(t *testing.T) {
	valid := []string{"utun0", "utun1", "utun15", "utun31"}
	for _, name := range valid {
		if !validUtunName(name) {
			t.Errorf("expected valid for %s, got false", name)
		}
	}

	invalid := []string{
		"", "utun", "utun32", "utun100", "en0", "utun 1", "utun1/2", "utun1;rm", "utun-1", "utun01",
	}
	for _, name := range invalid {
		if validUtunName(name) {
			t.Errorf("expected invalid for %q, got true", name)
		}
	}
}

func TestShouldCleanUtun(t *testing.T) {
	// 结果 1：名字非法 -> false
	if shouldCleanUtun("en0", "inet 10.88.0.2", true) {
		t.Error("expected false for invalid name en0")
	}
	if shouldCleanUtun("utun32", "inet 10.88.0.2", true) {
		t.Error("expected false for invalid name utun32")
	}

	// 结果 2：接口还在，且 ifconfig 文本里有 inet 10.88.0.2 -> true
	ifTextMatch := "utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1224\n\tinet 10.88.0.2 --> 10.88.0.2 netmask 0xffffff00\n"
	if !shouldCleanUtun("utun3", ifTextMatch, true) {
		t.Error("expected true when iface exists and contains inet 10.88.0.2")
	}

	// 结果 3：接口还在，但没有这个地址 -> false
	ifTextMismatch := "utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420\n\tinet 192.168.1.50 --> 192.168.1.1 netmask 0xffffff00\n"
	if shouldCleanUtun("utun3", ifTextMismatch, true) {
		t.Error("expected false when iface exists but lacks inet 10.88.0.2")
	}

	// 结果 4：接口已经不在 -> true
	if !shouldCleanUtun("utun3", "", false) {
		t.Error("expected true when iface does not exist")
	}
}

func TestUtunRecordPathOverride(t *testing.T) {
	tmpDir := t.TempDir()
	origHook := utunRecordPath
	t.Cleanup(func() {
		utunRecordPath = origHook
	})
	utunRecordPath = func() string {
		return filepath.Join(tmpDir, "utun.name")
	}

	p := utunRecordPath()
	if filepath.Dir(p) != tmpDir {
		t.Fatalf("expected utunRecordPath in tmpDir %s, got %s", tmpDir, p)
	}
}
