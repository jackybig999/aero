// Copyright 2026 AERO Protocol Contributors
//go:build windows

package main

import (
	"debug/pe"
	"os"
	"testing"
)

func TestClientSubsystem(t *testing.T) {
	exePath := "../../../tmp/client.exe"
	if _, err := os.Stat(exePath); os.IsNotExist(err) {
		t.Skip("tmp/client.exe not present, skipping PE header test")
	}

	f, err := pe.Open(exePath)
	if err != nil {
		t.Fatalf("pe.Open failed: %v", err)
	}
	defer f.Close()

	opt, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("expected 64-bit optional header, got %T", f.OptionalHeader)
	}

	// 2 = IMAGE_SUBSYSTEM_WINDOWS_GUI
	// 3 = IMAGE_SUBSYSTEM_WINDOWS_CUI (Console)
	if opt.Subsystem != 2 {
		t.Fatalf("CRITICAL REGRESSION: client.exe PE Subsystem is %d (expected 2 for Windows GUI, 3 means console popup)", opt.Subsystem)
	}
}
