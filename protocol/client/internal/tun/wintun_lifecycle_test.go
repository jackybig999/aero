//go:build windows

package tun

import (
	"os"
	"path/filepath"
	"testing"
)

func prepareWintunDLL(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dst := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if _, err := os.Stat(dst); err == nil {
		return
	}
	src := `D:\jacky\gemini\aisys\dist\win\wintun.dll`
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read wintun src: %v", err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("write wintun dst: %v", err)
	}
}

func TestPhysicalGateway(t *testing.T) {
	gw, ifIndex, err := PhysicalDefaultGateway()
	t.Logf("PhysicalDefaultGateway -> GW: %s, IfIndex: %s, Err: %v", gw, ifIndex, err)
}
