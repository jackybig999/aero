// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"os"
	"path/filepath"
	"testing"
)

// 客户端不得使用 edge 的数据目录；旧版写在那里的客户端配置在不属于 edge 时搬走。
func TestMigrateLinuxClientDir(t *testing.T) {
	root := t.TempDir()
	old, nw := filepath.Join(root, "aero"), filepath.Join(root, "aero-client")
	_ = os.MkdirAll(old, 0o755)
	_ = os.WriteFile(filepath.Join(old, "chain_proxy.json"), []byte("{}"), 0o600)
	_ = os.WriteFile(filepath.Join(old, "geodata_direct.txt"), []byte("x"), 0o600)
	migrateLinuxClientDir(old, nw)
	if _, err := os.Stat(filepath.Join(nw, "chain_proxy.json")); err != nil {
		t.Fatal("client config not migrated")
	}
	if _, err := os.Stat(filepath.Join(old, "geodata_direct.txt")); err != nil {
		t.Fatal("geodata must stay (it may belong to the edge)")
	}

	edgeDir, nw2 := filepath.Join(root, "edge"), filepath.Join(root, "client2")
	_ = os.MkdirAll(edgeDir, 0o755)
	_ = os.WriteFile(filepath.Join(edgeDir, "edge.lock"), []byte("1"), 0o600)
	_ = os.WriteFile(filepath.Join(edgeDir, "chain_proxy.json"), []byte("{}"), 0o600)
	migrateLinuxClientDir(edgeDir, nw2)
	if _, err := os.Stat(filepath.Join(edgeDir, "chain_proxy.json")); err != nil {
		t.Fatal("must not touch an edge data directory")
	}
}

func TestDataDirEnvOverride(t *testing.T) {
	d := filepath.Join(t.TempDir(), "x")
	t.Setenv("AERO_DATA_DIR", d)
	if got := GetDataDir(); got != d {
		t.Fatalf("GetDataDir = %q, want %q", got, d)
	}
}
