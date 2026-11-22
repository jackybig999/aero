// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// persistServerConfig 只写显式给定的路径，键名与 ServerConfig 的 json tag 一致。
func TestConfigPersistWritesOnlyExplicitPathWithReadableKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge.json")
	if err := os.WriteFile(path, []byte(`{"cert":"/old/c.pem","key":"/old/k.pem","custom":"keep"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ServerConfig{ConfigPath: path, Listen: ":8443", Domain: "edge.example.com", CertFile: "/c.pem", KeyFile: "/k.pem", AdminKey: "ak", DataDir: "/var/lib/aero"}
	if err := persistServerConfig(cfg.ConfigPath, fullConfigUpdates(cfg)); err != nil {
		t.Fatalf("persistServerConfig: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["cert_file"] != "/c.pem" || got["key_file"] != "/k.pem" {
		t.Fatalf("cert_file/key_file = %v/%v, want /c.pem//k.pem", got["cert_file"], got["key_file"])
	}
	if _, ok := got["cert"]; ok {
		t.Fatal("legacy key \"cert\" must be removed")
	}
	if got["custom"] != "keep" {
		t.Fatal("unrelated keys must be preserved")
	}
	// 写回的文件必须能被 cmd/edge 的方式（json.Unmarshal 到 ServerConfig）读回证书路径。
	var back ServerConfig
	if err := json.Unmarshal(raw, &back); err != nil || back.CertFile != "/c.pem" || back.KeyFile != "/k.pem" {
		t.Fatalf("round trip CertFile/KeyFile = %q/%q (err %v)", back.CertFile, back.KeyFile, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %v (err %v), want 0600", info.Mode().Perm(), err)
	}
}

func TestConfigPersistWithoutPathWritesNothing(t *testing.T) {
	cfg := ServerConfig{Listen: ":443", AdminKey: "ak"}
	if err := persistServerConfig(cfg.ConfigPath, fullConfigUpdates(cfg)); err != nil {
		t.Fatalf("persistServerConfig without path returned error: %v", err)
	}
}

// 回归：测试中的 NewServer 曾以 root 身份写入宿主 /etc/aero/edge.json。
func TestConfigPersistNewServerDoesNotTouchHostConfig(t *testing.T) {
	const hostPath = "/etc/aero/edge.json"
	before, beforeErr := os.ReadFile(hostPath)

	srv, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", DataDir: t.TempDir(), Domain: "example.test", AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.Close()

	after, afterErr := os.ReadFile(hostPath)
	if os.IsNotExist(beforeErr) != os.IsNotExist(afterErr) || !bytes.Equal(before, after) {
		t.Fatalf("NewServer modified %s on the host", hostPath)
	}
}

// 运行中修改 warp 时，运维此前用 ConfigSet 写入的 admin_key/domain/listen 不得被进程内存里的旧值覆盖；
// 旧文件权限为 0644 时写回后收紧为 0600。
func TestConfigPersistKeepsConfigSetValuesAndTightensMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge.json")
	if err := os.WriteFile(path, []byte(`{"domain":"old.example.com","listen":":2083","admin_key":"`+strings.Repeat("o", 32)+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// 进程内存里仍是启动时的旧值
	s := &Server{cfg: ServerConfig{ConfigPath: path, Domain: "old.example.com", Listen: ":2083", AdminKey: strings.Repeat("o", 32)}, dialGuard: NewDialGuard(4)}
	defer s.dialGuard.Close()

	newKey := strings.Repeat("n", 40)
	if _, err := ConfigSet(path, "admin_key", newKey); err != nil {
		t.Fatal(err)
	}
	if _, err := ConfigSet(path, "domain", "new.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := ConfigSet(path, "listen", "8443"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // 模拟旧版本留下的宽权限
		t.Fatal(err)
	}
	if err := s.SetWarpEgress(true, true); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["admin_key"] != newKey || m["domain"] != "new.example.com" || m["listen"] != ":8443" {
		t.Fatalf("ConfigSet values overwritten by stale memory: %v", m)
	}
	if m["warp_proxy"] != warpLocalProxy || m["warp_all"] != true {
		t.Fatalf("warp not persisted: %v", m)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v (err %v), want 0600", info.Mode().Perm(), err)
	}
}

// updates 中值为 nil 的键被删除；未列出的键保持不变；文件不存在时创建（0600）。
func TestConfigPersistNilDeletesAndCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "edge.json")
	if err := persistServerConfig(path, map[string]any{"a": "1", "b": true}); err != nil {
		t.Fatal(err)
	}
	if err := persistServerConfig(path, map[string]any{"a": nil}); err != nil {
		t.Fatal(err)
	}
	m, err := readConfigMap(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["a"]; ok || m["b"] != true {
		t.Fatalf("after nil update: %v", m)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v err=%v", info.Mode().Perm(), err)
	}
	// 文件损坏时不覆盖
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistServerConfig(path, map[string]any{"a": "1"}); err == nil {
		t.Fatal("corrupt config silently overwritten")
	}
	if b, _ := os.ReadFile(path); string(b) != "{broken" {
		t.Fatalf("corrupt config modified: %q", b)
	}
}
