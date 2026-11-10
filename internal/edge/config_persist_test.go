package edge

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// persistServerConfig 只写显式给定的路径，键名与 ServerConfig 的 json tag 一致。
func TestConfigPersistWritesOnlyExplicitPathWithReadableKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge.json")
	if err := os.WriteFile(path, []byte(`{"cert":"/old/c.pem","key":"/old/k.pem","custom":"keep"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ServerConfig{ConfigPath: path, Listen: ":8443", Domain: "edge.example.com", CertFile: "/c.pem", KeyFile: "/k.pem", AdminKey: "ak", DataDir: "/var/lib/aero"}
	if err := persistServerConfig(cfg); err != nil {
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
	if err := persistServerConfig(ServerConfig{Listen: ":443", AdminKey: "ak"}); err != nil {
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
