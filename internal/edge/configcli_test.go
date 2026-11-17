package edge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigSetValidatesAndPreservesOtherKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "edge.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(path, []byte(`{"data_dir":"/var/lib/aero","metering_key":"mk"}`), 0o600)
	for _, kv := range [][2]string{{"domain", "Node1.Example.com"}, {"listen", "443"}, {"warp", "all"}, {"usage_api", "true"}} {
		if _, err := ConfigSet(path, kv[0], kv[1]); err != nil {
			t.Fatalf("%v: %v", kv, err)
		}
	}
	key, err := ConfigSet(path, "admin_key", "random")
	if err != nil || len(key) != 64 {
		t.Fatalf("random key: %q %v", key, err)
	}
	for _, bad := range [][2]string{{"domain", "1.2.3.4"}, {"domain", "a;rm -rf /"}, {"listen", "70000"}, {"admin_key", "short"}, {"warp", "on"}, {"cert_file", "/etc/passwd"}, {"usage_api", "yes"}} {
		if _, err := ConfigSet(path, bad[0], bad[1]); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	b, _ := os.ReadFile(path)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["domain"] != "node1.example.com" || m["listen"] != ":443" || m["warp_proxy"] != warpLocalProxy || m["warp_all"] != true ||
		m["usage_api"] != true || m["metering_key"] != "mk" || m["data_dir"] != "/var/lib/aero" || m["admin_key"] != key {
		t.Fatalf("config: %v", m)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if v, _ := ConfigGet(path, "warp"); v != "all" {
		t.Fatalf("warp get = %q", v)
	}
	_, _ = ConfigSet(path, "warp", "off")
	if v, _ := ConfigGet(path, "warp"); v != "off" {
		t.Fatalf("warp off get = %q", v)
	}
}

func TestCheckNodeReportsFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge.json")
	_ = os.WriteFile(path, []byte(`{"admin_key":"tooshort","data_dir":"`+dir+`","listen":"127.0.0.1:0"}`), 0o600)
	got := map[string]string{}
	for _, it := range CheckNode(path) {
		got[it.Name] = it.Level
	}
	if got["domain"] != "FAIL" || got["certificate"] != "FAIL" || got["admin_key"] != "FAIL" {
		t.Fatalf("expected failures: %v", got)
	}

	cf, kf := writeTestCert(t, filepath.Join(dir, "cert"), "fullchain.pem", "privkey.pem", time.Now().Add(48*time.Hour), "n.example.com")
	cfg := map[string]any{"domain": "n.example.com", "cert_file": cf, "key_file": kf, "admin_key": strings.Repeat("a", 32), "data_dir": dir, "listen": "127.0.0.1:0"}
	b, _ := json.Marshal(cfg)
	_ = os.WriteFile(path, b, 0o600)
	got = map[string]string{}
	for _, it := range CheckNode(path) {
		got[it.Name] = it.Level
	}
	if got["domain"] != "OK" || got["certificate"] != "OK" || got["admin_key"] != "OK" {
		t.Fatalf("expected OK: %v", got)
	}
	cfg["domain"] = "other.example.org"
	b, _ = json.Marshal(cfg)
	_ = os.WriteFile(path, b, 0o600)
	for _, it := range CheckNode(path) {
		if it.Name == "certificate" && it.Level != "FAIL" {
			t.Fatal("certificate for another domain accepted")
		}
	}
}
