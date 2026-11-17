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

// 自动发现的证书路径不写入配置（并清除旧版本写入的路径）；换域名时清除默认目录下的旧证书路径。
func TestDiscoveredCertPathIsNotPersisted(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LE_WORKING_DIR", "")
	t.Setenv("ACME_HOME", "")
	dir := filepath.Join(home, ".acme.sh", "n.example.com_ecc")
	writeTestCert(t, dir, "fullchain.cer", "n.example.com.key", time.Now().Add(48*time.Hour), "n.example.com")
	cfgPath := filepath.Join(t.TempDir(), "edge.json")
	stale := filepath.Join(home, ".acme.sh", "old.example.com_ecc", "fullchain.cer")
	_ = os.WriteFile(cfgPath, []byte(`{"cert_file":"`+stale+`","key_file":"x"}`), 0o600)
	listen, _ := findTestAddr()
	srv, err := NewServer(ServerConfig{Listen: listen, Domain: "n.example.com", DataDir: t.TempDir(), ConfigPath: cfgPath, AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatal(err)
	}
	if !srv.certDiscovered {
		srv.Close()
		t.Fatal("test setup: certificate was not discovered")
	}
	srv.Close()
	m, _ := readConfigMap(cfgPath)
	if _, ok := m["cert_file"]; ok {
		t.Fatalf("discovered/stale cert path persisted: %v", m["cert_file"])
	}
	if m["domain"] != "n.example.com" {
		t.Fatalf("domain not persisted: %v", m)
	}

	_ = os.WriteFile(cfgPath, []byte(`{"domain":"n.example.com","cert_file":"`+stale+`","key_file":"k"}`), 0o600)
	if _, err := ConfigSet(cfgPath, "domain", "m.example.com"); err != nil {
		t.Fatal(err)
	}
	if m, _ := readConfigMap(cfgPath); m["cert_file"] != nil || m["key_file"] != nil {
		t.Fatalf("default-dir cert path kept after domain change: %v", m)
	}
	_ = os.WriteFile(cfgPath, []byte(`{"cert_file":"/srv/certs/custom.pem","key_file":"/srv/certs/custom.key"}`), 0o600)
	_, _ = ConfigSet(cfgPath, "domain", "m.example.com")
	if m, _ := readConfigMap(cfgPath); m["cert_file"] != "/srv/certs/custom.pem" {
		t.Fatal("explicitly configured cert path removed")
	}
}

// 线上实测：1.4.2 写入的证书路径在升级后应被清除（启动时按自动发现处理）；默认目录里按域名找不到时沿用配置的路径。
func TestLegacyPersistedCertPathMigrates(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LE_WORKING_DIR", "")
	t.Setenv("ACME_HOME", "")
	dir := filepath.Join(home, ".acme.sh", "n.example.com_ecc")
	cf, kf := writeTestCert(t, dir, "fullchain.cer", "n.example.com.key", time.Now().Add(48*time.Hour), "n.example.com")
	cfgPath := filepath.Join(t.TempDir(), "edge.json")
	_ = os.WriteFile(cfgPath, []byte(`{"cert_file":"`+cf+`","key_file":"`+kf+`"}`), 0o600)
	listen, _ := findTestAddr()
	srv, err := NewServer(ServerConfig{Listen: listen, Domain: "n.example.com", CertFile: cf, KeyFile: kf, DataDir: t.TempDir(), ConfigPath: cfgPath, AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatal(err)
	}
	discovered := srv.certDiscovered
	srv.Close()
	if m, _ := readConfigMap(cfgPath); !discovered || m["cert_file"] != nil {
		t.Fatalf("legacy path not migrated: discovered=%v cert_file=%v", discovered, m["cert_file"])
	}

	// 配置的路径在默认目录里，但域名对不上：沿用配置的路径（不因迁移而无法启动）
	listen, _ = findTestAddr()
	srv, err = NewServer(ServerConfig{Listen: listen, Domain: "other.example.org", CertFile: cf, KeyFile: kf, DataDir: t.TempDir(), AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatalf("fallback to configured path failed: %v", err)
	}
	if srv.certDiscovered || srv.certLoader == nil {
		t.Fatal("fallback must load the configured file, not be treated as discovered")
	}
	if f, _ := srv.certLoader.Files(); f != cf {
		t.Fatalf("fallback loaded %s, want %s", f, cf)
	}
	srv.Close()
}
