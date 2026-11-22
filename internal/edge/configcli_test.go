// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"encoding/json"
	"errors"
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

// connect_ip=false：服务端不建 TUN、不改宿主；check 不再要求防火墙工具与 TUN。
func TestConnectIPDisabledServerAndCheck(t *testing.T) {
	off := false
	dir := t.TempDir()
	cf, kf := writeTestCert(t, filepath.Join(dir, "c"), "fullchain.pem", "privkey.pem", time.Now().Add(48*time.Hour), "n.example.com")
	listen, _ := findTestAddr()
	srv, err := NewServer(ServerConfig{Listen: listen, Domain: "n.example.com", CertFile: cf, KeyFile: kf, DataDir: dir, ConnectIP: &off})
	if err != nil {
		t.Fatalf("relay-only edge must start without TUN: %v", err)
	}
	if srv.hostStateDir != "" || !srv.quicServer.connectIPDisabled {
		t.Fatalf("host touched=%q disabled=%v", srv.hostStateDir, srv.quicServer.connectIPDisabled)
	}
	srv.Close()
	path := filepath.Join(dir, "edge.json")
	b, _ := json.Marshal(map[string]any{"domain": "n.example.com", "cert_file": cf, "key_file": kf, "admin_key": strings.Repeat("a", 32), "data_dir": dir, "listen": "127.0.0.1:0", "connect_ip": false})
	_ = os.WriteFile(path, b, 0o600)
	names := map[string]string{}
	for _, it := range CheckNode(path) {
		names[it.Name] = it.Level
	}
	if names["connect_ip"] != "OK" || names["tun"] != "" || names["firewall"] != "" {
		t.Fatalf("check: %v", names)
	}
	if _, err := ConfigSet(path, "connect_ip", "true"); err != nil {
		t.Fatal(err)
	}
	if v, _ := ConfigGet(path, "connect_ip"); v != "true" {
		t.Fatalf("connect_ip get = %q", v)
	}
}

// 多跳入口：缺 next_hop_addr 或 hop_credential 时启动被拒、check 报 FAIL；配置齐全时 check 通过且说明 CONNECT-IP 关闭。
func TestIngressRoleConfigChecks(t *testing.T) {
	listen, _ := findTestAddr()
	_, err := NewServer(ServerConfig{Listen: listen, Domain: "n.example.com", DataDir: t.TempDir(), Role: "ingress", HopCredential: "hop"})
	if err == nil || !strings.Contains(err.Error(), "next hop address required") {
		t.Fatalf("ingress without next_hop_addr started: %v", err)
	}
	level := func(content string) string {
		path := filepath.Join(t.TempDir(), "edge.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got := ""
		for _, it := range CheckNode(path) {
			if it.Name == "role" {
				got = it.Level
			}
		}
		return got
	}
	if got := level(`{"role":"ingress","domain":"n.example.com"}`); got != "FAIL" {
		t.Fatalf("missing next_hop_addr: role check = %q, want FAIL", got)
	}
	if got := level(`{"role":"ingress","domain":"n.example.com","next_hop_addr":"e.example.com:443"}`); got != "FAIL" {
		t.Fatalf("missing hop_credential: role check = %q, want FAIL", got)
	}
	if got := level(`{"role":"ingress","domain":"n.example.com","next_hop_addr":"e.example.com:443","hop_credential":"h"}`); got != "OK" {
		t.Fatalf("complete ingress config: role check = %q, want OK", got)
	}
}

// 回归：全新安装时数据目录尚未创建，check 必须照常做端口检查，且不得创建数据目录或 edge.lock。
func TestCheckNodeListenWithMissingDataDirDoesNotCreateIt(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "not-yet")
	path := filepath.Join(base, "edge.json")
	b, _ := json.Marshal(map[string]any{"data_dir": dataDir, "listen": "127.0.0.1:0"})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var listen CheckItem
	for _, it := range CheckNode(path) {
		if it.Name == "listen" {
			listen = it
		}
	}
	if listen.Level != "OK" || !strings.Contains(listen.Detail, "free") {
		t.Fatalf("listen check = %+v, want a real port test", listen)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("CheckNode created the data dir (err=%v)", err)
	}
}

// 数据目录存在但还没有 edge.lock：不创建锁文件。
func TestEdgeInstanceRunningDoesNotCreateLockFile(t *testing.T) {
	dir := t.TempDir()
	running, err := edgeInstanceRunning(dir)
	if running || err != nil {
		t.Fatalf("running=%v err=%v", running, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "edge.lock")); !os.IsNotExist(err) {
		t.Fatalf("edge.lock created (err=%v)", err)
	}
}

// 锁被占用才视为运行中；锁释放后恢复；其他错误（此处 data_dir 是普通文件）如实返回并在 check 中为 WARN。
func TestEdgeInstanceRunningDetectsHeldLockAndOtherErrors(t *testing.T) {
	dir := t.TempDir()
	lock, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, lerr := acquireInstanceLock(dir); !errors.Is(lerr, errInstanceLockBusy) {
		t.Fatalf("second acquire = %v, want errInstanceLockBusy", lerr)
	}
	running, err := edgeInstanceRunning(dir)
	if !running || err != nil {
		t.Fatalf("held lock: running=%v err=%v", running, err)
	}
	_ = lock.release()
	if running, err = edgeInstanceRunning(dir); running || err != nil {
		t.Fatalf("released lock: running=%v err=%v", running, err)
	}

	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if running, err = edgeInstanceRunning(notDir); running || err == nil {
		t.Fatalf("data_dir is a file: running=%v err=%v, want error", running, err)
	}
	path := filepath.Join(t.TempDir(), "edge.json")
	b, _ := json.Marshal(map[string]any{"data_dir": notDir, "listen": "127.0.0.1:0"})
	_ = os.WriteFile(path, b, 0o600)
	for _, it := range CheckNode(path) {
		if it.Name == "listen" && it.Level != "WARN" {
			t.Fatalf("listen with unreadable data dir = %+v, want WARN", it)
		}
	}
}
