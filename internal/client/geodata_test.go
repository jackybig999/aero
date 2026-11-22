// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func geoTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AERO_DATA_DIR", dir)
	return dir
}

func newGeoEngine(t *testing.T, handler http.Handler) *Engine {
	t.Helper()
	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	t.Cleanup(func() { SetPhysicalDialerHook(nil) })
	eng := NewEngine()
	t.Cleanup(func() { _ = eng.Close() })
	eng.SetGeoDataURL("http://geodata.example.com" + geoDataAPIPath)
	return eng
}

func serveRules(content string, calls *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(content))
	})
}

// 启动时加载上次落盘的规则；文件不存在不是错误；坏文件报错且不改现有规则。
func TestLoadGeoDataFromDisk(t *testing.T) {
	dir := geoTestEnv(t)
	eng := NewEngine()
	defer eng.Close()

	if n, err := eng.LoadGeoDataFromDisk(); n != 0 || err != nil {
		t.Fatalf("无文件应返回 (0,nil)，got (%d,%v)", n, err)
	}
	if err := os.WriteFile(filepath.Join(dir, geoDataFileName), []byte("persisted-direct.example\n203.0.113.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := eng.LoadGeoDataFromDisk()
	if err != nil || n != 2 {
		t.Fatalf("加载 = (%d,%v)，期望 (2,nil)", n, err)
	}
	if eng.splitEngine.MatchDomain("www.persisted-direct.example") != DIRECT {
		t.Error("落盘规则应在加载后生效（重启不丢）")
	}
	if ts, _ := eng.geoStatus(); ts == 0 {
		t.Error("加载后应有更新时间（取文件时间）")
	}

	// 坏文件（无有效规则）：报错，现有规则保留
	if err := os.WriteFile(filepath.Join(dir, geoDataFileName), []byte("<html>x</html>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.LoadGeoDataFromDisk(); err == nil {
		t.Error("无有效规则的文件应报错")
	}
	if eng.splitEngine.MatchDomain("persisted-direct.example") != DIRECT {
		t.Error("坏文件不应冲掉已加载的规则")
	}
}

// 200 → 落盘+生效；304 → 不变；重启（新引擎）读盘后再同步走 304。
func TestSyncGeoDataPersistsAndConditional(t *testing.T) {
	dir := geoTestEnv(t)
	var calls atomic.Int32
	eng := newGeoEngine(t, serveRules("fresh.example\nfull:exact.example\n198.51.100.0/24\n", &calls))

	n, updated, err := eng.SyncGeoData(context.Background())
	if err != nil || !updated || n < 3 {
		t.Fatalf("首次同步 = (%d,%v,%v)", n, updated, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, geoDataFileName)); !strings.Contains(string(b), "fresh.example") {
		t.Fatal("规则应落盘")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, geoDataETagName)); strings.TrimSpace(string(b)) != `"v1"` {
		t.Fatalf("etag 文件 = %q", b)
	}
	ts, errMsg := eng.geoStatus()
	if ts == 0 || errMsg != "" {
		t.Fatalf("成功后状态 = (%d,%q)", ts, errMsg)
	}

	if _, updated, err := eng.SyncGeoData(context.Background()); err != nil || updated {
		t.Fatalf("第二次应为 304（updated=false），got (%v,%v)", updated, err)
	}

	// 模拟重启：新引擎先读盘，再同步 → 304，规则仍在
	eng2 := newGeoEngine(t, serveRules("fresh.example\n", &calls))
	if _, err := eng2.LoadGeoDataFromDisk(); err != nil {
		t.Fatal(err)
	}
	if _, updated, err := eng2.SyncGeoData(context.Background()); err != nil || updated {
		t.Fatalf("重启后同步应 304，got (%v,%v)", updated, err)
	}
	if eng2.splitEngine.MatchDomain("fresh.example") != DIRECT {
		t.Error("重启后规则应仍然生效")
	}
}

// 磁盘上有 etag 但内存没有规则（例如读盘失败）时，不能带 If-None-Match，否则会因 304 永远拿不到规则。
func TestSyncGeoDataIgnoresETagWithoutLoadedRules(t *testing.T) {
	dir := geoTestEnv(t)
	if err := os.WriteFile(filepath.Join(dir, geoDataETagName), []byte(`"v1"`), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := newGeoEngine(t, serveRules("needed.example\n", nil))
	n, updated, err := eng.SyncGeoData(context.Background())
	if err != nil || !updated || n == 0 {
		t.Fatalf("应当完整下载，got (%d,%v,%v)", n, updated, err)
	}
}

// 伪装页(HTML)、空数据、5xx：全部拒绝，现有规则不变，状态里带出错误。
func TestSyncGeoDataRejectsBadResponses(t *testing.T) {
	geoTestEnv(t)
	cases := map[string]http.HandlerFunc{
		"html 200": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
		},
		"empty 200": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
		},
		"garbage 200": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("<<<>>>\nhttp://x/y\n"))
		},
		"500": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://evil.example/list", http.StatusFound)
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			eng := newGeoEngine(t, h)
			if _, err := eng.splitEngine.ReloadRules([]byte("keep-me.example\n")); err != nil {
				t.Fatal(err)
			}
			if _, _, err := eng.SyncGeoData(context.Background()); err == nil {
				t.Fatal("应报错")
			}
			if eng.splitEngine.MatchDomain("keep-me.example") != DIRECT {
				t.Error("失败不得改动现有规则")
			}
			if _, msg := eng.geoStatus(); msg == "" {
				t.Error("状态里应带出错误原因")
			}
			if _, err := os.Stat(filepath.Join(GetDataDir(), geoDataFileName)); err == nil {
				t.Error("失败不应落盘")
			}
		})
	}
}

// 订阅里还没有节点：明确的错误，而不是去请求一个不存在的默认域名。
func TestSyncGeoDataNoSource(t *testing.T) {
	geoTestEnv(t)
	eng := NewEngine()
	defer eng.Close()
	if _, _, err := eng.SyncGeoData(context.Background()); err != errNoGeoSource {
		t.Fatalf("err = %v, 期望 errNoGeoSource", err)
	}
}

// 来源顺序与地址拼接：当前节点优先、按 IP 拨号、SNI 作 ServerName、去重、封顶，订阅主机排最后。
func TestGeoSources(t *testing.T) {
	eng := NewEngine()
	defer eng.Close()
	eng.mu.Lock()
	eng.activeAddr = "b.example.com:8443"
	eng.savedSubURL = "https://mid.example.com/sub/token"
	eng.appliedSub = &Applied{Servers: []ServerConfig{
		{Address: "a.example.com:443", SNI: "a.example.com"},
		{Address: "b.example.com:8443", Host: "b.example.com", SNI: "cover.example.org", IP: "203.0.113.9"},
		{Address: "a.example.com:443", SNI: "a.example.com"}, // 重复
		{Address: "c.example.com"},                           // 缺端口 → 443，缺 SNI → 用主机名
	}}
	eng.mu.Unlock()

	got := eng.geoSources()
	if len(got) != 4 {
		t.Fatalf("来源数 = %d, 期望 4（3 个节点去重后 + 订阅主机）: %+v", len(got), got)
	}
	if got[3].url != "https://mid.example.com"+geoDataAPIPath {
		t.Errorf("订阅主机应排最后: %+v", got[3])
	}
	b := got[0]
	if b.url != "https://b.example.com:8443"+geoDataAPIPath || b.serverName != "cover.example.org" || b.nodeHost != "b.example.com" || b.dialAddr != "203.0.113.9:8443" {
		t.Errorf("当前节点应排第一并按 IP 拨号: %+v", b)
	}
	var c geoSource
	for _, s := range got {
		if strings.Contains(s.url, "c.example.com") {
			c = s
		}
	}
	if c.url != "https://c.example.com"+geoDataAPIPath || c.serverName != "c.example.com" || c.dialAddr != "" {
		t.Errorf("缺省端口/SNI 的处理不对: %+v", c)
	}
	if last := got[len(got)-1]; last.url != "https://mid.example.com"+geoDataAPIPath {
		t.Errorf("订阅主机应排最后: %+v", last)
	}
	for _, s := range got {
		if strings.Contains(s.url, "aero-protocol.com") {
			t.Errorf("不应再有写死的默认域名: %s", s.url)
		}
	}

	// 显式 URL 优先且唯一
	eng.SetGeoDataURL("http://custom.example/list")
	if g := eng.geoSources(); len(g) != 1 || g[0].url != "http://custom.example/list" {
		t.Errorf("显式 URL 应是唯一来源: %+v", g)
	}

	// 来源上限
	eng.SetGeoDataURL("")
	var many []ServerConfig
	for i := 0; i < 12; i++ {
		many = append(many, ServerConfig{Address: "n" + string(rune('a'+i)) + ".example.com:443"})
	}
	eng.mu.Lock()
	eng.appliedSub = &Applied{Servers: many}
	eng.mu.Unlock()
	if g := eng.geoSources(); len(g) != geoMaxSources {
		t.Errorf("来源数 = %d, 期望封顶 %d", len(g), geoMaxSources)
	}
}

// 后台自动同步：订阅载入前不请求；载入后自动下载；失败后按退避重试；Close 后协程退出。
func TestStartGeoDataAutoSync(t *testing.T) {
	geoTestEnv(t)
	oldFirst, oldRetry, oldWait, oldMax := geoFirstDelay, geoRetryMin, geoNoSourceWait, geoRetryMax
	geoFirstDelay, geoRetryMin, geoNoSourceWait, geoRetryMax = 20*time.Millisecond, 30*time.Millisecond, 20*time.Millisecond, 60*time.Millisecond
	defer func() { geoFirstDelay, geoRetryMin, geoNoSourceWait, geoRetryMax = oldFirst, oldRetry, oldWait, oldMax }()

	var calls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n <= 2 { // 前两次失败，验证退避后重试
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("auto-synced.example\n"))
	})
	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	eng := NewEngine()
	// 不设显式 URL：来源来自订阅节点；节点地址是 http 不可用，这里改用订阅主机兜底来源需要 https，
	// 因此用显式 URL 但先置空来模拟“订阅未载入”，稍后再设置
	eng.StartGeoDataAutoSync()
	time.Sleep(120 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("没有来源时不应发请求，got %d", calls.Load())
	}

	eng.SetGeoDataURL("http://geodata.example.com" + geoDataAPIPath)
	deadline := time.Now().Add(5 * time.Second)
	for !eng.splitEngine.HasDirectRules() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !eng.splitEngine.HasDirectRules() {
		t.Fatalf("自动同步未在期限内成功（请求数 %d）", calls.Load())
	}
	if calls.Load() < 3 {
		t.Errorf("应经历 2 次失败后第 3 次成功，请求数 = %d", calls.Load())
	}
	if eng.splitEngine.MatchDomain("auto-synced.example") != DIRECT {
		t.Error("自动同步的规则应生效")
	}
	if ts, msg := eng.geoStatus(); ts == 0 || msg != "" {
		t.Errorf("成功后状态 = (%d,%q)", ts, msg)
	}

	// 重复启动无副作用；Close 后不再请求
	eng.StartGeoDataAutoSync()
	_ = eng.Close()
	select {
	case <-eng.geoLoopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close 后后台同步协程未退出")
	}
	before := calls.Load()
	time.Sleep(150 * time.Millisecond)
	if calls.Load() != before {
		t.Error("Close 后后台同步应停止")
	}
}

// 应急开关：AERO_DISABLE_GEODATA=1 时不加载磁盘副本、不启动后台同步。
func TestStartGeoDataAutoSyncDisabledByEnv(t *testing.T) {
	dir := geoTestEnv(t)
	if err := os.WriteFile(filepath.Join(dir, geoDataFileName), []byte("persisted.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AERO_DISABLE_GEODATA", "1")
	eng := NewEngine()
	defer eng.Close()
	eng.StartGeoDataAutoSync()
	if eng.splitEngine.HasDirectRules() {
		t.Error("开关打开时不应加载下发规则")
	}
	if eng.geoLoopDone != nil {
		t.Error("开关打开时不应启动后台同步协程")
	}
}

// 节点与订阅链接指向同一主机（默认 443）时只下载一次：URL 里省略默认端口，才能去重。
// （用户日志里同一主机被连续尝试了两次，每次都等满超时。）
func TestGeoSourcesDedupesSameHostDefaultPort(t *testing.T) {
	eng := NewEngine()
	defer eng.Close()
	eng.mu.Lock()
	eng.savedSubURL = "https://us.example.com/sub/token"
	eng.appliedSub = &Applied{Servers: []ServerConfig{{Address: "us.example.com:443", SNI: "us.example.com"}}}
	eng.mu.Unlock()
	got := eng.geoSources()
	if len(got) != 1 || got[0].url != "https://us.example.com"+geoDataAPIPath {
		t.Fatalf("同一主机应只有一个来源，got %+v", got)
	}
	// 非默认端口仍然保留；IPv6 字面量加方括号
	if g := geoURLHost("2001:db8::1", "443"); g != "[2001:db8::1]" {
		t.Errorf("IPv6 默认端口 = %s", g)
	}
	if g := geoURLHost("us.example.com", "8443"); g != "us.example.com:8443" {
		t.Errorf("非默认端口 = %s", g)
	}
}
