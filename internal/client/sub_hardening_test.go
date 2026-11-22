// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------- M5：C5 §3 字段校验

func validServer(mut func(*ServerConfig)) ServerConfig {
	s := ServerConfig{Name: "n", Host: "node.example.com", Address: "node.example.com:443", Token: "tok", SNI: "node.example.com", Protocol: "connect-ip"}
	if mut != nil {
		mut(&s)
	}
	return s
}

func TestValidateAndNormalize_Table(t *testing.T) {
	cases := []struct {
		name     string
		srv      ServerConfig
		wantErr  string // 非空：单节点订阅应整份被拒，错误包含该文本
		wantAddr string
	}{
		{"ok", validServer(nil), "", "node.example.com:443"},
		{"hostname only address gets 443", validServer(func(s *ServerConfig) { s.Address = "node.example.com" }), "", "node.example.com:443"},
		{"address empty falls back to host", validServer(func(s *ServerConfig) { s.Address = "" }), "", "node.example.com:443"},
		{"bracketed ipv6 without port", validServer(func(s *ServerConfig) { s.Address = "[2001:db8::1]" }), "", "[2001:db8::1]:443"},
		{"bare ipv6 without port", validServer(func(s *ServerConfig) { s.Address = "2001:db8::1" }), "", "[2001:db8::1]:443"},
		{"port 1", validServer(func(s *ServerConfig) { s.Address = "node.example.com:1" }), "", "node.example.com:1"},
		{"port 65535", validServer(func(s *ServerConfig) { s.Address = "node.example.com:65535" }), "", "node.example.com:65535"},
		{"port 0", validServer(func(s *ServerConfig) { s.Address = "node.example.com:0" }), "invalid port", ""},
		{"port 65536", validServer(func(s *ServerConfig) { s.Address = "node.example.com:65536" }), "invalid port", ""},
		{"port negative", validServer(func(s *ServerConfig) { s.Address = "node.example.com:-1" }), "invalid port", ""},
		{"port not a number", validServer(func(s *ServerConfig) { s.Address = "node.example.com:https" }), "invalid port", ""},
		{"empty host in address", validServer(func(s *ServerConfig) { s.Address = ":443" }), "empty host", ""},
		{"garbage host:port", validServer(func(s *ServerConfig) { s.Address = "a:b:c" }), "not a valid host", ""},
		{"alt port 0", validServer(func(s *ServerConfig) { s.AltPorts = []int{2083, 0} }), "alt_ports", ""},
		{"alt port 65536", validServer(func(s *ServerConfig) { s.AltPorts = []int{65536} }), "alt_ports", ""},
		{"alt port negative", validServer(func(s *ServerConfig) { s.AltPorts = []int{-5} }), "alt_ports", ""},
		{"missing sni", validServer(func(s *ServerConfig) { s.SNI = "" }), "missing sni", ""},
		{"missing protocol", validServer(func(s *ServerConfig) { s.Protocol = "" }), "protocol", ""},
		{"protocol tcp", validServer(func(s *ServerConfig) { s.Protocol = "tcp" }), "protocol", ""},
		{"protocol wrong case", validServer(func(s *ServerConfig) { s.Protocol = "CONNECT-IP" }), "protocol", ""},
		{"missing token", validServer(func(s *ServerConfig) { s.Token = " " }), "missing token", ""},
		{"missing address and host", validServer(func(s *ServerConfig) { s.Address, s.Host = "", "" }), "missing address and host", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sub := &Subscription{Version: "aero/3.0", Servers: []ServerConfig{c.srv}}
			err := sub.ValidateAndNormalize()
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := sub.Servers[0].Address; got != c.wantAddr {
				t.Fatalf("Address = %q, want %q", got, c.wantAddr)
			}
		})
	}
}

func TestValidateAndNormalize_SkipsInvalidNodesKeepsValid(t *testing.T) {
	buf := captureLog(t)
	sub := &Subscription{Version: "aero/3.0", Servers: []ServerConfig{
		validServer(func(s *ServerConfig) { s.Name = "bad-port"; s.Address = "node.example.com:70000" }),
		validServer(func(s *ServerConfig) { s.Name = "good"; s.Token = "SECRET_TOKEN_VALUE" }),
		validServer(func(s *ServerConfig) { s.Name = "bad-proto"; s.Protocol = "tcp" }),
	}}
	if err := sub.ValidateAndNormalize(); err != nil {
		t.Fatalf("expected valid nodes to survive, got %v", err)
	}
	if len(sub.Servers) != 1 || sub.Servers[0].Name != "good" {
		t.Fatalf("servers = %+v, want only [good]", sub.Servers)
	}
	out := buf.String()
	if !strings.Contains(out, "bad-port") || !strings.Contains(out, "bad-proto") {
		t.Errorf("skipped nodes should be logged, log = %q", out)
	}
	if strings.Contains(out, "SECRET_TOKEN_VALUE") {
		t.Errorf("log must not contain tokens: %q", out)
	}
}

func TestValidateAndNormalize_AltPortsDedupAndMainPortFiltered(t *testing.T) {
	sub := &Subscription{Version: "aero/3.0", Servers: []ServerConfig{
		validServer(func(s *ServerConfig) { s.AltPorts = []int{8443, 443, 8443, 2083} }),
	}}
	if err := sub.ValidateAndNormalize(); err != nil {
		t.Fatal(err)
	}
	got := sub.Servers[0].AltPorts
	if len(got) != 2 || got[0] != 8443 || got[1] != 2083 {
		t.Fatalf("AltPorts = %v, want [8443 2083]", got)
	}
}

// ---------------------------------------------------------------- H3：只接受 https，重定向受限

func TestFetchSubscription_RejectsNonHTTPS(t *testing.T) {
	var dials atomic.Int32
	useSubHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dials.Add(1) }))
	for _, u := range []string{
		"http://sub.aero.test/sub/x",
		"HTTP://sub.aero.test/sub/x",
		"ftp://sub.aero.test/sub/x",
		"file:///etc/passwd",
		"//sub.aero.test/sub/x",
		"sub.aero.test/sub/x",
		"https:///sub/x",
		"https://",
	} {
		_, err := FetchSubscription(context.Background(), u, SubFetchOptions{DisableCache: true})
		if err == nil {
			t.Errorf("FetchSubscription(%q) accepted a non-https URL", u)
			continue
		}
		if !strings.Contains(err.Error(), "https://") {
			t.Errorf("FetchSubscription(%q) error should say https is required, got: %v", u, err)
		}
	}
	if _, _, err := fetchSingleSubURL(context.Background(), "http://sub.aero.test/sub/x", SubFetchOptions{}); err == nil {
		t.Error("fetchSingleSubURL accepted http://")
	}
	if dials.Load() != 0 {
		t.Errorf("a rejected URL must not reach the network, handler hits = %d", dials.Load())
	}
}

func TestFetchSingleSubURL_Redirects(t *testing.T) {
	cases := []struct {
		name    string
		hops    int    // 经过多少次重定向到达最终响应
		toHTTP  bool   // 第一跳重定向到 http://
		wantErr string // 空表示成功
	}{
		{"no redirect", 0, false, ""},
		{"3 redirects allowed", 3, false, ""},
		{"4 redirects rejected", 4, false, "redirected more than"},
		{"redirect to http rejected", 1, true, "non-https"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var final atomic.Int32
			useSubHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var n int
				_, _ = fmt.Sscanf(r.URL.Path, "/r/%d", &n)
				if c.toHTTP {
					http.Redirect(w, r, "http://redir.aero.test/sub/x", http.StatusFound)
					return
				}
				if n < c.hops {
					http.Redirect(w, r, fmt.Sprintf("https://redir.aero.test/r/%d", n+1), http.StatusFound)
					return
				}
				final.Add(1)
				fmt.Fprint(w, subJSONFor("redir.aero.test:443", "tok"))
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			sub, _, err := fetchSingleSubURL(ctx, "https://redir.aero.test/r/0", SubFetchOptions{})
			if c.wantErr == "" {
				if err != nil || sub == nil {
					t.Fatalf("unexpected failure: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, c.wantErr)
			}
			if final.Load() != 0 {
				t.Errorf("rejected redirect chain still reached the final response")
			}
		})
	}
}

// ---------------------------------------------------------------- M1：响应体上限

func TestFetchSingleSubURL_BodyLimit(t *testing.T) {
	cases := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"exactly at limit", maxSubscriptionBodyBytes, false},
		{"one byte over", maxSubscriptionBodyBytes + 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := subJSONFor("big.aero.test:443", "tok")
			body += strings.Repeat(" ", c.size-len(body))
			useSubHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_, got, err := fetchSingleSubURL(ctx, "https://big.aero.test/sub/x", SubFetchOptions{})
			if c.wantErr {
				if err == nil || !strings.Contains(err.Error(), "exceeds") {
					t.Fatalf("err = %v, want size error", err)
				}
				return
			}
			if err != nil || len(got) != c.size {
				t.Fatalf("err = %v, len = %d", err, len(got))
			}
		})
	}
}

func TestFetchSubscription_OversizeBodyNotCached(t *testing.T) {
	body := subJSONFor("big.aero.test:443", "tok")
	body += strings.Repeat(" ", maxSubscriptionBodyBytes+1-len(body))
	useSubHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	const u = "https://big.aero.test:8443/sub/x"
	if _, err := FetchSubscription(context.Background(), u, SubFetchOptions{DisableCache: true}); err == nil {
		t.Fatal("oversize body accepted")
	}
	if b := LoadLastBody(u); len(b) != 0 {
		t.Fatalf("oversize body was written to the cache (%d bytes)", len(b))
	}
}

// ---------------------------------------------------------------- M2：拨号层校验实际目标 IP

func TestSubForbiddenIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true}, {"::1", true}, {"10.1.2.3", true}, {"172.16.0.1", true}, {"172.31.255.255", true},
		{"192.168.0.1", true}, {"fc00::1", true}, {"fd12:3456::1", true}, {"169.254.169.254", true}, {"fe80::1", true},
		{"0.0.0.0", true}, {"::", true}, {"100.64.0.1", true}, {"100.127.255.255", true}, {"198.18.0.1", true}, {"198.19.255.1", true},
		{"224.0.0.1", true}, {"ff02::1", true}, {"::ffff:10.0.0.1", true}, {"0.1.2.3", true},
		{"8.8.8.8", false}, {"1.1.1.1", false}, {"172.32.0.1", false}, {"100.128.0.1", false}, {"198.20.0.1", false},
		{"2606:4700:4700::1111", false},
	}
	for _, c := range cases {
		if got := subForbiddenIP(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("subForbiddenIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func setSubLookup(t *testing.T, fn func(ctx context.Context, host string) ([]net.IP, error)) {
	t.Helper()
	subLookupIPsForTest.Store(&fn)
	t.Cleanup(func() { subLookupIPsForTest.Store(nil) })
}

func TestSubDialContext_ResolvedPrivateRejected(t *testing.T) {
	SetPhysicalDialerHook(nil)
	cases := []struct {
		name string
		ips  []string
	}{
		{"10/8", []string{"10.0.0.8"}},
		{"172.16/12", []string{"172.20.1.1"}},
		{"192.168/16", []string{"192.168.1.1"}},
		{"fc00::/7", []string{"fc00::5"}},
		{"link-local v4", []string{"169.254.169.254"}},
		{"link-local v6", []string{"fe80::1"}},
		{"loopback", []string{"127.0.0.1"}},
		{"loopback v6", []string{"::1"}},
		{"public plus private mixed", []string{"8.8.8.8", "10.0.0.1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var calls int
			setSubLookup(t, func(ctx context.Context, host string) ([]net.IP, error) {
				calls++
				var out []net.IP
				for _, s := range c.ips {
					out = append(out, net.ParseIP(s))
				}
				return out, nil
			})
			conn, err := subDialContext(context.Background(), "tcp", "rebind.example.com:443")
			if err == nil {
				_ = conn.Close()
				t.Fatal("private resolution was dialed")
			}
			if !strings.Contains(err.Error(), "forbidden") {
				t.Fatalf("err = %v, want forbidden", err)
			}
			if calls != 1 {
				t.Errorf("lookup calls = %d, want 1", calls)
			}
		})
	}
	for _, h := range []string{"localhost:443", "LOCALHOST.:443", "a.localhost:443", "127.0.0.1:443", "10.0.0.1:443", "[fc00::1]:443"} {
		if conn, err := subDialContext(context.Background(), "tcp", h); err == nil {
			_ = conn.Close()
			t.Errorf("dial %s should be forbidden", h)
		}
	}
}

// physical hook 路径：字面量私网在调用钩子之前拒绝；主机名则在连接建立后核对对端地址。
func TestSubDialContext_HookPathValidated(t *testing.T) {
	var hookCalls atomic.Int32
	var closed atomic.Bool
	SetPhysicalDialerHook(func(ctx context.Context, network, addr string) (net.Conn, error) {
		hookCalls.Add(1)
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return &fakeRemoteConn{Conn: c1, remote: &net.TCPAddr{IP: net.ParseIP("10.9.8.7"), Port: 443}, closed: &closed}, nil
	})
	t.Cleanup(func() { SetPhysicalDialerHook(nil) })

	if _, err := subDialContext(context.Background(), "tcp", "192.168.0.9:443"); err == nil {
		t.Error("literal private IP reached the hook")
	}
	if hookCalls.Load() != 0 {
		t.Errorf("hook called %d times for a forbidden literal", hookCalls.Load())
	}
	conn, err := subDialContext(context.Background(), "tcp", "node.aero.test:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("hook connection to a private peer was accepted")
	}
	if !strings.Contains(err.Error(), "forbidden") || !closed.Load() {
		t.Errorf("err = %v, closed = %v; want forbidden and the connection closed", err, closed.Load())
	}
}

type fakeRemoteConn struct {
	net.Conn
	remote net.Addr
	closed *atomic.Bool
}

func (f *fakeRemoteConn) RemoteAddr() net.Addr { return f.remote }
func (f *fakeRemoteConn) Close() error         { f.closed.Store(true); return f.Conn.Close() }

// 真实 TCP：主机名解析到回环，只有显式测试开关才放行；解析恰好一次（拨的是已校验的 IP 字面量）；重定向到私网被拒。
func TestSubDialContext_ResolveOnceAndRedirectToPrivate(t *testing.T) {
	SetPhysicalDialerHook(nil)
	var redirectTarget atomic.Value
	redirectTarget.Store("")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loc := redirectTarget.Load().(string); loc != "" {
			http.Redirect(w, r, loc, http.StatusFound)
			return
		}
		fmt.Fprint(w, subJSONFor("example.com:443", "tok"))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	subRootCAsForTest.Store(pool)
	t.Cleanup(func() { subRootCAsForTest.Store(nil); subAllowLoopbackForTest.Store(false) })

	var lookups atomic.Int32
	setSubLookup(t, func(ctx context.Context, host string) ([]net.IP, error) {
		lookups.Add(1)
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	})
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("https://example.com:%d/sub/x", port)

	// 默认（生产）：解析到回环 -> 拒绝
	if _, _, err := fetchSingleSubURL(context.Background(), target, SubFetchOptions{}); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("loopback resolution must be forbidden by default, err = %v", err)
	}

	subAllowLoopbackForTest.Store(true)
	lookups.Store(0)
	if _, _, err := fetchSingleSubURL(context.Background(), target, SubFetchOptions{}); err != nil {
		t.Fatalf("fetch with the loopback test switch failed: %v", err)
	}
	if lookups.Load() != 1 {
		t.Errorf("lookups = %d, want exactly 1", lookups.Load())
	}

	// 开关只放行回环；重定向到私网地址仍被拒绝
	redirectTarget.Store("https://192.168.7.7/sub/x")
	if _, _, err := fetchSingleSubURL(context.Background(), target, SubFetchOptions{}); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("redirect to a private IP must be forbidden, err = %v", err)
	}
	redirectTarget.Store("https://rebind.example.net/sub/x")
	setSubLookup(t, func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.2")}, nil // 重定向目标的名字解析到私网（DNS 重绑定）
	})
	if _, _, err := fetchSingleSubURL(context.Background(), target, SubFetchOptions{}); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("redirect to a host resolving to a private IP must be forbidden, err = %v", err)
	}
}

// ---------------------------------------------------------------- M3：缓存文件

func TestLastBodyPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AERO_DATA_DIR", dir)
	const urlA = "https://sub.example.com/sub/SECRETSLUG-a"
	const urlB = "https://sub.example.com/sub/SECRETSLUG-b"
	pa, pb := lastBodyPath(urlA), lastBodyPath(urlB)
	if pa == pb {
		t.Fatal("different subscription URLs share a cache file")
	}
	if filepath.Dir(pa) != dir {
		t.Errorf("cache file %s is not in the data dir %s", pa, dir)
	}
	if !regexp.MustCompile(`^\.last-sub-[0-9a-f]{16}$`).MatchString(filepath.Base(pa)) {
		t.Errorf("unexpected cache file name %q", filepath.Base(pa))
	}
	if strings.Contains(pa, "SECRETSLUG") || strings.Contains(pa, "example") {
		t.Errorf("cache path leaks the URL: %s", pa)
	}
	if lastBodyPath(urlA) != pa || lastBodyPath(" "+urlA+"\n") != pa {
		t.Error("cache path must be stable for the same URL")
	}
}

func TestSaveLoadClearLastBody(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AERO_DATA_DIR", dir)
	const a, b = "https://a.example.com/sub/a", "https://b.example.com/sub/b"
	SaveLastBody(a, []byte("body-a-1"))
	SaveLastBody(b, []byte("body-b"))
	SaveLastBody(a, []byte("body-a-2")) // 原子替换已有文件
	if got := string(LoadLastBody(a)); got != "body-a-2" {
		t.Errorf("a = %q", got)
	}
	if got := string(LoadLastBody(b)); got != "body-b" {
		t.Errorf("b = %q (must not be overwritten by another URL)", got)
	}
	if LoadLastBody("https://c.example.com/sub/c") != nil {
		t.Error("an unknown URL must not see any other subscription's cache")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(lastBodyPath(a))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("cache file mode = %v err = %v, want 0600", fi.Mode().Perm(), err)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
	ClearLastBody(a)
	if LoadLastBody(a) != nil || LoadLastBody(b) == nil {
		t.Error("ClearLastBody must only remove the given URL's cache")
	}
}

func TestLastBody_OldLocationNotUsed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AERO_DATA_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, ".last-sub-body"), []byte(subJSONFor("old.example.com:443", "old")), 0o600); err != nil {
		t.Fatal(err)
	}
	if LoadLastBody("https://sub.example.com/sub/x") != nil {
		t.Error("the legacy shared .last-sub-body must not be read")
	}
}

func TestSaveLastBody_WriteFailureIsLogged(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AERO_DATA_DIR", file) // 数据目录其实是个文件：写必然失败
	buf := captureLog(t)
	SaveLastBody("https://sub.example.com/sub/x", []byte("body"))
	if !strings.Contains(buf.String(), "cannot cache subscription") {
		t.Errorf("write failure must be logged, log = %q", buf.String())
	}
	if strings.Contains(buf.String(), "sub.example.com") {
		t.Errorf("log must not contain the subscription URL: %q", buf.String())
	}
}

func TestSaveLoadLastBody_Concurrent(t *testing.T) {
	t.Setenv("AERO_DATA_DIR", t.TempDir())
	const u = "https://sub.example.com/sub/x"
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			SaveLastBody(u, []byte(fmt.Sprintf("body-%02d-%s", i, strings.Repeat("x", 4096))))
			if b := LoadLastBody(u); len(b) != 0 && !strings.HasPrefix(string(b), "body-") {
				t.Errorf("torn read: %.20q", b)
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------- H2：缓存回退必须可区分

type toggleServer struct {
	offline  atomic.Bool
	status   atomic.Int32 // 离线时的状态码，默认 500
	hits     atomic.Int32 // 全部请求
	primary  atomic.Int32 // 不带端口的 Host（主通道 443）请求，每次拉取尝试一次
	token    atomic.Value // 在线时下发的 token
	hostName string
}

func newToggleServer(host, token string) *toggleServer {
	s := &toggleServer{hostName: host}
	s.token.Store(token)
	s.status.Store(http.StatusInternalServerError)
	return s
}

func (s *toggleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	if !strings.Contains(r.Host, ":") {
		s.primary.Add(1)
	}
	if s.offline.Load() {
		w.WriteHeader(int(s.status.Load()))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, subJSONFor(s.hostName+":443", s.token.Load().(string)))
}

func TestFetchSubscription_CacheFallbackIsDistinguishable(t *testing.T) {
	for _, u := range []string{"https://fb.aero.test/sub/a", "https://fb.aero.test:8443/sub/a"} {
		t.Run(u, func(t *testing.T) {
			srv := newToggleServer("fb.aero.test", "tok_live")
			useSubHTTPS(t, srv)
			ctx := context.Background()

			live, err := FetchSubscription(ctx, u, SubFetchOptions{})
			if err != nil || live.FromCache {
				t.Fatalf("online fetch: err=%v fromCache=%v", err, live != nil && live.FromCache)
			}

			srv.offline.Store(true)
			cached, err := FetchSubscription(ctx, u, SubFetchOptions{})
			if err != nil {
				t.Fatalf("cache fallback should still return a subscription (startup must work offline): %v", err)
			}
			if !cached.FromCache || cached.Servers[0].Token != "tok_live" {
				t.Fatalf("fallback result must be flagged FromCache with the cached node: %+v", cached)
			}
			applied, err := ApplySubscription(cached)
			if err != nil || !applied.FromCache {
				t.Fatalf("Applied must carry FromCache: err=%v applied=%+v", err, applied)
			}
			if live2, _ := ApplySubscription(live); live2.FromCache {
				t.Error("a live subscription must not be flagged FromCache")
			}

			if _, err := FetchSubscription(ctx, u, SubFetchOptions{DisableCache: true}); err == nil {
				t.Error("DisableCache must not fall back to the cache")
			}
			// 换成另一个订阅 URL：不得回退到上一个订阅的节点
			other := strings.Replace(u, "/sub/a", "/sub/other", 1)
			if sub, err := FetchSubscription(ctx, other, SubFetchOptions{}); err == nil {
				t.Fatalf("a different subscription URL got another subscription's cache: %+v", sub)
			}
		})
	}
}

func TestFetchSubscription_403ClearsCache(t *testing.T) {
	srv := newToggleServer("fb.aero.test", "tok_live")
	useSubHTTPS(t, srv)
	const u = "https://fb.aero.test/sub/a"
	if _, err := FetchSubscription(context.Background(), u, SubFetchOptions{}); err != nil {
		t.Fatal(err)
	}
	srv.status.Store(http.StatusForbidden)
	srv.offline.Store(true)
	if _, err := FetchSubscription(context.Background(), u, SubFetchOptions{}); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("err = %v, want revoked", err)
	}
	if LoadLastBody(u) != nil {
		t.Error("cache must be cleared after 403")
	}
}

// 启动时订阅服务不可达：仍能用缓存应用订阅并连上节点
func TestEngineStartupUsesCacheWhenOffline(t *testing.T) {
	srv := newToggleServer("fb.aero.test", "tok_start")
	useSubHTTPS(t, srv)
	const u = "https://fb.aero.test/sub/a"
	if _, err := FetchSubscription(context.Background(), u, SubFetchOptions{}); err != nil {
		t.Fatal(err)
	}
	srv.offline.Store(true)

	eng := NewEngine()
	defer eng.Close()
	applied, err := eng.LoadAndApplySubscription(u)
	if err != nil {
		t.Fatalf("startup with the subscription service down must still work from cache: %v", err)
	}
	if !applied.FromCache {
		t.Error("applied should be flagged FromCache")
	}
	if addr, tok, _, _ := getActiveEdge(); tok != "tok_start" || addr == "" {
		t.Errorf("active edge = %q / %q, want the cached node and token", addr, tok)
	}
}

// ---------------------------------------------------------------- H2：token 刷新不空转

func setRefreshTimings(t *testing.T, minRetry, maxRetry time.Duration) {
	t.Helper()
	oldMin, oldMax := tokenRefreshMinRetryNs.Load(), tokenRefreshMaxRetryNs.Load()
	tokenRefreshMinRetryNs.Store(int64(minRetry))
	tokenRefreshMaxRetryNs.Store(int64(maxRetry))
	t.Cleanup(func() { tokenRefreshMinRetryNs.Store(oldMin); tokenRefreshMaxRetryNs.Store(oldMax) })
}

func TestTokenRefresher_BacksOffInsteadOfSpinning(t *testing.T) {
	cases := []struct {
		name    string
		offline bool // true：订阅服务 5xx（回退到缓存）；false：服务正常但 token 没变
	}{
		{"subscription service down (cache fallback)", true},
		{"refresh succeeds but token unchanged", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setRefreshTimings(t, 60*time.Millisecond, 240*time.Millisecond)
			now := time.Now()
			oldTok := fakeSignedToken(now.Add(-90*time.Minute), now.Add(30*time.Minute), "old") // 已过 75%
			newTok := fakeSignedToken(now, now.Add(24*time.Hour), "new")
			srv := newToggleServer("rf.aero.test", oldTok)
			useSubHTTPS(t, srv)

			eng := NewEngine()
			defer eng.Close()
			if _, err := eng.LoadAndApplySubscription("https://rf.aero.test/sub/x"); err != nil {
				t.Fatalf("initial load: %v", err)
			}
			srv.offline.Store(c.offline)
			srv.primary.Store(0)

			time.Sleep(time.Second)
			attempts := srv.primary.Load()
			// 退避 60,120,240,240...ms：1 秒内约 6 次；空转时是成百上千次
			if attempts < 2 || attempts > 12 {
				t.Fatalf("refresh attempts in 1s = %d, want 2..12 (backoff, no spinning)", attempts)
			}

			// 服务恢复并下发新 token：按退避重试自行换上新 token（不需要外部 kick）
			srv.offline.Store(false)
			srv.token.Store(newTok)
			deadline := time.Now().Add(3 * time.Second)
			for {
				if _, tok, _, _ := getActiveEdge(); tok == newTok {
					return
				}
				if time.Now().After(deadline) {
					t.Fatal("token not rotated after the service recovered")
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

// 401 之后拿到的是缓存：不能报“订阅仍带着它（已吊销）”，也不能当作成功换了 token
func TestRefreshAfterAuthFailure_CacheIsNotRevocation(t *testing.T) {
	buf := captureLog(t)
	srv := newToggleServer("rf.aero.test", "tok_same")
	useSubHTTPS(t, srv)
	eng := NewEngine()
	defer eng.Close()
	const u = "https://rf.aero.test/sub/x"
	if _, err := eng.LoadAndApplySubscription(u); err != nil {
		t.Fatal(err)
	}
	srv.offline.Store(true)
	eng.refreshAfterAuthFailure()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), "refresh after authentication failure failed") {
		if time.Now().After(deadline) {
			t.Fatalf("expected a failure log for the cache result, log = %q", buf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	out := buf.String()
	if strings.Contains(out, "still carries") || strings.Contains(out, "revoked") {
		t.Errorf("a cached result must not be reported as revocation: %q", out)
	}
	if !strings.Contains(out, "cached copy") {
		t.Errorf("log should say only the cached copy was available: %q", out)
	}
}

// 在线且 token 未变才是“订阅仍带着它”
func TestRefreshAfterAuthFailure_LiveSameTokenReportsRevoked(t *testing.T) {
	buf := captureLog(t)
	srv := newToggleServer("rf.aero.test", "tok_same")
	useSubHTTPS(t, srv)
	eng := NewEngine()
	defer eng.Close()
	if _, err := eng.LoadAndApplySubscription("https://rf.aero.test/sub/x"); err != nil {
		t.Fatal(err)
	}
	eng.refreshAfterAuthFailure()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), "still carries") {
		if time.Now().After(deadline) {
			t.Fatalf("expected the revoked message for a live subscription, log = %q", buf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
