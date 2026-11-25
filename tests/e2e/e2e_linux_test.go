//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

// 黑盒端到端测试：编译真实的 cmd/edge 与 cmd/client，在隔离的用户 + 网络 + 挂载 + PID 命名空间中运行
// （宿主不受影响），用真实 QUIC 验证数据面。不 import 任何 internal 包（组件隔离门禁）。
//
// 拓扑：
//
//	[C 客户端] 46.0.0.2 ── 46.0.0.1 [A edge :443] 45.0.0.1 ── 45.0.0.2 [B “互联网” HTTP:80 UDP:7]
//
// C 没有到 B 的路由：能访问到 B 即证明流量经过了 edge。测试依次验证：直连不通、TCP、UDP、edge 重启后自动重连。
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	roleEnv    = "AERO_E2E_ROLE"
	dirEnv     = "AERO_E2E_DIR"
	nodeDomain = "edge.e2e.test"
	edgeOnC    = "46.0.0.1"
	clientIP   = "46.0.0.2"
	edgeOnB    = "45.0.0.1"
	internetIP = "45.0.0.2"
	socksAddr  = "127.0.0.1:55555"
	clientAPI  = "127.0.0.1:19877"
)

// TestEdgeClientEndToEnd 是入口：编译程序后在新命名空间中重新执行自身（role=root）完成编排。
func TestEdgeClientEndToEnd(t *testing.T) {
	switch os.Getenv(roleEnv) {
	case "":
	case "root":
		runRoot(t)
		return
	default:
		t.Skip("helper role")
	}
	if testing.Short() {
		t.Skip("end-to-end test skipped in -short mode")
	}
	for _, tool := range []string{"unshare", "ip", "mount"} {
		if _, err := exec.LookPath(tool); err != nil {
			envSkip(t, "%s not available", tool)
		}
	}
	dir := t.TempDir()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	for _, c := range []string{"edge", "client"} {
		if pre := os.Getenv("AERO_E2E_BIN"); pre != "" { // 预先编译好的程序（在没有 Go 工具链的机器上运行）
			b, err := os.ReadFile(filepath.Join(pre, c))
			if err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(filepath.Join(dir, c), b, 0o755)
			continue
		}
		build := exec.Command("go", "build", "-o", filepath.Join(dir, c), "./cmd/"+c)
		build.Dir = root
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", c, err, out)
		}
	}
	cmd := exec.Command("unshare", "-rnmpf", "--mount-proc", os.Args[0], "-test.run=^TestEdgeClientEndToEnd$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), roleEnv+"=root", dirEnv+"="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil && (bytes.Contains(out, []byte("Operation not permitted")) || bytes.Contains(out, []byte("unshare failed"))) {
		envSkip(t, "namespaces not permitted: %s", out)
	}
	if err != nil || !bytes.Contains(out, []byte("--- PASS: TestEdgeClientEndToEnd")) {
		t.Fatalf("end-to-end run failed: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

// ---------------- 编排（命名空间 A，edge 所在） ----------------

func runRoot(t *testing.T) {
	dir := os.Getenv(dirEnv)
	must(t, "ip", "link", "set", "lo", "up")

	// /etc/hosts 只在本挂载命名空间内替换：测试域名解析到 edge 在客户端链路上的地址
	hosts := filepath.Join(dir, "hosts")
	_ = os.WriteFile(hosts, []byte("127.0.0.1 localhost\n::1 localhost\n"+edgeOnC+" "+nodeDomain+"\n"), 0o644)
	must(t, "mount", "--bind", hosts, "/etc/hosts")
	// 不使用宿主的 systemd-resolved：客户端 TUN 模式在 127.0.0.53 存根时会调用 resolvectl，
	// 后者经 D-Bus 作用于宿主（跨越网络命名空间）。另放一个假的 resolvectl，被调用即判失败。
	resolv := filepath.Join(dir, "resolv.conf")
	_ = os.WriteFile(resolv, []byte("nameserver "+edgeOnC+"\n"), 0o644)
	must(t, "mount", "--bind", resolv, "/etc/resolv.conf")
	fakeBin := filepath.Join(dir, "bin")
	_ = os.MkdirAll(fakeBin, 0o755)
	_ = os.WriteFile(filepath.Join(fakeBin, "resolvectl"), []byte("#!/bin/sh\ntouch "+filepath.Join(dir, "resolvectl-called")+"\nexit 1\n"), 0o755)
	os.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))

	caPEM, certFile, keyFile := makeCerts(t, dir)
	caFile := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(caFile, caPEM, 0o644)

	// B：“互联网”
	inet := startRole(t, "internet", nil)
	must(t, "ip", "link", "add", "veth-ab", "type", "veth", "peer", "name", "veth-ba", "netns", fmt.Sprint(inet.Process.Pid))
	must(t, "ip", "addr", "add", edgeOnB+"/24", "dev", "veth-ab")
	must(t, "ip", "link", "set", "veth-ab", "up")
	must(t, "ip", "route", "add", "default", "via", internetIP)
	waitFile(t, filepath.Join(dir, "internet-ready"), 20*time.Second)

	// A：edge
	_, tunErr := os.Stat("/dev/net/tun")
	connectIP := tunErr == nil
	adminKey := hex.EncodeToString(randBytes(32))
	cfg := map[string]any{
		"domain": nodeDomain, "advertise_host": nodeDomain, "listen": ":443",
		"cert_file": certFile, "key_file": keyFile, "data_dir": filepath.Join(dir, "edge-data"),
		"admin_key": adminKey, "connect_ip": connectIP,
	}
	cfgFile := filepath.Join(dir, "edge.json")
	b, _ := json.Marshal(cfg)
	_ = os.WriteFile(cfgFile, b, 0o600)
	httpc := tlsClient(t, caPEM)
	// 新网络命名空间的 ip_forward 初值继承自宿主（宿主跑 docker 或 edge 时为 1）：记录后比较
	fwdBefore, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	edge := startEdge(t, dir, cfgFile, httpc)
	t.Logf("edge up (connect_ip=%v)", connectIP)

	// 管理员订阅地址（经 edge 控制台接口，黑盒）
	statusReq, _ := http.NewRequest(http.MethodGet, "https://"+nodeDomain+"/console/api/status", nil)
	statusReq.Header.Set("Authorization", "Bearer "+adminKey)
	resp, err := httpc.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		AdminSubURL string `json:"admin_sub_url"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if !strings.HasPrefix(st.AdminSubURL, "https://") {
		t.Fatalf("no admin subscription URL: %q", st.AdminSubURL)
	}

	// C：客户端
	client := startRole(t, "client", []string{"AERO_E2E_SUB=" + st.AdminSubURL, "AERO_E2E_CA=" + caFile})
	must(t, "ip", "link", "add", "veth-ac", "type", "veth", "peer", "name", "veth-ca", "netns", fmt.Sprint(client.Process.Pid))
	must(t, "ip", "addr", "add", edgeOnC+"/24", "dev", "veth-ac")
	must(t, "ip", "link", "set", "veth-ac", "up")
	applyNetem(t, "veth-ac") // 仅在 AERO_E2E_NETEM 设置时生效

	// 客户端第一阶段通过后重启 edge，验证客户端自动重连
	waitFile(t, filepath.Join(dir, "client-phase1"), 90*time.Second)
	stopProc(t, edge, "edge")
	edge = startEdge(t, dir, cfgFile, httpc)
	_ = os.WriteFile(filepath.Join(dir, "edge-restarted"), nil, 0o644)

	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("client role failed: %v\n%s", err, readFile(dir, "role-client.log"))
		}
	case <-time.After(120 * time.Second):
		_ = client.Process.Kill()
		t.Fatalf("client role timed out\n%s", readFile(dir, "role-client.log"))
	}
	t.Logf("client role:\n%s", readFile(dir, "role-client.log"))

	stopProc(t, edge, "edge")
	if connectIP { // edge 退出后宿主（命名空间 A）必须还原
		if v, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); string(v) != string(fwdBefore) {
			t.Errorf("ip_forward not restored: %q, was %q", v, fwdBefore)
		}
		if out, _ := exec.Command("sh", "-c", "nft list ruleset 2>/dev/null; iptables-save 2>/dev/null").CombinedOutput(); strings.Contains(string(out), "aero_edge") {
			t.Errorf("edge rules left after exit:\n%s", out)
		}
	}
	_ = inet.Process.Kill()
	_ = inet.Wait()
}

func startEdge(t *testing.T, dir, cfgFile string, httpc *http.Client) *exec.Cmd {
	t.Helper()
	logf, _ := os.OpenFile(filepath.Join(dir, "edge.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	cmd := exec.Command(filepath.Join(dir, "edge"), "-config", cfgFile)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if r, err := httpc.Get("https://" + nodeDomain + "/"); err == nil {
			r.Body.Close()
			if r.StatusCode == http.StatusOK {
				return cmd
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	t.Fatalf("edge not ready\n%s", readFile(dir, "edge.log"))
	return nil
}

func stopProc(t *testing.T, cmd *exec.Cmd, name string) {
	t.Helper()
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("%s did not stop on SIGTERM", name)
	}
}

// startRole 在新的网络命名空间中以给定角色重新执行本测试二进制。
func startRole(t *testing.T, role string, env []string) *exec.Cmd {
	t.Helper()
	dir := os.Getenv(dirEnv)
	logf, _ := os.Create(filepath.Join(dir, "role-"+role+".log"))
	cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run=^TestRole$", "-test.v", "-test.count=1")
	cmd.Env = append(append(os.Environ(), roleEnv+"="+role), env...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	// 子进程执行 unshare(CLONE_NEWNET) 之前移交网卡，网卡会留在当前命名空间：先等它进入新命名空间
	self, _ := os.Readlink("/proc/self/ns/net")
	if !waitTrue(t, 10*time.Second, func() bool {
		ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid))
		return err == nil && ns != self
	}) {
		t.Fatalf("%s role did not enter a new network namespace", role)
	}
	return cmd
}

// ---------------- 角色（各自的网络命名空间） ----------------

// TestRole 只在 startRole 启动的子进程中运行。
func TestRole(t *testing.T) {
	switch os.Getenv(roleEnv) {
	case "internet":
		roleInternet(t)
	case "client":
		roleClient(t)
	default:
		t.Skip("only runs as a helper role")
	}
}

// roleInternet：B 中的 HTTP（回显来源地址）与 UDP 回显服务。
func roleInternet(t *testing.T) {
	dir := os.Getenv(dirEnv)
	waitLink(t, "veth-ba")
	must(t, "ip", "link", "set", "lo", "up")
	must(t, "ip", "addr", "add", internetIP+"/24", "dev", "veth-ba")
	must(t, "ip", "link", "set", "veth-ba", "up")
	ln, err := net.Listen("tcp", internetIP+":80")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/bulk" { // 吞吐测试用：?mb=N 返回 N MiB 数据
				var mb int
				fmt.Sscan(r.URL.Query().Get("mb"), &mb)
				w.Header().Set("Content-Length", fmt.Sprint(mb<<20))
				chunk := make([]byte, 64<<10)
				for sent := 0; sent < mb<<20; sent += len(chunk) {
					if _, err := w.Write(chunk); err != nil {
						return
					}
				}
				return
			}
			fmt.Fprintf(w, "hello-e2e from %s", r.RemoteAddr)
		}))
	}()
	pc, err := net.ListenPacket("udp", internetIP+":7")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()
	_ = os.WriteFile(filepath.Join(dir, "internet-ready"), nil, 0o644)
	select {} // 由编排进程结束
}

// roleClient：C 中运行客户端（SOCKS 模式），经隧道验证 TCP、UDP 与重连。
func roleClient(t *testing.T) {
	dir := os.Getenv(dirEnv)
	waitLink(t, "veth-ca")
	must(t, "ip", "link", "set", "lo", "up")
	must(t, "ip", "addr", "add", clientIP+"/24", "dev", "veth-ca")
	must(t, "ip", "link", "set", "veth-ca", "up")
	applyNetem(t, "veth-ca")

	// 直连 B 必须不通（C 没有到 B 的路由）：后面能访问到 B 就证明经过了 edge
	if c, err := net.DialTimeout("tcp", internetIP+":80", 2*time.Second); err == nil {
		c.Close()
		t.Fatal("client namespace can reach the internet directly; the test would prove nothing")
	}

	logf, _ := os.Create(filepath.Join(dir, "client.log"))
	cl := exec.Command(filepath.Join(dir, "client"), "-headless", "-mode", "socks", "-listen", socksAddr, "-api", clientAPI, "-sub", os.Getenv("AERO_E2E_SUB"))
	cl.Env = append(os.Environ(), "SSL_CERT_FILE="+os.Getenv("AERO_E2E_CA"), "AERO_DATA_DIR="+filepath.Join(dir, "client-data"), "HOME="+dir)
	cl.Stdout, cl.Stderr = logf, logf
	if err := cl.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cl.Process.Signal(syscall.SIGTERM); _ = cl.Wait() }()
	fail := func(format string, a ...any) {
		t.Helper()
		t.Fatalf(format+"\n--- client.log ---\n%s", append(a, readFile(dir, "client.log"))...)
	}

	api := &http.Client{Timeout: 5 * time.Second}
	waitTrue(t, 20*time.Second, func() bool {
		r, err := api.Get("http://" + clientAPI + "/api/v1/status")
		if err == nil {
			r.Body.Close()
		}
		return err == nil
	})
	req, _ := http.NewRequest(http.MethodPost, "http://"+clientAPI+"/api/v1/connect", nil)
	req.Header.Set("Origin", "http://"+clientAPI)
	if r, err := api.Do(req); err != nil {
		fail("connect: %v", err)
	} else {
		r.Body.Close()
	}
	if !waitTrue(t, 30*time.Second, func() bool { return clientConnected(api) }) {
		fail("client did not connect")
	}

	if body, err := socksHTTPGet(internetIP + ":80"); err != nil || !strings.Contains(body, "hello-e2e from "+edgeOnB) {
		fail("TCP through tunnel: %q %v", body, err)
	}
	t.Log("TCP through tunnel: ok")
	if got, err := socksUDPEcho(internetIP+":7", "ping-e2e"); err != nil || got != "echo:ping-e2e" {
		fail("UDP through tunnel: %q %v", got, err)
	}
	t.Log("UDP through tunnel: ok")

	if mb := os.Getenv("AERO_E2E_BULK_MB"); mb != "" {
		var n int
		fmt.Sscan(mb, &n)
		for i := 0; i < 2; i++ { // 两次：第二次排除拥塞窗口冷启动
			bytes, d, err := socksBulk(internetIP+":80", n)
			t.Logf("BULK run %d: %d bytes in %v = %.2f Mbit/s (err=%v) netem=%q", i+1, bytes, d.Round(time.Millisecond), float64(bytes)*8/d.Seconds()/1e6, err, os.Getenv("AERO_E2E_NETEM"))
		}
	}

	// edge 重启后客户端应自动恢复
	_ = os.WriteFile(filepath.Join(dir, "client-phase1"), nil, 0o644)
	waitFile(t, filepath.Join(dir, "edge-restarted"), 60*time.Second)
	if !waitTrue(t, 60*time.Second, func() bool {
		body, err := socksHTTPGet(internetIP + ":80")
		return err == nil && strings.Contains(body, "hello-e2e")
	}) {
		fail("client did not recover after edge restart")
	}
	t.Log("reconnect after edge restart: ok")

	// CONNECT-IP 全局隧道：客户端 TUN 模式下，普通 TCP/UDP（不经 SOCKS）经 客户端 TUN → CONNECT-IP →
	// edge TUN → NAT 出口。需要 /dev/net/tun（CI 有，部分沙箱没有）。
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		envSkip(t, "/dev/net/tun not present: CONNECT-IP end-to-end not run")
		return
	}
	_ = cl.Process.Signal(syscall.SIGTERM)
	_ = cl.Wait()
	logf2, _ := os.Create(filepath.Join(dir, "client-tun.log"))
	cl = exec.Command(filepath.Join(dir, "client"), "-headless", "-mode", "tun", "-listen", socksAddr, "-api", clientAPI, "-sub", os.Getenv("AERO_E2E_SUB"))
	cl.Env = append(os.Environ(), "SSL_CERT_FILE="+os.Getenv("AERO_E2E_CA"), "AERO_DATA_DIR="+filepath.Join(dir, "client-data"), "HOME="+dir)
	cl.Stdout, cl.Stderr = logf2, logf2
	if err := cl.Start(); err != nil {
		t.Fatal(err)
	}
	failTun := func(format string, a ...any) {
		t.Helper()
		routes, _ := exec.Command("ip", "route").CombinedOutput()
		t.Fatalf(format+"\n--- routes ---\n%s\n--- client-tun.log ---\n%s", append(a, routes, readFile(dir, "client-tun.log"))...)
	}
	waitTrue(t, 20*time.Second, func() bool {
		r, err := api.Get("http://" + clientAPI + "/api/v1/status")
		if err == nil {
			r.Body.Close()
		}
		return err == nil
	})
	req, _ = http.NewRequest(http.MethodPost, "http://"+clientAPI+"/api/v1/connect", nil)
	req.Header.Set("Origin", "http://"+clientAPI)
	if r, err := api.Do(req); err != nil {
		failTun("connect (tun): %v", err)
	} else {
		r.Body.Close()
	}
	if !waitTrue(t, 30*time.Second, func() bool { return clientConnected(api) }) {
		failTun("client (tun) did not connect")
	}
	var body string
	if !waitTrue(t, 20*time.Second, func() bool {
		r, err := (&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}).Get("http://" + internetIP + "/")
		if err != nil {
			return false
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		return true
	}) || !strings.Contains(body, "hello-e2e from "+edgeOnB) {
		failTun("TCP through CONNECT-IP: %q", body)
	}
	t.Log("TCP through CONNECT-IP (TUN mode): ok")
	u, err := net.Dial("udp", internetIP+":7")
	if err != nil {
		failTun("udp dial: %v", err)
	}
	buf := make([]byte, 256)
	got := ""
	for i := 0; i < 5 && got == ""; i++ {
		_, _ = u.Write([]byte("ping-ip"))
		_ = u.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := u.Read(buf); err == nil {
			got = string(buf[:n])
		}
	}
	u.Close()
	if got != "echo:ping-ip" {
		failTun("UDP through CONNECT-IP: %q", got)
	}
	t.Log("UDP through CONNECT-IP (TUN mode): ok")

	// 订阅里节点声明了 capsule（C5 transports）：客户端应已向真实 edge 建立 ai 会话（ADR-0017）。
	if !waitTrue(t, 20*time.Second, func() bool { return clientAIChannel(api) == "up" }) {
		failTun("AI stable channel did not come up against the real edge: state=%q", clientAIChannel(api))
	}
	t.Log("AI stable channel (DATAGRAM capsule session) established against the real edge: ok")

	// 退出后客户端命名空间不得残留（TUN 网卡、路由）
	_ = cl.Process.Signal(syscall.SIGTERM)
	_ = cl.Wait()
	if out, _ := exec.Command("ip", "-o", "link").CombinedOutput(); strings.Contains(string(out), "aero") {
		failTun("TUN interface left after client exit:\n%s", out)
	}
	if out, _ := exec.Command("ip", "route").CombinedOutput(); strings.TrimSpace(string(out)) != "46.0.0.0/24 dev veth-ca proto kernel scope link src "+clientIP {
		failTun("routes left after client exit:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "resolvectl-called")); err == nil {
		t.Fatal("client called resolvectl (would touch the host's systemd-resolved)")
	}
	t.Log("no residue after client exit: ok")
}

// clientAIChannel 返回客户端状态里的 AI 稳定通道状态（读取失败返回空串）。
func clientAIChannel(api *http.Client) string {
	r, err := api.Get("http://" + clientAPI + "/api/v1/status")
	if err != nil {
		return ""
	}
	defer r.Body.Close()
	var st struct {
		AIChannel string `json:"ai_channel"`
	}
	if json.NewDecoder(r.Body).Decode(&st) != nil {
		return ""
	}
	return st.AIChannel
}

func clientConnected(api *http.Client) bool {
	r, err := api.Get("http://" + clientAPI + "/api/v1/status")
	if err != nil {
		return false
	}
	defer r.Body.Close()
	var st struct {
		Connected bool `json:"connected"`
	}
	return json.NewDecoder(r.Body).Decode(&st) == nil && st.Connected
}

// ---------------- 最小 SOCKS5 客户端 ----------------

func socksHandshake(c net.Conn, cmd byte, target string) (net.Addr, error) {
	host, portStr, _ := net.SplitHostPort(target)
	ip := net.ParseIP(host).To4()
	var port uint16
	fmt.Sscan(portStr, &port)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0 {
		return nil, fmt.Errorf("socks method: %v %v", resp, err)
	}
	msg := append([]byte{5, cmd, 0, 1}, ip...)
	msg = binary.BigEndian.AppendUint16(msg, port)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		return nil, err
	}
	if rep[1] != 0 || rep[3] != 1 {
		return nil, fmt.Errorf("socks reply %v", rep[:4])
	}
	return &net.UDPAddr{IP: net.IP(rep[4:8]), Port: int(binary.BigEndian.Uint16(rep[8:10]))}, nil
}

// applyNetem 在 dev 上按 AERO_E2E_NETEM（如 "delay 95ms 5ms loss 0.5%"）注入延迟与丢包，用来复现长距离、有丢包的链路。
// 未设置时什么也不做。两端各设一次，所以延迟与丢包在两个方向各生效一次。
func applyNetem(t *testing.T, dev string) {
	t.Helper()
	spec := strings.Fields(os.Getenv("AERO_E2E_NETEM"))
	if len(spec) == 0 {
		return
	}
	must(t, "tc", append([]string{"qdisc", "add", "dev", dev, "root", "netem"}, spec...)...)
}

// socksBulk 经 SOCKS 下载 /bulk?mb=N，返回收到的字节数与耗时（读到 150 秒截止）。
func socksBulk(target string, mb int) (int64, time.Duration, error) {
	c, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return 0, 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(150 * time.Second))
	if _, err := socksHandshake(c, 1, target); err != nil {
		return 0, 0, err
	}
	start := time.Now()
	fmt.Fprintf(c, "GET /bulk?mb=%d HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", mb, target)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0, time.Since(start), err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	return n, time.Since(start), err
}

func socksHTTPGet(target string) (string, error) {
	c, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := socksHandshake(c, 1, target); err != nil {
		return "", err
	}
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func socksUDPEcho(target, payload string) (string, error) {
	ctl, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer ctl.Close()
	_ = ctl.SetDeadline(time.Now().Add(15 * time.Second))
	relay, err := socksHandshake(ctl, 3, "0.0.0.0:0")
	if err != nil {
		return "", err
	}
	ra := relay.(*net.UDPAddr)
	if ra.IP.IsUnspecified() {
		ra.IP = net.IPv4(127, 0, 0, 1)
	}
	u, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return "", err
	}
	defer u.Close()
	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscan(portStr, &port)
	pkt := append([]byte{0, 0, 0, 1}, net.ParseIP(host).To4()...)
	pkt = binary.BigEndian.AppendUint16(pkt, port)
	pkt = append(pkt, payload...)
	buf := make([]byte, 2048)
	for i := 0; i < 5; i++ { // UDP：首包可能在会话建立期间丢失
		if _, err := u.Write(pkt); err != nil {
			return "", err
		}
		_ = u.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := u.Read(buf)
		if err == nil && n > 10 {
			return string(buf[10:n]), nil
		}
	}
	return "", fmt.Errorf("no UDP reply")
}

// ---------------- 工具 ----------------

func makeCerts(t *testing.T, dir string) (caPEM []byte, certFile, keyFile string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "AERO e2e CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: nodeDomain}, DNSNames: []string{nodeDomain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	_ = os.WriteFile(certFile, chain, 0o644)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), certFile, keyFile
}

func tlsClient(t *testing.T, caPEM []byte) *http.Client {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("bad CA")
	}
	// 编排进程与 edge 同在命名空间 A：连本机 443，SNI 与证书校验仍按节点域名
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, "127.0.0.1:443")
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: pool}}}
}

func must(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func waitLink(t *testing.T, name string) {
	t.Helper()
	if !waitTrue(t, 20*time.Second, func() bool { return exec.Command("ip", "link", "show", name).Run() == nil }) {
		out, _ := exec.Command("ip", "link").CombinedOutput()
		t.Fatalf("link %s did not appear (pid %d)\n%s", name, os.Getpid(), out)
	}
}

func waitFile(t *testing.T, path string, d time.Duration) {
	t.Helper()
	if !waitTrue(t, d, func() bool { _, err := os.Stat(path); return err == nil }) {
		t.Fatalf("timeout waiting for %s\n--- client role ---\n%s\n--- edge ---\n%s", filepath.Base(path),
			readFile(filepath.Dir(path), "role-client.log"), readFile(filepath.Dir(path), "edge.log"))
	}
}

func waitTrue(t *testing.T, d time.Duration, f func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func readFile(dir, name string) string {
	b, _ := os.ReadFile(filepath.Join(dir, name))
	if len(b) > 6000 {
		b = b[len(b)-6000:]
	}
	return string(b)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// envSkip 在环境不支持时跳过；CI 设置 AERO_REQUIRE_NETNS=1 时改为失败，避免命名空间测试被静默跳过。
func envSkip(t *testing.T, format string, a ...any) {
	t.Helper()
	if os.Getenv("AERO_REQUIRE_NETNS") == "1" {
		t.Fatalf("required environment missing (AERO_REQUIRE_NETNS=1): "+format, a...)
	}
	t.Skipf(format, a...)
}
