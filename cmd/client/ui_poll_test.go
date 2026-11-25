// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// 界面的连接轮询曾经一次结果没回来就永远转圈（IPC 调用没有超时，28 秒的期限检查在 await 之后）。
// 这里用 node 执行 ui/app.js 里 <testable:begin>…<testable:end> 之间的真实代码（与发布的是同一份），
// 验证：挂住的调用在期限内被放弃、报错不会终止轮询、取消被响应、决定被正确返回。没有 node 时跳过。
func TestUIPollHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available")
	}
	src, err := os.ReadFile(filepath.Join("ui", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i, j := strings.Index(s, "// <testable:begin>"), strings.Index(s, "// <testable:end>")
	if i < 0 || j < i {
		t.Fatal("app.js 里找不到 <testable:begin>/<testable:end> 区块")
	}
	script := s[i:j] + `
const assert = require('assert')
const never = () => new Promise(() => {})
;(async () => {
  // 1) 每次调用都挂住：总期限内必须返回 timedOut（旧实现永远不返回）
  let t0 = Date.now()
  let r = await pollUntil({ intervalMs: 5, deadlineMs: 300, callTimeoutMs: 40, fetchStatus: never, decide: () => undefined })
  assert.ok(r.timedOut, 'hanging call must time out: ' + JSON.stringify(r))
  assert.ok(Date.now() - t0 < 2000, 'must return near the deadline, took ' + (Date.now() - t0))

  // 2) 前两次挂住/报错，第三次拿到结果：不会因为一次失败终止
  let n = 0
  r = await pollUntil({
    intervalMs: 5, deadlineMs: 2000, callTimeoutMs: 40,
    fetchStatus: () => { n++; if (n === 1) return never(); if (n === 2) return Promise.reject(new Error('boom')); return Promise.resolve({ connected: true }) },
    decide: (st) => (st.connected ? 'connected' : undefined),
  })
  assert.strictEqual(r.decision, 'connected')
  assert.strictEqual(n, 3)

  // 3) 状态一直是 starting：持续轮询到期限，返回 timedOut 并带上最后一次状态
  r = await pollUntil({ intervalMs: 5, deadlineMs: 150, callTimeoutMs: 40, fetchStatus: () => Promise.resolve({ starting: true, last_error: 'x' }), decide: (st) => (st.starting ? undefined : 'done') })
  assert.ok(r.timedOut && r.last && r.last.last_error === 'x')

  // 4) 取消：isCancelled 为真时立刻返回（即使调用正挂住）
  let cancelled = false
  setTimeout(() => { cancelled = true }, 60)
  t0 = Date.now()
  r = await pollUntil({ intervalMs: 5, deadlineMs: 5000, callTimeoutMs: 1000, fetchStatus: never, isCancelled: () => cancelled, decide: () => undefined })
  assert.ok(r.cancelled, JSON.stringify(r))
  assert.ok(Date.now() - t0 < 1500, 'cancel must be honored promptly, took ' + (Date.now() - t0))

  // 5) withTimeout：按时返回、超时拒绝、不泄漏定时器
  assert.strictEqual(await withTimeout(Promise.resolve(7), 50, 'x'), 7)
  await assert.rejects(() => withTimeout(never(), 30, 'x'), /timed out/)
  await assert.rejects(() => withTimeout(Promise.reject(new Error('inner')), 50, 'x'), /inner/)

  console.log('ui poll helpers ok')
})().catch((e) => { console.error(e); process.exit(1) })
`
	tmp := filepath.Join(t.TempDir(), "poll_test.js")
	if err := os.WriteFile(tmp, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, tmp).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ui poll helpers ok") {
		t.Fatalf("node 测试失败: %v\n%s", err, out)
	}
}

// 页面从本机 HTTP 服务加载时 api() 必须走 fetch：UI 线程上的同步 IPC 是“一直转圈”的结构性原因。
func TestUIAPIPrefersFetchOnHTTPOrigin(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("ui", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "function useIPC()") || !strings.Contains(s, "!/^https?:$/.test(location.protocol)") {
		t.Error("api() 应只在非 http 来源（内嵌页面退路）时使用 IPC")
	}
	if !strings.Contains(s, "withTimeout(window.goClientAPI(") {
		t.Error("IPC 调用必须带硬超时")
	}
	if strings.Contains(s, "while (busy)") && strings.Contains(s, "async function pollConnectStatus") {
		// 旧的串行 await 轮询不应回来
		if i := strings.Index(s, "async function pollConnectStatus"); strings.Contains(s[i:i+400], "while (busy)") {
			t.Error("pollConnectStatus 不应回到串行 while(busy) await 的写法")
		}
	}
}

// 界面等接口的时间必须大于服务端对该接口的时限并留不少于 20% 余量（L0 §8.1）。
// 从 main.go 里读出每个处理器的 context.WithTimeout(r.Context(), N*time.Second)，用 node 执行界面里同一份 apiTimeoutMs 比较。
// 此前界面对 geo 同步（服务端 150 秒）只给 5 秒，测速（服务端 5 秒）也只给 5 秒，fetch 先中止，调用白白失败。
func TestUITimeoutsExceedServerLimits(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available")
	}
	appSrc, err := os.ReadFile(filepath.Join("ui", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	mainSrc, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	handlerRe := regexp.MustCompile(`mux\.HandleFunc\("([^"]+)"`)
	timeoutRe := regexp.MustCompile(`context\.WithTimeout\(r\.Context\(\), (\d+)\*time\.Second\)`)
	m := string(mainSrc)
	idx := handlerRe.FindAllStringSubmatchIndex(m, -1)
	server := map[string]int{"/api/v1/import": 30} // 导入订阅：引擎里拉取订阅的上限（LoadAndApplySubscription 的 30 秒）
	for i, loc := range idx {
		end := len(m)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		path := m[loc[2]:loc[3]]
		if tm := timeoutRe.FindStringSubmatch(m[loc[0]:end]); tm != nil {
			var n int
			fmt.Sscan(tm[1], &n)
			server[path] = n
		}
	}
	if server["/api/v1/geodata/sync"] < 100 || server["/api/v1/nodes/probe"] < 3 {
		t.Fatalf("没有从 main.go 解析出预期的服务端超时: %v", server)
	}

	s := string(appSrc)
	i, j := strings.Index(s, "// <testable:begin>"), strings.Index(s, "// <testable:end>")
	if i < 0 || j < i {
		t.Fatal("app.js 里找不到 <testable:begin>/<testable:end> 区块")
	}
	var cases strings.Builder
	for p, n := range server {
		fmt.Fprintf(&cases, "check(%q, %d)\n", p, n)
	}
	script := s[i:j] + `
const assert = require('assert')
function check(path, serverSec) {
  const ui = apiTimeoutMs(path)
  assert.ok(ui >= serverSec * 1000 * 1.2, path + ': UI timeout ' + ui + 'ms must be >= 1.2 x server ' + serverSec + 's')
}
` + cases.String() + `console.log('ui timeouts ok')
`
	tmp := filepath.Join(t.TempDir(), "timeouts_test.js")
	if err := os.WriteFile(tmp, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, tmp).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ui timeouts ok") {
		t.Fatalf("界面超时与服务端时限不匹配: %v\n%s", err, out)
	}
}

// 连接轮询属于启动它的那一代：取消后马上重连，旧轮询不能在到点后把新的连接取消掉。
func TestUIPollIsBoundToItsConnectGeneration(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("ui", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{"let connectGen = 0", "const gen = ++connectGen", "await pollConnectStatus(gen)", "gen !== connectGen || !busy"} {
		if !strings.Contains(s, want) {
			t.Errorf("app.js 缺少 %q", want)
		}
	}
}
