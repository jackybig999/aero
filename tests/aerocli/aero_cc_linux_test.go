//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

// 运维命令 `aero cc`（deploy/aero）的黑盒测试：用假的 aero-edge、systemctl、journalctl 替换系统命令，
// 真正执行脚本，检查它读写了什么配置、有没有先检查再重启。不碰宿主（所有路径都在临时目录里）。
package aerocli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const fakeEdge = `#!/usr/bin/env bash
# 假的 aero-edge：config get/set 读写 $FAKE_STATE（一行一个 键=值），check 记录调用并按 $FAKE_CHECK_RC 返回
state="$FAKE_STATE"
case "$1" in
  -version) echo "aero-edge 0.0.0-test" ;;
  check) echo "check" >> "$FAKE_LOG"; echo "OK   congestion_control"; exit "${FAKE_CHECK_RC:-0}" ;;
  config)
    shift; [[ "$1" == -config ]] && shift 2
    op="$1"; key="$2"; val="${3:-}"
    case "$op" in
      get) v=$(grep "^$key=" "$state" 2>/dev/null | cut -d= -f2-); if [[ "$key" == congestion_control && -z "$v" ]]; then v=cubic; fi; echo "$v" ;;
      set)
        if [[ "$key" == congestion_control && "$val" != lossy && "$val" != cubic ]]; then echo "congestion_control must be lossy or cubic" >&2; exit 1; fi
        grep -v "^$key=" "$state" 2>/dev/null > "$state.new" || true; echo "$key=$val" >> "$state.new"; mv "$state.new" "$state"
        echo "set $key $val" >> "$FAKE_LOG" ;;
    esac ;;
esac
`

const fakeSystemctl = `#!/usr/bin/env bash
echo "systemctl $*" >> "$FAKE_LOG"
exit 0
`

const fakeJournalctl = `#!/usr/bin/env bash
echo "2026/11/25 00:00:00 [EDGE] Server started on :443 (TLS + QUIC)"
`

type harness struct {
	t     *testing.T
	dir   string
	aero  string
	state string
	log   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"aero-edge": fakeEdge, "systemctl": fakeSystemctl, "journalctl": fakeJournalctl} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_, file, _, _ := runtime.Caller(0)
	src, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "deploy", "aero"))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, aero: filepath.Join(dir, "aero"), state: filepath.Join(dir, "state"), log: filepath.Join(dir, "log")}
	script := string(src)
	// 指向假命令与临时配置；跳过 root 检查（不碰宿主）
	script = replaceLine(t, script, "EDGE=", "EDGE="+filepath.Join(bin, "aero-edge"))
	script = replaceLine(t, script, "CONFIG=", "CONFIG="+filepath.Join(dir, "edge.json"))
	script = replaceLine(t, script, "need_root()", "need_root() { :; }")
	if err := os.WriteFile(h.aero, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{h.state, h.log} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func replaceLine(t *testing.T, script, prefix, repl string) string {
	t.Helper()
	lines := strings.Split(script, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			lines[i] = repl
			return strings.Join(lines, "\n")
		}
	}
	t.Fatalf("deploy/aero 里找不到以 %q 开头的行", prefix)
	return ""
}

func (h *harness) run(env []string, args ...string) (string, int) {
	h.t.Helper()
	cmd := exec.Command("bash", append([]string{h.aero}, args...)...)
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(h.dir, "bin")+":"+os.Getenv("PATH"), "FAKE_STATE="+h.state, "FAKE_LOG="+h.log)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if err != nil {
		h.t.Fatalf("run: %v", err)
	}
	return string(out), rc
}

func (h *harness) calls() []string {
	b, _ := os.ReadFile(h.log)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestAeroCCStatusShowsDefault(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{"cc"}, {"cc", "status"}} {
		out, rc := h.run(nil, args...)
		if rc != 0 || !strings.Contains(out, "拥塞控制: cubic") || !strings.Contains(out, "aero cc lossy|cubic") {
			t.Errorf("%v: rc=%d out=%q", args, rc, out)
		}
	}
	if got := strings.Join(h.calls(), "|"); strings.Contains(got, "restart") || strings.Contains(got, "set ") {
		t.Errorf("查看状态不应修改配置或重启: %q", got)
	}
}

func TestAeroCCSetChecksThenRestarts(t *testing.T) {
	h := newHarness(t)
	out, rc := h.run(nil, "cc", "lossy")
	if rc != 0 || !strings.Contains(out, "拥塞控制已设为: lossy") || !strings.Contains(out, "AERO_CONGESTION_CONTROL") {
		t.Fatalf("rc=%d out=%q", rc, out)
	}
	calls := strings.Join(h.calls(), "|")
	iSet, iCheck, iRestart := strings.Index(calls, "set congestion_control lossy"), strings.Index(calls, "check"), strings.Index(calls, "systemctl restart aero-edge")
	if iSet < 0 || iCheck < 0 || iRestart < 0 || !(iSet < iCheck && iCheck < iRestart) {
		t.Errorf("应按 写配置 → 检查 → 重启 的顺序执行: %q", calls)
	}
	if out, _ := h.run(nil, "cc"); !strings.Contains(out, "拥塞控制: lossy") {
		t.Errorf("设置后状态应为 lossy: %q", out)
	}
	if out, rc := h.run(nil, "cc", "cubic"); rc != 0 || !strings.Contains(out, "拥塞控制已设为: cubic") {
		t.Errorf("回退 cubic: rc=%d out=%q", rc, out)
	}
	if out, _ := h.run(nil, "cc"); !strings.Contains(out, "拥塞控制: cubic") {
		t.Errorf("回退后状态应为 cubic: %q", out)
	}
}

// 检查没通过时不重启服务（沿用 aero 的约定：检查通过才重启）。
func TestAeroCCDoesNotRestartWhenCheckFails(t *testing.T) {
	h := newHarness(t)
	out, rc := h.run([]string{"FAKE_CHECK_RC=1"}, "cc", "lossy")
	if rc == 0 {
		t.Errorf("检查失败应返回非零: out=%q", out)
	}
	if got := strings.Join(h.calls(), "|"); strings.Contains(got, "systemctl restart") {
		t.Errorf("检查未通过不应重启: %q", got)
	}
	if !strings.Contains(out, "服务未重启") {
		t.Errorf("应提示服务未重启: %q", out)
	}
}

func TestAeroCCRejectsInvalidValue(t *testing.T) {
	h := newHarness(t)
	for _, bad := range []string{"bbr", "LOSSY", "on", "true"} {
		out, rc := h.run(nil, "cc", bad)
		if rc == 0 || !strings.Contains(out, "用法: aero cc") {
			t.Errorf("%q: rc=%d out=%q，应拒绝并给出用法", bad, rc, out)
		}
	}
	if got := strings.Join(h.calls(), "|"); strings.Contains(got, "set ") || strings.Contains(got, "restart") {
		t.Errorf("非法取值不应改配置或重启: %q", got)
	}
}

func TestAeroHelpListsCC(t *testing.T) {
	h := newHarness(t)
	out, rc := h.run(nil, "help")
	if rc != 0 || !strings.Contains(out, "cc [lossy|cubic]") {
		t.Errorf("帮助里应列出 cc: rc=%d out=%q", rc, out)
	}
}
