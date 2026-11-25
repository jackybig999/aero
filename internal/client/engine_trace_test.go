// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestStartTraceNilSafe(t *testing.T) {
	var tr *startTrace
	tr.enter("x")
	tr.note("a=%d", 1)
	tr.finish()
	tr.fail(errors.New("boom"), false)
}

func TestStartTraceLogsStagesAndNotes(t *testing.T) {
	buf := captureLog(t)
	tr := newStartTrace("tun")
	tr.enter("quic-dial")
	time.Sleep(15 * time.Millisecond)
	tr.note("port=%d", 2083)
	tr.enter("connect-ip")
	tr.finish()
	out := buf.String()
	for _, want := range []string{"[START] begin (mode=tun)", "[START] quic-dial ok in ", "[port=2083]", "[START] connect-ip ok in ", "[START] done, total "} {
		if !strings.Contains(out, want) {
			t.Errorf("日志缺少 %q:\n%s", want, out)
		}
	}
}

func TestStartTraceFailAndCancelAreDistinguishable(t *testing.T) {
	buf := captureLog(t)
	tr := newStartTrace("tun")
	tr.enter("quic-dial")
	tr.fail(errors.New("dial timeout"), false)
	tr2 := newStartTrace("tun")
	tr2.enter("connect-ip")
	tr2.fail(context.Canceled, true)
	out := buf.String()
	if !strings.Contains(out, `FAILED at stage "quic-dial"`) || !strings.Contains(out, "dial timeout") {
		t.Errorf("失败应记录阶段与原因:\n%s", out)
	}
	if !strings.Contains(out, `CANCELLED at stage "connect-ip"`) {
		t.Errorf("取消应单独标出:\n%s", out)
	}
}

// 真实启动流程会输出各阶段耗时、ai 会话结果与总耗时（连接慢时靠它定位）。
func TestEngineStartLogsStageTimings(t *testing.T) {
	buf := captureLog(t)
	h := startAIHarness(t, bothTransports, true)
	h.waitState(t, AIChannelUp)
	out := buf.String()
	for _, want := range []string{"[START] begin", "[START] quic-dial ok", "[START] connect-ip ok", "[START] ai-session ok", "ai=up", "[START] tun-open ok", "[START] data-plane ok", "[START] done, total"} {
		if !strings.Contains(out, want) {
			t.Errorf("启动日志缺少 %q", want)
		}
	}
	if strings.Contains(out, "FAILED") || strings.Contains(out, "CANCELLED") {
		t.Errorf("成功的启动不应出现失败/取消记录")
	}
}

// ai 会话建立失败时，启动日志带上原因码（不影响隧道），运行期的拨号失败也有日志。
func TestEngineStartLogsAIFailureReason(t *testing.T) {
	buf := captureLog(t)
	h := startAIHarnessErr(t, bothTransports, true, &EdgeRejectError{Status: 403, Code: "class_not_allowed"})
	h.waitState(t, AIChannelUnavailable)
	out := buf.String()
	if !strings.Contains(out, "ai=failed(EDGE_CLASS_NOT_ALLOWED)") {
		t.Errorf("启动日志应带 ai 失败原因码:\n%s", out)
	}
	if !strings.Contains(out, "[AI] session dial failed (reason=EDGE_CLASS_NOT_ALLOWED, permanent=true)") {
		t.Errorf("应有 ai 拨号失败日志:\n%s", out)
	}
	if !strings.Contains(out, "[START] done, total") {
		t.Errorf("ai 失败不应让启动失败")
	}
}

// 拨号失败：日志写明停在哪个阶段与原因（FAILED）。
func TestEngineStartFailureLogsStage(t *testing.T) {
	buf := captureLog(t)
	hosts := useFakeTunHost(t, nil)
	stubCloseTestDial(t, func(context.Context, *SessionManager) (IPPacketConn, string, error) {
		return nil, "", errors.New("connect-ip request timed out")
	})
	eng := newCloseTestEngine(t, hosts)
	if err := eng.StartWith(eng.RequestStart()); err == nil {
		t.Fatal("StartWith succeeded")
	}
	out := buf.String()
	if !strings.Contains(out, `[START] FAILED at stage "connect-ip"`) || !strings.Contains(out, "connect-ip request timed out") {
		t.Errorf("失败启动应记录阶段与原因:\n%s", out)
	}
}

// 拨号期间被停止/取消（界面等满 28 秒后调用取消时就是这种情况）：日志写明 CANCELLED 与停在哪个阶段。
func TestEngineStartCancelLogsStage(t *testing.T) {
	buf := captureLog(t)
	hosts := useFakeTunHost(t, nil)
	inDial := make(chan struct{})
	stubCloseTestDial(t, func(ctx context.Context, m *SessionManager) (IPPacketConn, string, error) {
		close(inDial)
		<-ctx.Done()
		return nil, "", ctx.Err()
	})
	eng := newCloseTestEngine(t, hosts)
	ticket := eng.RequestStart()
	done := make(chan error, 1)
	go func() { done <- eng.StartWith(ticket) }()
	<-inDial
	_ = eng.Stop()
	if err := <-done; !errors.Is(err, ErrStartAborted) {
		t.Fatalf("StartWith = %v, want ErrStartAborted", err)
	}
	out := buf.String()
	if !strings.Contains(out, `[START] CANCELLED at stage "connect-ip"`) {
		t.Errorf("被取消的启动应记录 CANCELLED 与所在阶段:\n%s", out)
	}
}
