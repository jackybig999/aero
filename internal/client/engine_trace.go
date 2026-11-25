// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// startTrace 记录一次启动各阶段的耗时，只写日志，不影响启动行为。
// 目的：连接慢或超时（界面 28 秒后自行取消）时，日志能直接说明时间花在哪个阶段、取消时停在哪里。
// 所有方法对 nil 接收者安全（测试直接调用内部函数时没有 trace）。不记录地址、令牌等敏感信息。
type startTrace struct {
	mu      sync.Mutex
	t0      time.Time
	stage   string
	stageAt time.Time
	notes   []string
}

func newStartTrace(mode string) *startTrace {
	now := time.Now()
	log.Printf("[START] begin (mode=%s)", mode)
	return &startTrace{t0: now, stageAt: now}
}

func rounded(d time.Duration) time.Duration { return d.Round(time.Millisecond) }

// enter 结束上一个阶段（写一行耗时）并进入 name。
func (t *startTrace) enter(name string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeStageLocked(time.Now(), "ok")
	t.stage = name
}

// note 给当前阶段附加一条说明，随该阶段的结束行一起输出（如实际使用的端口、ai 会话结果）。
func (t *startTrace) note(format string, a ...any) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.notes = append(t.notes, fmt.Sprintf(format, a...))
	t.mu.Unlock()
}

func (t *startTrace) closeStageLocked(now time.Time, result string) {
	if t.stage == "" {
		return
	}
	extra := ""
	if len(t.notes) > 0 {
		extra = " [" + strings.Join(t.notes, "; ") + "]"
	}
	log.Printf("[START] %s %s in %v (total %v)%s", t.stage, result, rounded(now.Sub(t.stageAt)), rounded(now.Sub(t.t0)), extra)
	t.stage, t.notes, t.stageAt = "", nil, now
}

// finish 在启动成功时调用：写出最后一个阶段与总耗时。
func (t *startTrace) finish() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.closeStageLocked(now, "ok")
	log.Printf("[START] done, total %v", rounded(now.Sub(t.t0)))
}

// fail 在启动失败或被取消时调用：写出停在哪个阶段、该阶段已耗时、总耗时与原因。
// cancelled 为真表示由停止/取消（含界面 28 秒超时后的取消）触发，不是启动自身出错。
func (t *startTrace) fail(err error, cancelled bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	kind := "FAILED"
	if cancelled {
		kind = "CANCELLED"
	}
	stage := t.stage
	if stage == "" {
		stage = "(between stages)"
	}
	extra := ""
	if len(t.notes) > 0 {
		extra = " [" + strings.Join(t.notes, "; ") + "]"
	}
	log.Printf("[START] %s at stage %q after %v (total %v)%s: %v", kind, stage, rounded(now.Sub(t.stageAt)), rounded(now.Sub(t.t0)), extra, err)
	t.stage, t.notes = "", nil
}
