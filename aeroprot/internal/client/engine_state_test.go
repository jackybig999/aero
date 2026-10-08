package client

import (
	"errors"
	"testing"
)

// TestEngineStateMachine_TicketsAndInvariants 严格验证阶段 F 状态机与票据流转
func TestEngineStateMachine_TicketsAndInvariants(t *testing.T) {
	eng := NewEngine()

	// 1. 停滞态下 PrepareModeSwitch：直接更新 mode，禁止 epoch++ 与 ticket 签发
	needRestart, ticket := eng.PrepareModeSwitch("sysproxy")
	if needRestart || ticket != 0 {
		t.Fatalf("stopped engine should not need restart, got needRestart=%v, ticket=%d", needRestart, ticket)
	}
	if eng.GetMode() != "sysproxy" {
		t.Fatalf("expected mode sysproxy, got %s", eng.GetMode())
	}
	if eng.startEpoch != 0 {
		t.Fatalf("expected startEpoch 0, got %d", eng.startEpoch)
	}

	// 2. RequestStart 签发有效票据
	t1 := eng.RequestStart()
	if t1 != 1 {
		t.Fatalf("expected ticket 1, got %d", t1)
	}
	st := eng.GetState()
	if !st.Starting {
		t.Fatalf("expected Starting=true when startPending is active")
	}
	if st.Connected {
		t.Fatalf("expected Connected=false before running")
	}

	// 3. BeginStop 作废票据并置 Stopping
	eng.state.Store(stateStarting)
	wasActive := eng.BeginStop()
	if !wasActive {
		t.Fatalf("expected wasActive=true when stopping starting engine")
	}
	if !eng.IsStopping() {
		t.Fatalf("expected IsStopping=true")
	}
	stStopping := eng.GetState()
	if !stStopping.Stopping {
		t.Fatalf("expected AppState.Stopping=true")
	}
	if stStopping.Connected {
		t.Fatalf("expected Connected=false while stopping")
	}

	// 4. 旧票据 t1 启动必须返回 ErrStartAborted，且禁止修改为 stateRunning
	err := eng.StartWith(t1)
	if !errors.Is(err, ErrStartAborted) {
		t.Fatalf("expected ErrStartAborted for invalidated ticket, got %v", err)
	}
	if eng.tunnelClient == nil {
		t.Fatalf("abortStartLocked must NOT nil tunnelClient pointer")
	}

	// 5. 模拟正常停止完成
	_ = eng.Stop()
	if eng.IsStopping() {
		t.Fatalf("expected IsStopping=false after Stop()")
	}

	// 6. 新签发票据 t2 并在运行中触发 PrepareModeSwitch
	eng.state.Store(stateRunning)
	eng.running.Store(true)
	needRestart2, t3 := eng.PrepareModeSwitch("tun")
	if !needRestart2 || t3 == 0 {
		t.Fatalf("expected needRestart=true and non-zero ticket for running engine")
	}
	if !eng.IsStopping() {
		t.Fatalf("expected stateStopping after PrepareModeSwitch")
	}

	// 7. 在模式重启排队时调用 BeginStop
	eng.BeginStop()
	// 尝试以 t3 启动：必须因票据已作废而被拒绝
	err2 := eng.startLocked(t3)
	if !errors.Is(err2, ErrStartAborted) {
		t.Fatalf("expected ErrStartAborted when stopped during mode restart, got %v", err2)
	}

	// 8. 验证 SetLastError 与 ClearStartPending
	t4 := eng.RequestStart()
	eng.SetLastError("test connection failure")
	stErr := eng.GetState()
	if stErr.LastError != "test connection failure" || stErr.ErrorCode != "CONNECT_ERROR" {
		t.Fatalf("SetLastError failed, got %q / %q", stErr.LastError, stErr.ErrorCode)
	}
	eng.ClearStartPending(t4)
	if eng.startPending.Load() {
		t.Fatalf("ClearStartPending failed to clear flag")
	}
}
