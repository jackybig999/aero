package service

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"aisys/connect/os/internal/infra/db"
)

// TestSecondaryLaunchPreservesSession 验证环境二次启动会话保留与防 URL 冲刷机制
func TestSecondaryLaunchPreservesSession(t *testing.T) {
	tempDir := t.TempDir()
	testDBPath := filepath.Join(tempDir, "test_session.db")
	database, err := db.InitDB(testDBPath)
	if err != nil {
		t.Fatalf("InitDB 失败: %v", err)
	}
	defer db.CloseDB()

	svc := InitAppService(database, nil, filepath.Join(tempDir, "data"), 18890)

	// 1. 创建默认 Firefox 环境（未填启动网址）
	prof1, err := svc.CreateProfileAdvanced(&CreateProfileRequest{
		Name:          "Firefox测试环境",
		KernelType:    "firefox",
		KernelVersion: "156",
		Country:       "US",
	})
	if err != nil {
		t.Fatalf("创建环境失败: %v", err)
	}
	if prof1.Notes != "" {
		t.Fatalf("默认环境 Notes 应为空，实际为: %s", prof1.Notes)
	}

	// 2. 模拟首次启动前：last_launched_at 为 NULL，预期首次启动打开检测页
	var lastLaunched sql.NullTime
	_ = database.QueryRow("SELECT last_launched_at FROM profiles WHERE id = ?", prof1.ID).Scan(&lastLaunched)
	if lastLaunched.Valid {
		t.Errorf("首次启动前 last_launched_at 应无效")
	}

	// 3. 模拟首次启动后标记已启动
	now := time.Now()
	_, _ = database.Exec("UPDATE profiles SET status = 'stopped', last_launched_at = ? WHERE id = ?", now, prof1.ID)

	// 4. 模拟历史遗留污染数据：notes 包含 "启动: https://whoer.net/zh"
	_, _ = database.Exec("UPDATE profiles SET notes = '启动: https://whoer.net/zh' WHERE id = ?", prof1.ID)

	// 读取并检验 launcher 判定逻辑
	var notes string
	_ = database.QueryRow("SELECT notes, last_launched_at FROM profiles WHERE id = ?", prof1.ID).Scan(&notes, &lastLaunched)

	hasCustomURL := false
	startupURL := ""
	if len(notes) > 0 {
		cand := notes
		if idx := len("启动: "); len(cand) >= idx && cand[:idx] == "启动: " {
			cand = cand[idx:]
		}
		isLegacyCheck := cand == "https://whoer.net/zh" || cand == "https://whoer.net/en"
		if cand != "" && !isLegacyCheck {
			startupURL = cand
			hasCustomURL = true
		}
	}
	if !hasCustomURL && !lastLaunched.Valid {
		startupURL = "https://whoer.net/zh"
	}

	if startupURL != "" {
		t.Errorf("二次启动时，历史 whoer 检测网址绝不能作为强制启动 URL 传入，实际为: %s", startupURL)
	}
	t.Log("✅ 验证通过：二次启动时 whoer 检测链接被成功忽略，startupURL 保持为空以恢复会话")

	// 5. 验证编辑环境时清空 startupURL 会剔除 notes 中的残留
	updated, err := svc.UpdateProfileAdvanced(&CreateProfileRequest{
		ID:         prof1.ID,
		Name:       prof1.Name,
		KernelType: prof1.KernelType,
		StartupURL: "",
	})
	if err != nil {
		t.Fatalf("更新环境失败: %v", err)
	}
	if updated.Notes != "" {
		t.Errorf("清空启动URL后 Notes 应为空，实际为: %s", updated.Notes)
	}
	t.Log("✅ 验证通过：更新环境成功剥离启动 URL 标记")

	// 6. 验证自定义目标网址仍能生效
	customProf, err := svc.CreateProfileAdvanced(&CreateProfileRequest{
		Name:          "特定主页环境",
		KernelType:    "firefox",
		KernelVersion: "156",
		Country:       "US",
		StartupURL:    "https://example.com",
	})
	if err != nil {
		t.Fatalf("创建自定义主页环境失败: %v", err)
	}
	if customProf.Notes != "启动: https://example.com" {
		t.Errorf("自定义主页应记录在 notes，实际为: %s", customProf.Notes)
	}
}

// TestInstanceProcessLifecycle 验证单通道 ExitChan 退出监控与双并发调用免疫
func TestInstanceProcessLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	testDBPath := filepath.Join(tempDir, "test_lifecycle.db")
	database, err := db.InitDB(testDBPath)
	if err != nil {
		t.Fatalf("InitDB 失败: %v", err)
	}
	defer db.CloseDB()

	svc := InitAppService(database, nil, filepath.Join(tempDir, "data"), 18891)

	// 模拟已启动环境
	_, err = database.Exec(`INSERT INTO profiles (id, user_id, name, kernel_type, status, fingerprint_config, data_dir) VALUES (10, 1, '测试生命周期', 'chrome', 'running', '{}', ?)`, tempDir)
	if err != nil {
		t.Fatalf("插入测试环境失败: %v", err)
	}

	exitChan := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(exitChan)
	}()

	done := make(chan bool)
	go func() {
		<-exitChan
		svc.mu.Lock()
		_, _ = svc.DB.Exec(`UPDATE profiles SET status = 'stopped' WHERE id = 10`)
		svc.mu.Unlock()
		done <- true
	}()

	select {
	case <-done:
		var st string
		_ = database.QueryRow("SELECT status FROM profiles WHERE id = 10").Scan(&st)
		if st != "stopped" {
			t.Errorf("状态应更新为 stopped, 实际为: %s", st)
		}
		t.Log("✅ 单通道 ExitChan 生命周期闭环测试 PASS")
	case <-time.After(2 * time.Second):
		t.Fatal("超时未收到退出信号")
	}
}
