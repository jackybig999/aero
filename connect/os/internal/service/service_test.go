package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aisys/connect/os/internal/domain/proxy"
	"aisys/connect/os/internal/infra/db"
)

type mockSysDetector struct {
	mockCfg *proxy.ProxyConfig
}

func (m *mockSysDetector) Detect() (*proxy.ProxyConfig, error) {
	return m.mockCfg, nil
}

func TestServiceAndAPI(t *testing.T) {
	tempDir := t.TempDir()
	testDBPath := filepath.Join(tempDir, "test_service.db")
	defer os.Remove(testDBPath)

	database, err := db.InitDB(testDBPath)
	if err != nil {
		t.Fatalf("InitDB 失败: %v", err)
	}
	defer db.CloseDB()

	mockDetector := &mockSysDetector{
		mockCfg: &proxy.ProxyConfig{
			Enabled:  true,
			Protocol: "socks5",
			Host:     "127.0.0.1",
			Port:     7890,
		},
	}

	service := InitAppService(database, mockDetector, filepath.Join(tempDir, "data"), 18889)

	// 1. 验证直接创建环境
	createdProfile, err := service.CreateProfile("跨境店铺测试", "chrome", "JP", "")
	if err != nil {
		t.Fatalf("创建环境失败: %v", err)
	}
	if createdProfile.Name != "跨境店铺测试" {
		t.Errorf("创建环境名称不匹配: %+v", createdProfile)
	}

	// 2. 验证环境列表
	listResp, err := service.ListProfiles()
	if err != nil || len(listResp) == 0 {
		t.Fatalf("环境列表应不为空: %v", err)
	}

	// 5. 验证 Step 8 代理健康轮询协程启动与停止
	service.StartProxyHealthPoller(100 * time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	service.StopHealthPoller()

	// 5. 验证环境编辑与更新 (UpdateProfileAdvanced)
	updated, err := service.UpdateProfileAdvanced(&CreateProfileRequest{
		ID:         createdProfile.ID,
		Name:       "跨境店铺测试_已编辑",
		KernelType: "firefox",
		Timezone:   "Asia/Tokyo",
		Languages:  "ja-JP,ja",
		Resolution: "2560x1440",
		CPUCores:   16,
		MemoryGB:   32,
		StartupURL: "https://example.com/login",
	})
	if err != nil {
		t.Fatalf("编辑环境失败: %v", err)
	}
	if updated.Name != "跨境店铺测试_已编辑" || updated.KernelType != "firefox" {
		t.Fatalf("编辑环境字段不匹配: %+v", updated)
	}

	// 6. 验证环境克隆 (CloneProfile)
	cloned, err := service.CloneProfile(updated.ID)
	if err != nil {
		t.Fatalf("克隆环境失败: %v", err)
	}
	if cloned.ID == updated.ID || !strings.Contains(cloned.Name, "副本") {
		t.Fatalf("克隆环境属性异常: %+v", cloned)
	}

	// 7. 验证批量停止与批量删除
	batchStopRes := service.BatchStopProfiles([]int64{updated.ID, cloned.ID})
	if batchStopRes["stopped_count"].(int) != 2 {
		t.Errorf("批量停止数量不匹配: %+v", batchStopRes)
	}
	batchDelRes := service.BatchDeleteProfiles([]int64{cloned.ID})
	if batchDelRes["deleted_count"].(int) != 1 {
		t.Errorf("批量删除数量不匹配: %+v", batchDelRes)
	}

	// 验证独立语言设置与持久化
	langErr := service.UpdateProfileLanguage(updated.ID, "zh-CN,zh")
	if langErr != nil {
		t.Fatalf("更新语言失败: %v", langErr)
	}
	pList, _ := service.ListProfiles()
	var foundUpdated *db.Profile
	for _, p := range pList {
		if p.ID == updated.ID {
			foundUpdated = p
			break
		}
	}
	if foundUpdated == nil || !strings.Contains(foundUpdated.FingerprintConfig, "zh-CN") {
		t.Fatalf("环境语言持久化校验失败: %v", foundUpdated)
	}

	// 8. 验证 Safari 专属环境创建与指纹特征固化
	safariProf, err := service.CreateProfileAdvanced(&CreateProfileRequest{
		Name:       "macOS_Safari_电商运营环境",
		KernelType: "safari",
		Country:    "US",
		Timezone:   "America/Los_Angeles",
		Languages:  "en-US,en",
	})
	if err != nil {
		t.Fatalf("创建 Safari 环境失败: %v", err)
	}
	if safariProf.KernelType != "safari" {
		t.Errorf("Safari 环境内核类型应为 safari, 实际为: %s", safariProf.KernelType)
	}
	if !strings.Contains(safariProf.FingerprintConfig, "MacIntel") || !strings.Contains(safariProf.FingerprintConfig, "Safari") {
		t.Errorf("Safari 环境指纹未正确注入 MacIntel/Safari 特征: %s", safariProf.FingerprintConfig)
	}
	_ = service.DeleteProfile(safariProf.ID)

	// 单项彻底删除
	if err := service.DeleteProfile(updated.ID); err != nil {
		t.Fatalf("删除环境失败: %v", err)
	}
	remaining, _ := service.ListProfiles()
	if len(remaining) != 0 {
		t.Fatalf("环境删除后数量应为0，实际为: %d", len(remaining))
	}
}
