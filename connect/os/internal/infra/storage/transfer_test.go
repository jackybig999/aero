package storage

import (
	"os"
	"path/filepath"
	"testing"

	"aisys/connect/os/internal/domain/fingerprint"
	"aisys/connect/os/internal/domain/proxy"
	"aisys/connect/os/internal/infra/db"
)

func TestTransferAndStorage(t *testing.T) {
	tempDir := t.TempDir()
	exportPath := filepath.Join(tempDir, "profile_export.json")

	prof := &db.Profile{
		Name:          "跨境店铺_01",
		Notes:         "生产运营环境",
		KernelType:    "chrome",
		KernelVersion: "133.0",
	}

	proxyCfg := &proxy.ProxyConfig{
		Enabled:  true,
		Protocol: "socks5",
		Host:     "127.0.0.1",
		Port:     7890,
	}

	fp := &fingerprint.FingerprintConfig{
		Timezone:            "America/New_York",
		HardwareConcurrency: 8,
	}

	err := ExportProfileConfig(prof, proxyCfg, fp, exportPath)
	if err != nil {
		t.Fatalf("导出配置失败: %v", err)
	}

	imported, err := ImportProfileConfig(exportPath)
	if err != nil {
		t.Fatalf("导入配置失败: %v", err)
	}
	if imported.Name != prof.Name || imported.FingerprintConfig.Timezone != fp.Timezone {
		t.Errorf("导入数据不匹配: %+v", imported)
	}

	// 测试 UserData 备份与还原
	userDataDir := filepath.Join(tempDir, "user_data")
	_ = os.MkdirAll(filepath.Join(userDataDir, "Default"), 0755)
	_ = os.WriteFile(filepath.Join(userDataDir, "Default", "Preferences"), []byte("{\"test\": true}"), 0644)
	_ = os.WriteFile(filepath.Join(userDataDir, "SingletonLock"), []byte("lock"), 0644)

	backupZip := filepath.Join(tempDir, "backup.zip")
	err = BackupUserData(userDataDir, backupZip)
	if err != nil {
		t.Fatalf("备份 UserData 失败: %v", err)
	}

	restoreDir := filepath.Join(tempDir, "restored_data")
	err = RestoreUserData(backupZip, restoreDir)
	if err != nil {
		t.Fatalf("还原 UserData 失败: %v", err)
	}

	if _, err := os.Stat(filepath.Join(restoreDir, "Default", "Preferences")); os.IsNotExist(err) {
		t.Errorf("还原文件未找到")
	}
	if _, err := os.Stat(filepath.Join(restoreDir, "SingletonLock")); !os.IsNotExist(err) {
		t.Errorf("锁文件不应被备份还原")
	}
}
