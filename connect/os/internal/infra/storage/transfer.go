package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"aisys/connect/os/internal/domain/fingerprint"
	"aisys/connect/os/internal/domain/proxy"
	"aisys/connect/os/internal/infra/db"
)

// ProfileExportDTO 环境导出数据结构
type ProfileExportDTO struct {
	Version           string                         `json:"version"`
	ExportedAt        time.Time                      `json:"exported_at"`
	Name              string                         `json:"name"`
	Notes             string                         `json:"notes"`
	KernelType        string                         `json:"kernel_type"`
	KernelVersion     string                         `json:"kernel_version"`
	ProxyProtocol     string                         `json:"proxy_protocol,omitempty"`
	ProxyHost         string                         `json:"proxy_host,omitempty"`
	ProxyPort         int                            `json:"proxy_port,omitempty"`
	FingerprintConfig *fingerprint.FingerprintConfig `json:"fingerprint_config"`
}

// ExportProfileConfig 将环境指纹配置导出为 JSON 文件
func ExportProfileConfig(profile *db.Profile, proxyCfg *proxy.ProxyConfig, fp *fingerprint.FingerprintConfig, exportPath string) error {
	dto := ProfileExportDTO{
		Version:           "2.0",
		ExportedAt:        time.Now(),
		Name:              profile.Name,
		Notes:             profile.Notes,
		KernelType:        profile.KernelType,
		KernelVersion:     profile.KernelVersion,
		FingerprintConfig: fp,
	}

	if proxyCfg != nil && proxyCfg.Enabled {
		dto.ProxyProtocol = proxyCfg.Protocol
		dto.ProxyHost = proxyCfg.Host
		dto.ProxyPort = proxyCfg.Port
	}

	data, err := json.MarshalIndent(dto, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	dir := filepath.Dir(exportPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(exportPath, data, 0644)
}

// ImportProfileConfig 从导出的 JSON 文件导入指纹环境配置
func ImportProfileConfig(importPath string) (*ProfileExportDTO, error) {
	data, err := os.ReadFile(importPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var dto ProfileExportDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	return &dto, nil
}
