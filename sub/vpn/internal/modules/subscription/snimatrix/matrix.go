package snimatrix

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed default_matrix.json
var defaultMatrixJSON []byte

// RouteMap 区域 -> SNI 列表
type RouteMap map[string][]string

// ProviderConfig 运营商规则配置
type ProviderConfig struct {
	Name       string   `json:"name"`
	DefaultSNI string   `json:"default_sni"`
	Routes     RouteMap `json:"routes"`
}

// MatrixConfig 全局 SNI 矩阵配置
type MatrixConfig struct {
	Version   string                    `json:"version"`
	Providers map[string]ProviderConfig `json:"providers"`
}

// Manager 管理 SNI 矩阵计算与持久化加载
type Manager struct {
	mu     sync.RWMutex
	path   string
	config MatrixConfig
}

// New 创建并初始化矩阵管理器
func New(path string) *Manager {
	m := &Manager{
		path: path,
	}
	// 1. 加载嵌入式默认基线
	_ = json.Unmarshal(defaultMatrixJSON, &m.config)

	// 2. 若外部文件存在，优先加载外部文件
	if path != "" {
		_ = m.LoadFile(path)
	}
	return m
}

// LoadFile 从磁盘读取或刷新矩阵配置
func (m *Manager) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg MatrixConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.path = path
	m.config = cfg
	return nil
}

// SaveFile 保存当前矩阵至磁盘
func (m *Manager) SaveFile(path string) error {
	m.mu.RLock()
	data, err := json.MarshalIndent(m.config, "", "  ")
	m.mu.RUnlock()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Match 根据运营商与 VPS 区域返回最优 SNI
func (m *Manager) Match(isp, region string) string {
	candidates := m.ListCandidates(isp, region)
	if len(candidates) > 0 && candidates[0] != "" {
		return candidates[0]
	}
	return "edge.microsoft.com"
}

// ListCandidates 获取该匹配条件下的所有候选 SNI
func (m *Manager) ListCandidates(isp, region string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normISP := normalizeISP(isp)
	normRegion := normalizeRegion(region)

	prov, ok := m.config.Providers[normISP]
	if !ok {
		prov, ok = m.config.Providers["default"]
	}
	if !ok {
		return []string{"edge.microsoft.com", "gateway.icloud.com"}
	}

	// 1. 精确匹配区域
	if routes, ok := prov.Routes[normRegion]; ok && len(routes) > 0 {
		return append([]string(nil), routes...)
	}

	// 2. 回退到该运营商的 DEFAULT 区域
	if defRoutes, ok := prov.Routes["DEFAULT"]; ok && len(defRoutes) > 0 {
		return append([]string(nil), defRoutes...)
	}

	// 3. 回退到 default_sni
	if prov.DefaultSNI != "" {
		return []string{prov.DefaultSNI}
	}

	return []string{"edge.microsoft.com"}
}

func normalizeISP(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "telecom") || strings.Contains(s, "电信"):
		return "china_telecom"
	case strings.Contains(s, "unicom") || strings.Contains(s, "联通"):
		return "china_unicom"
	case strings.Contains(s, "mobile") || strings.Contains(s, "移动"):
		return "china_mobile"
	case strings.Contains(s, "broadcast") || strings.Contains(s, "广电"):
		return "china_broadcast"
	default:
		return "default"
	}
}

func normalizeRegion(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "JP") || strings.Contains(s, "JAPAN") || strings.Contains(s, "东京") || strings.Contains(s, "日本"):
		return "JP"
	case strings.Contains(s, "HK") || strings.Contains(s, "HONG") || strings.Contains(s, "香港"):
		return "HK"
	case strings.Contains(s, "US") || strings.Contains(s, "AMERICA") || strings.Contains(s, "美国"):
		return "US"
	case strings.Contains(s, "DE") || strings.Contains(s, "GERMAN") || strings.Contains(s, "德国"):
		return "DE"
	case strings.Contains(s, "SG") || strings.Contains(s, "SINGAPORE") || strings.Contains(s, "新加坡"):
		return "SG"
	default:
		return "DEFAULT"
	}
}
