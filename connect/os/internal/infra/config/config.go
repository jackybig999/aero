package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"aisys/connect/os/internal/domain/proxy"
	"aisys/connect/os/internal/infra/db"
)

// VPNInfo VPN/TUN 状态模型
type VPNInfo struct {
	Detected  bool   `json:"detected"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	IP        string `json:"ip"`
	IsActive  bool   `json:"is_active"`
	CheckedAt string `json:"checked_at"`
}

// UnifiedConfig 跨平台唯一配置文件模型 (mac与win通用复用)
type UnifiedConfig struct {
	AppVersion  string            `json:"app_version"`
	LastUpdated string            `json:"last_updated"`
	OS          string            `json:"os"` // "windows" 或 "darwin"
	VPN         VPNInfo           `json:"vpn"`
	SystemProxy proxy.ProxyConfig `json:"system_proxy"`
	Settings    AppSettings       `json:"settings"`
	Profiles    []*db.Profile     `json:"profiles"`
	Proxies     []*db.ProxyItem   `json:"proxies"`
}

type AppSettings struct {
	DefaultKernel string `json:"default_kernel"` // "chrome" 或 "firefox"
	AutoCheckVPN  bool   `json:"auto_check_vpn"`
	WindowWidth   int    `json:"window_width"`
	WindowHeight  int    `json:"window_height"`
}

var (
	globalConfig   *UnifiedConfig
	configMutex    sync.RWMutex
	configFilePath string
)

// DefaultConfigPath 返回单配置文件默认路径
func DefaultConfigPath() string {
	return "config.json"
}

// LoadOrCreateUnifiedConfig 加载单一全局配置文件，若不存在则创建默认配置
func LoadOrCreateUnifiedConfig(path string) (*UnifiedConfig, error) {
	configMutex.Lock()
	defer configMutex.Unlock()

	if path == "" {
		path = DefaultConfigPath()
	}
	configFilePath = path

	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := &UnifiedConfig{
			AppVersion:  "2.0",
			LastUpdated: time.Now().Format(time.RFC3339),
			OS:          runtime.GOOS,
			VPN: VPNInfo{
				Detected: false,
			},
			SystemProxy: proxy.ProxyConfig{
				Enabled: false,
			},
			Settings: AppSettings{
				DefaultKernel: "chrome",
				AutoCheckVPN:  true,
				WindowWidth:   1120,
				WindowHeight:  760,
			},
			Profiles: make([]*db.Profile, 0),
			Proxies:  make([]*db.ProxyItem, 0),
		}

		data, err := json.MarshalIndent(cfg, "", "  ")
		if err == nil {
			_ = os.WriteFile(path, data, 0644)
		}
		globalConfig = cfg
		return globalConfig, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var cfg UnifiedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件 JSON 失败: %w", err)
	}

	globalConfig = &cfg
	return globalConfig, nil
}

// GetUnifiedConfig 获取当前全局内存配置
func GetUnifiedConfig() *UnifiedConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return globalConfig
}

// SaveUnifiedConfig 保存全局配置回唯一配置文件
func SaveUnifiedConfig(cfg *UnifiedConfig) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	if cfg == nil {
		cfg = globalConfig
	}
	if cfg == nil {
		return fmt.Errorf("未初始化的配置")
	}

	cfg.LastUpdated = time.Now().Format(time.RFC3339)
	cfg.OS = runtime.GOOS

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	path := configFilePath
	if path == "" {
		path = DefaultConfigPath()
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(path, data, 0644)
}

// DetectSystemVPN 跨平台智能检测系统是否已开启 VPN / TUN 虚拟网卡 (Win/Mac通用)
func DetectSystemVPN() (*VPNInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	vpnKeywords := []string{
		"singbox", "sing-tun", "sing_box",
		"wintun", "tap", "tun",
		"wireguard", "wg",
		"tailscale", "zerotier",
		"clash", "clash_tun",
		"openvpn",
		"utun", "ppp", "ipsec",
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		nameLower := strings.ToLower(iface.Name)
		for _, kw := range vpnKeywords {
			if strings.Contains(nameLower, kw) {
				addrs, _ := iface.Addrs()
				var ipStr string
				for _, a := range addrs {
					if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
						if ipNet.IP.To4() != nil {
							ipStr = ipNet.IP.String()
							break
						}
					}
				}

				typeName := "TUN/VPN"
				if strings.Contains(nameLower, "sing") {
					typeName = "Sing-Box TUN"
				} else if strings.Contains(nameLower, "wireguard") || strings.Contains(nameLower, "wg") {
					typeName = "WireGuard"
				} else if strings.Contains(nameLower, "tailscale") {
					typeName = "Tailscale"
				} else if strings.Contains(nameLower, "utun") {
					typeName = "macOS utun"
				}

				return &VPNInfo{
					Detected:  true,
					Name:      iface.Name,
					Type:      typeName,
					IP:        ipStr,
					IsActive:  true,
					CheckedAt: time.Now().Format("15:04:05"),
				}, nil
			}
		}
	}

	return &VPNInfo{
		Detected:  false,
		CheckedAt: time.Now().Format("15:04:05"),
	}, nil
}

// BackgroundAsyncVPNCheck 异步后台执行 VPN 探测并自动写入单配置文件
func BackgroundAsyncVPNCheck(onDetected func(info *VPNInfo)) {
	go func() {
		time.Sleep(1 * time.Second)

		vpn, err := DetectSystemVPN()
		if err == nil && vpn.Detected {
			configMutex.Lock()
			if globalConfig != nil {
				globalConfig.VPN = *vpn
			}
			configMutex.Unlock()
			_ = SaveUnifiedConfig(nil)

			if onDetected != nil {
				onDetected(vpn)
			}
		}
	}()
}
