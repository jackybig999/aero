// 服务端配置文件加载器
package config

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerFileConfig 服务端配置文件结构体
type ServerFileConfig struct {
	Aero struct {
		Version string `yaml:"version" json:"version"`
		Server  struct {
			Listen struct {
				Ports []int `yaml:"ports" json:"ports"`
			} `yaml:"listen" json:"listen"`
			TLS struct {
				Mode     string `yaml:"mode" json:"mode"`
				CertFile string `yaml:"cert_file" json:"cert_file"`
				KeyFile  string `yaml:"key_file" json:"key_file"`
				AutoCert struct {
					Domain   string `yaml:"domain" json:"domain"`
					Email    string `yaml:"email" json:"email"`
					CacheDir string `yaml:"cache_dir" json:"cache_dir"`
				} `yaml:"autocert" json:"autocert"`
			} `yaml:"tls" json:"tls"`
			ECH struct {
				PublicName string `yaml:"public_name" json:"public_name"`
			} `yaml:"ech" json:"ech"`
			Auth struct {
				Tokens []struct {
					Token string `yaml:"token" json:"token"`
					User  string `yaml:"user" json:"user"`
				} `yaml:"tokens" json:"tokens"`
			} `yaml:"auth" json:"auth"`
			Log struct {
				File   string `yaml:"file" json:"file"`
				Format string `yaml:"format" json:"format"`
			} `yaml:"log" json:"log"`
		} `yaml:"server" json:"server"`
	} `yaml:"aero" json:"aero"`
}

// LoadServerFile 加载服务端配置文件
func LoadServerFile(path string) (*ServerFileConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("config path empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	cfg := &ServerFileConfig{}
	if len(data) > 0 && data[0] == '{' {
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse JSON: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse YAML: %w", err)
		}
	}
	return cfg, nil
}
