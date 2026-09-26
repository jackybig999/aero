// AERO 配置加载器：支持 YAML/JSON + flag 覆盖
package config

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load 从文件路径加载配置，自动识别 YAML / JSON 格式
func Load(path string) (*AeroConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("config path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &AeroConfig{}

	// 自动识别格式：JSON 以 { 开头，YAML 以字母开头
	if len(data) > 0 && data[0] == '{' {
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse JSON config: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse YAML config: %w", err)
		}
	}

	// 填充默认值 + 校验
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// LoadOrNil 加载配置，失败返回 nil（用于可选配置文件）
func LoadOrNil(path string) *AeroConfig {
	cfg, err := Load(path)
	if err != nil {
		return nil
	}
	return cfg
}
