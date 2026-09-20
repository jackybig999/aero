// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const defaultSNIMatrixJSON = `{
  "version": "1.0.0",
  "providers": {
    "china_telecom": {
      "name": "中国电信",
      "default_sni": "edge.microsoft.com",
      "routes": {
        "JP": ["edge.microsoft.com", "gateway.icloud.com", "swdist.apple.com"],
        "HK": ["live.azure.com", "teams.microsoft.com", "edge.microsoft.com"],
        "US": ["edge.microsoft.com", "live.azure.com"],
        "DE": ["edge.microsoft.com", "gateway.icloud.com"],
        "DEFAULT": ["edge.microsoft.com", "gateway.icloud.com"]
      }
    },
    "china_unicom": {
      "name": "中国联通",
      "default_sni": "gateway.icloud.com",
      "routes": {
        "JP": ["gateway.icloud.com", "swdist.apple.com", "edge.microsoft.com"],
        "HK": ["gateway.icloud.com", "edge.microsoft.com"],
        "DE": ["gateway.icloud.com", "edge.microsoft.com"],
        "US": ["gateway.icloud.com", "edge.microsoft.com"],
        "DEFAULT": ["gateway.icloud.com", "edge.microsoft.com"]
      }
    },
    "china_mobile": {
      "name": "中国移动",
      "default_sni": "live.azure.com",
      "routes": {
        "HK": ["live.azure.com", "edge.microsoft.com", "s3.ap-east-1.amazonaws.com"],
        "SG": ["live.azure.com", "edge.microsoft.com"],
        "JP": ["live.azure.com", "swdist.apple.com"],
        "DEFAULT": ["live.azure.com", "edge.microsoft.com"]
      }
    },
    "default": {
      "name": "通用网络",
      "default_sni": "edge.microsoft.com",
      "routes": {
        "DEFAULT": ["edge.microsoft.com", "gateway.icloud.com", "live.azure.com"]
      }
    }
  }
}`

type SNIRouteMap map[string][]string

type SNIProviderConfig struct {
	Name       string      `json:"name"`
	DefaultSNI string      `json:"default_sni"`
	Routes     SNIRouteMap `json:"routes"`
}

type SNIMatrixConfig struct {
	Version   string                       `json:"version"`
	Providers map[string]SNIProviderConfig `json:"providers"`
}

type SNIMatrixManager struct {
	mu     sync.RWMutex
	path   string
	config SNIMatrixConfig
}

func NewSNIMatrixManager(path string) *SNIMatrixManager {
	m := &SNIMatrixManager{path: path}
	_ = json.Unmarshal([]byte(defaultSNIMatrixJSON), &m.config)
	if path != "" {
		_ = m.LoadFile(path)
	}
	return m
}

func (m *SNIMatrixManager) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg SNIMatrixConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.path = path
	m.config = cfg
	return nil
}

func (m *SNIMatrixManager) SaveFile(path string) error {
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

func (m *SNIMatrixManager) Match(isp, region string) string {
	candidates := m.ListCandidates(isp, region)
	if len(candidates) > 0 && candidates[0] != "" {
		return candidates[0]
	}
	return "edge.microsoft.com"
}

func (m *SNIMatrixManager) ListCandidates(isp, region string) []string {
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

	if routes, ok := prov.Routes[normRegion]; ok && len(routes) > 0 {
		return append([]string(nil), routes...)
	}
	if defRoutes, ok := prov.Routes["DEFAULT"]; ok && len(defRoutes) > 0 {
		return append([]string(nil), defRoutes...)
	}
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
