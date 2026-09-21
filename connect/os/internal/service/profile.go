package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"aisys/connect/os/internal/domain/fingerprint"
	"aisys/connect/os/internal/domain/proxy"
	"aisys/connect/os/internal/infra/db"
)

// CreateProfileRequest 高级指纹环境创建与编辑参数
type CreateProfileRequest struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Notes         string `json:"notes"`
	KernelType    string `json:"kernel_type"`
	KernelVersion string `json:"kernel_version"`
	Country       string `json:"country"`
	ProxyMode     string `json:"proxy_mode"` // vpn, sys, custom, direct
	ProxyRaw      string `json:"proxy_raw"`
	Timezone      string `json:"timezone"`
	Languages     string `json:"languages"` // 逗号分隔例如 "en-US,en"
	Platform      string `json:"platform"`  // "Win32", "MacIntel", "Linux x86_64"
	UserAgent     string `json:"user_agent"`
	Resolution    string `json:"resolution"` // "1920x1080"
	CPUCores      int    `json:"cpu_cores"`
	MemoryGB      int    `json:"memory_gb"`
	WebGLVendor   string `json:"webgl_vendor"`
	WebGLRenderer string `json:"webgl_renderer"`
	CanvasNoise   bool   `json:"canvas_noise"`
	AudioNoise    bool   `json:"audio_noise"`
	WebRTCBlock   bool   `json:"webrtc_block"`
	StartupURL    string `json:"startup_url"`
}

// CreateProfile 创建新环境并自动生成指纹 (兼容旧签名)
func (s *AppService) CreateProfile(name, kernelType, country, proxyRaw string) (*db.Profile, error) {
	return s.CreateProfileAdvanced(&CreateProfileRequest{
		Name:       name,
		KernelType: kernelType,
		Country:    country,
		ProxyRaw:   proxyRaw,
	})
}

// CreateProfileAdvanced 创建全维度可配置的指纹环境
func (s *AppService) CreateProfileAdvanced(req *CreateProfileRequest) (*db.Profile, error) {
	if req.Name == "" {
		return nil, errors.New("环境名称不能为空")
	}
	if req.KernelType == "" {
		req.KernelType = "chrome"
	}
	if req.Country == "" {
		req.Country = "US"
	}

	fp := fingerprint.GenerateFingerprintConfig("", req.Country, req.KernelType, req.KernelVersion)

	if req.Timezone != "" {
		fp.Timezone = req.Timezone
	}
	fp.Languages = ResolveProfileLanguages(req.Languages)
	if req.Platform != "" {
		fp.Platform = req.Platform
	}
	if req.UserAgent != "" {
		fp.UserAgent = req.UserAgent
	}
	if req.Resolution != "" {
		parts := strings.Split(req.Resolution, "x")
		if len(parts) == 2 {
			w, _ := strconv.Atoi(parts[0])
			h, _ := strconv.Atoi(parts[1])
			if w > 0 && h > 0 {
				fp.ScreenWidth = w
				fp.ScreenHeight = h
			}
		}
	}
	if req.CPUCores > 0 {
		fp.HardwareConcurrency = req.CPUCores
	}
	if req.MemoryGB > 0 {
		fp.DeviceMemory = req.MemoryGB
	}
	if req.WebGLVendor != "" {
		fp.WebGLVendor = req.WebGLVendor
	}
	if req.WebGLRenderer != "" {
		fp.WebGLRenderer = req.WebGLRenderer
	}
	if !req.CanvasNoise {
		fp.CanvasNoise = 0
	}
	if !req.AudioNoise {
		fp.AudioNoise = 0
	}

	fpBytes, _ := json.Marshal(fp)

	var proxyID int64 = 0
	if req.ProxyMode == "custom" && req.ProxyRaw != "" {
		proxyCfg, _ := proxy.ParseProxyString(req.ProxyRaw)
		if proxyCfg != nil {
			r, err := s.DB.Exec(`INSERT INTO proxies (user_id, raw_input, protocol, host, port, username, password, status) VALUES (1, ?, ?, ?, ?, ?, ?, 'ready')`,
				req.ProxyRaw, proxyCfg.Protocol, proxyCfg.Host, proxyCfg.Port, proxyCfg.Username, proxyCfg.Password,
			)
			if err == nil {
				proxyID, _ = r.LastInsertId()
			}
		}
	}

	notes := req.Notes
	if req.StartupURL != "" {
		if notes != "" {
			notes += " | 启动: " + req.StartupURL
		} else {
			notes = "启动: " + req.StartupURL
		}
	}

	res, err := s.DB.Exec(`INSERT INTO profiles (user_id, name, notes, kernel_type, kernel_version, proxy_id, fingerprint_config, data_dir, status) VALUES (1, ?, ?, ?, ?, ?, ?, ?, 'stopped')`,
		req.Name, notes, req.KernelType, req.KernelVersion, proxyID, string(fpBytes), s.DataDir,
	)
	if err != nil {
		return nil, err
	}

	id, _ := res.LastInsertId()
	return &db.Profile{
		ID:                id,
		UserID:            1,
		Name:              req.Name,
		Notes:             notes,
		KernelType:        req.KernelType,
		KernelVersion:     req.KernelVersion,
		ProxyID:           proxyID,
		FingerprintConfig: string(fpBytes),
		DataDir:           s.DataDir,
		Status:            "stopped",
		CreatedAt:         time.Now(),
	}, nil
}

// UpdateProfileAdvanced 编辑更新既有指纹环境
func (s *AppService) UpdateProfileAdvanced(req *CreateProfileRequest) (*db.Profile, error) {
	if req.ID <= 0 {
		return nil, errors.New("无效的环境ID")
	}
	if req.Name == "" {
		return nil, errors.New("环境名称不能为空")
	}

	var oldKernel, oldVer, oldFP, oldNotes string
	var oldProxyID int64
	err := s.DB.QueryRow(`SELECT kernel_type, kernel_version, notes, proxy_id, fingerprint_config FROM profiles WHERE id = ?`, req.ID).Scan(&oldKernel, &oldVer, &oldNotes, &oldProxyID, &oldFP)
	if err != nil {
		return nil, fmt.Errorf("未找到待编辑环境 %d: %w", req.ID, err)
	}

	var fp fingerprint.FingerprintConfig
	if err := json.Unmarshal([]byte(oldFP), &fp); err != nil {
		fp = *fingerprint.GenerateFingerprintConfig("", req.Country, req.KernelType, req.KernelVersion)
	}

	if req.Timezone != "" {
		fp.Timezone = req.Timezone
	}
	if req.Languages != "" {
		fp.Languages = ResolveProfileLanguages(req.Languages)
	}
	if req.Platform != "" {
		fp.Platform = req.Platform
	}
	if req.UserAgent != "" {
		fp.UserAgent = req.UserAgent
	}
	if req.Resolution != "" {
		parts := strings.Split(req.Resolution, "x")
		if len(parts) == 2 {
			w, _ := strconv.Atoi(parts[0])
			h, _ := strconv.Atoi(parts[1])
			if w > 0 && h > 0 {
				fp.ScreenWidth = w
				fp.ScreenHeight = h
			}
		}
	}
	if req.CPUCores > 0 {
		fp.HardwareConcurrency = req.CPUCores
	}
	if req.MemoryGB > 0 {
		fp.DeviceMemory = req.MemoryGB
	}
	if req.WebGLVendor != "" {
		fp.WebGLVendor = req.WebGLVendor
	}
	if req.WebGLRenderer != "" {
		fp.WebGLRenderer = req.WebGLRenderer
	}
	if !req.CanvasNoise {
		fp.CanvasNoise = 0
	} else if fp.CanvasNoise == 0 {
		fp.CanvasNoise = -0.0005
	}
	if !req.AudioNoise {
		fp.AudioNoise = 0
	} else if fp.AudioNoise == 0 {
		fp.AudioNoise = 0.0001
	}

	fpBytes, _ := json.Marshal(fp)

	proxyID := oldProxyID
	if req.ProxyMode == "custom" && req.ProxyRaw != "" {
		proxyCfg, _ := proxy.ParseProxyString(req.ProxyRaw)
		if proxyCfg != nil {
			r, err := s.DB.Exec(`INSERT INTO proxies (user_id, raw_input, protocol, host, port, username, password, status) VALUES (1, ?, ?, ?, ?, ?, ?, 'ready')`,
				req.ProxyRaw, proxyCfg.Protocol, proxyCfg.Host, proxyCfg.Port, proxyCfg.Username, proxyCfg.Password,
			)
			if err == nil {
				proxyID, _ = r.LastInsertId()
			}
		}
	} else if req.ProxyMode != "custom" {
		proxyID = 0
	}

	notes := req.Notes
	if req.StartupURL != "" {
		if strings.Contains(notes, "启动: ") {
			idx := strings.Index(notes, "启动: ")
			notes = strings.TrimSpace(notes[:idx])
		}
		if notes != "" {
			notes += " | 启动: " + req.StartupURL
		} else {
			notes = "启动: " + req.StartupURL
		}
	} else if strings.Contains(notes, "启动: ") {
		idx := strings.Index(notes, "启动: ")
		notes = strings.TrimRight(strings.TrimSpace(notes[:idx]), "|")
		notes = strings.TrimSpace(notes)
	}

	_, err = s.DB.Exec(`UPDATE profiles SET name = ?, notes = ?, kernel_type = ?, kernel_version = ?, proxy_id = ?, fingerprint_config = ? WHERE id = ?`,
		req.Name, notes, req.KernelType, req.KernelVersion, proxyID, string(fpBytes), req.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("更新环境失败: %w", err)
	}

	var updated db.Profile
	_ = s.DB.QueryRow(`SELECT id, user_id, name, notes, icon_color, kernel_type, kernel_version, proxy_id, fingerprint_config, data_dir, status, last_launched_at, created_at FROM profiles WHERE id = ?`, req.ID).Scan(
		&updated.ID, &updated.UserID, &updated.Name, &updated.Notes, &updated.IconColor, &updated.KernelType, &updated.KernelVersion, &updated.ProxyID, &updated.FingerprintConfig, &updated.DataDir, &updated.Status, &updated.LastLaunchedAt, &updated.CreatedAt,
	)
	return &updated, nil
}
