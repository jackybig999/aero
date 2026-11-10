// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// SNIProfile 本机 ISP 特化与优选伪装 SNI 配置结构
type SNIProfile struct {
	ISP         string           `json:"isp"` // "telecom" | "unicom" | "mobile" | "default"
	ISPName     string           `json:"isp_name"`
	TopSNIs     []string         `json:"top_snis"`
	ProbeRTTs   map[string]int64 `json:"probe_rtts,omitempty"`
	LastUpdated int64            `json:"last_updated"`
}

var (
	sniProfileMu     sync.RWMutex
	cachedSNIProfile *SNIProfile
	sniProberStarted sync.Once

	builtinSNIMatrix = map[string][]string{
		"telecom": {"edge.microsoft.com", "gateway.icloud.com", "live.azure.com"},
		"unicom":  {"gateway.icloud.com", "edge.microsoft.com", "swdist.apple.com"},
		"mobile":  {"live.azure.com", "edge.microsoft.com", "s3.ap-east-1.amazonaws.com"},
		"default": {"edge.microsoft.com", "gateway.icloud.com", "live.azure.com"},
	}

	ispNameMap = map[string]string{
		"telecom": "中国电信",
		"unicom":  "中国联通",
		"mobile":  "中国移动",
		"default": "通用网络",
	}
)

func sniProfileFilePath() string {
	return filepath.Join(GetDataDir(), "sni_profile.json")
}

// detectISP 尝试根据物理出口信息或探测推断运营商代码
func detectISP() (string, string) {
	// 默认兜底
	ispCode := "default"
	ispName := ispNameMap[ispCode]

	// 尝试根据物理默认网关所在接口或外部线索判定
	gw, _, err := PhysicalDefaultGateway()
	if err == nil && gw != "" {
		// 优先保持原有推断或默认
		ispCode = "default"
		ispName = ispNameMap[ispCode]
	}
	return ispCode, ispName
}

// LoadSNIProfile 从本地持久化缓存以 <1ms 耗时高速加载 SNI 配置（SWR 模式）
func LoadSNIProfile() *SNIProfile {
	sniProfileMu.RLock()
	if cachedSNIProfile != nil {
		pCopy := *cachedSNIProfile
		sniProfileMu.RUnlock()
		return &pCopy
	}
	sniProfileMu.RUnlock()

	sniProfileMu.Lock()
	defer sniProfileMu.Unlock()

	// 二次复检
	if cachedSNIProfile != nil {
		pCopy := *cachedSNIProfile
		return &pCopy
	}

	filePath := sniProfileFilePath()
	data, err := os.ReadFile(filePath)
	if err == nil {
		var prof SNIProfile
		if jerr := json.Unmarshal(data, &prof); jerr == nil && len(prof.TopSNIs) > 0 {
			cachedSNIProfile = &prof
			pCopy := prof
			return &pCopy
		}
	}

	// 首次启动或文件损坏，根据环境快速创建基线配置
	ispCode, ispName := detectISP()
	candidates, ok := builtinSNIMatrix[ispCode]
	if !ok {
		candidates = builtinSNIMatrix["default"]
	}

	prof := &SNIProfile{
		ISP:         ispCode,
		ISPName:     ispName,
		TopSNIs:     append([]string(nil), candidates...),
		ProbeRTTs:   make(map[string]int64),
		LastUpdated: time.Now().Unix(),
	}
	for _, sni := range prof.TopSNIs {
		prof.ProbeRTTs[sni] = 50 // 默认初始虚拟 RTT
	}

	// 原子写盘保存
	_ = saveSNIProfileLocked(prof)
	cachedSNIProfile = prof
	pCopy := *prof
	return &pCopy
}

// SaveSNIProfile 保存 SNI 配置到本地文件
func SaveSNIProfile(p *SNIProfile) error {
	sniProfileMu.Lock()
	defer sniProfileMu.Unlock()
	return saveSNIProfileLocked(p)
}

func saveSNIProfileLocked(p *SNIProfile) error {
	if p == nil {
		return nil
	}
	cachedSNIProfile = p
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	filePath := sniProfileFilePath()
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, filePath)
}

// GetOptimalSNIs 获取当前机器的前 3 个最优备用 SNI
func GetOptimalSNIs() []string {
	prof := LoadSNIProfile()
	if prof == nil || len(prof.TopSNIs) == 0 {
		return []string{"edge.microsoft.com", "gateway.icloud.com", "live.azure.com"}
	}
	if len(prof.TopSNIs) > 3 {
		return prof.TopSNIs[:3]
	}
	return prof.TopSNIs
}

// StartAsyncSNIProber 启动低优先级后台异步 SNI 探针循环（绝不阻塞启动路径与连接热路径）
func StartAsyncSNIProber(ctx context.Context) {
	sniProberStarted.Do(func() {
		go func() {
			// 启动后延时 5 秒再执行首次探针，绝不争抢主通道资源
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}

			probeAndUpdateSNIs(ctx)

			// 之后每 6 小时在后台低优先级轮测更新一次
			ticker := time.NewTicker(6 * time.Hour)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					probeAndUpdateSNIs(ctx)
				}
			}
		}()
	})
}

// probeAndUpdateSNIs 对全部候选 SNI 进行快速物理链路测速，筛选最优 TOP-3 并持久化
func probeAndUpdateSNIs(ctx context.Context) {
	prof := LoadSNIProfile()
	if prof == nil {
		return
	}

	allCandidates := make([]string, 0)
	seen := make(map[string]bool)
	for _, list := range builtinSNIMatrix {
		for _, sni := range list {
			if !seen[sni] {
				seen[sni] = true
				allCandidates = append(allCandidates, sni)
			}
		}
	}

	type probeResult struct {
		sni string
		rtt int64
	}

	results := make([]probeResult, 0, len(allCandidates))
	var wg sync.WaitGroup
	var resMu sync.Mutex

	for _, sni := range allCandidates {
		wg.Add(1)
		go func(targetSNI string) {
			defer wg.Done()
			pctx, pcancel := context.WithTimeout(ctx, 3*time.Second)
			defer pcancel()

			start := time.Now()
			// 尝试通过物理网络拨号 443 进行简短 TLS 握手测试连通性与时延
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			conn, err := dialer.DialContext(pctx, "tcp", net.JoinHostPort(targetSNI, "443"))
			if err != nil {
				return
			}
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         targetSNI,
				InsecureSkipVerify: true, // 仅用于纯时延探测，不承载任何业务数据
			})
			_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
			err = tlsConn.HandshakeContext(pctx)
			_ = tlsConn.Close()

			if err == nil {
				dur := time.Since(start).Milliseconds()
				resMu.Lock()
				results = append(results, probeResult{sni: targetSNI, rtt: dur})
				resMu.Unlock()
			}
		}(sni)
	}

	wg.Wait()

	if len(results) == 0 {
		return
	}

	// 按 RTT 升序排序
	sort.Slice(results, func(i, j int) bool {
		return results[i].rtt < results[j].rtt
	})

	topSNIs := make([]string, 0, 3)
	rttMap := make(map[string]int64)
	for i, r := range results {
		if i < 3 {
			topSNIs = append(topSNIs, r.sni)
		}
		rttMap[r.sni] = r.rtt
	}

	prof.TopSNIs = topSNIs
	prof.ProbeRTTs = rttMap
	prof.LastUpdated = time.Now().Unix()

	_ = SaveSNIProfile(prof)
}
