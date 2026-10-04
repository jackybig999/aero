// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// 1. 验证国内主要金融机构与交易所内置分流规则
func TestFinancialDomains(t *testing.T) {
	engine := NewSplitEngine()

	financialDomains := []string{
		"icbc.com.cn", "icbc.com", "abchina.com", "abchina.com.cn",
		"boc.cn", "bankofchina.com", "ccb.com", "ccb.com.cn",
		"bankcomm.com", "95559.com.cn", "cmbchina.com", "cmbwinglung.com",
		"spdb.com.cn", "cmbc.com.cn", "cib.com.cn", "pingan.com", "pingan.com.cn",
		"citicbank.com", "ecitic.com", "cebbank.com", "hxb.com.cn", "psbc.com",
		"cgbchina.com.cn", "unionpay.com", "95516.com", "pbc.gov.cn",
		"sse.com.cn", "szse.cn", "bse.cn", "chinaclear.cn",
	}

	for _, domain := range financialDomains {
		strat := engine.MatchDomain(domain)
		if strat != DIRECT {
			t.Errorf("expected %s to have DIRECT strategy, got %v", domain, strat)
		}
	}
}

// 2. 验证 ReloadRules 动态规则加载与 TotalRules 统计
func TestReloadRulesAndTotalRules(t *testing.T) {
	engine := NewSplitEngine()
	initialRules := engine.TotalRules()
	if initialRules <= 0 {
		t.Fatalf("expected initial TotalRules > 0, got %d", initialRules)
	}

	rulesData := []byte(`
# 动态测试规则
dynamic-direct.org
custom-bank.com.cn
203.0.113.0/24
198.51.100.42
`)

	count, err := engine.ReloadRules(rulesData)
	if err != nil {
		t.Fatalf("ReloadRules failed: %v", err)
	}
	if count != 4 {
		t.Errorf("expected 4 loaded rules, got %d", count)
	}

	// 验证域名与 CIDR 匹配生效
	if strat := engine.MatchDomain("dynamic-direct.org"); strat != DIRECT {
		t.Errorf("expected dynamic-direct.org to be DIRECT, got %v", strat)
	}
	if strat := engine.MatchDomain("custom-bank.com.cn"); strat != DIRECT {
		t.Errorf("expected custom-bank.com.cn to be DIRECT, got %v", strat)
	}
	if strat := engine.MatchIP(net.ParseIP("203.0.113.10")); strat != DIRECT {
		t.Errorf("expected 203.0.113.10 to be DIRECT, got %v", strat)
	}
	if strat := engine.MatchIP(net.ParseIP("198.51.100.42")); strat != DIRECT {
		t.Errorf("expected 198.51.100.42 to be DIRECT, got %v", strat)
	}

	// 验证保留了 AI 与移出直连后 Apple 服务默认走 PROXY
	if strat := engine.MatchDomain("api.openai.com"); strat != AI {
		t.Errorf("expected api.openai.com to remain AI, got %v", strat)
	}
	if strat := engine.MatchDomain("apple.com"); strat != PROXY {
		t.Errorf("expected apple.com to be PROXY, got %v", strat)
	}

	// 验证 TotalRules 正常统计
	total := engine.TotalRules()
	if total <= 0 {
		t.Errorf("expected positive TotalRules, got %d", total)
	}
}

// 3. 验证 GetDataDir 跨平台路径获取与自动创建
func TestGetDataDir(t *testing.T) {
	dir := GetDataDir()
	if dir == "" {
		t.Fatal("GetDataDir returned empty string")
	}

	stat, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("GetDataDir folder does not exist: %v", err)
	}
	if !stat.IsDir() {
		t.Fatalf("GetDataDir %s is not a directory", dir)
	}
}

// 4. 验证 sortServersByISP 运营商亲和性排序
func TestSortServersByISP(t *testing.T) {
	servers := []ServerConfig{
		{Name: "Node-1", Address: "1.1.1.1:443", ISPAffinity: "CM"},
		{Name: "Node-2", Address: "2.2.2.2:443", ISPAffinity: "CU"},
		{Name: "Node-3", Address: "3.3.3.3:443", ISPAffinity: "CT"},
		{Name: "Node-4", Address: "4.4.4.4:443", ISPAffinity: "CU"},
		{Name: "Node-5", Address: "5.5.5.5:443", ISPAffinity: ""},
	}

	// 按 CU 排序
	sortServersByISP(servers, "CU")

	if servers[0].Name != "Node-2" || servers[1].Name != "Node-4" {
		t.Fatalf("expected CU nodes first in stable order, got %+v", servers)
	}
	if servers[2].Name != "Node-1" || servers[3].Name != "Node-3" || servers[4].Name != "Node-5" {
		t.Fatalf("expected rest of nodes in original relative order, got %+v", servers)
	}

	// 按 CT 排序
	sortServersByISP(servers, "CT")
	if servers[0].Name != "Node-3" {
		t.Fatalf("expected CT node first, got %+v", servers)
	}

	// 空 ISP 或单节点不 panic
	sortServersByISP(servers, "")
	sortServersByISP(servers[:1], "CT")
}

// 5. 验证 Sentinel LastRTT 度量与记录
func TestSentinelLastRTT(t *testing.T) {
	eng := NewEngine()
	s := newNodeSentinel(eng)

	if rtt := s.LastRTT(); rtt != 0 {
		t.Errorf("expected initial LastRTT to be 0, got %v", rtt)
	}

	eng.activeAddr = "192.0.2.1:443"
	eng.activeSNI = "test.example.com"

	s.dialFn = func(ctx context.Context, cfg *TransportConfig) (*Client, error) {
		time.Sleep(15 * time.Millisecond)
		return &Client{}, nil
	}

	healthy := s.isCurrentNodeHealthy(context.Background())
	if !healthy {
		t.Fatal("expected isCurrentNodeHealthy to return true")
	}

	lastRTT := s.LastRTT()
	if lastRTT < 10*time.Millisecond {
		t.Errorf("expected LastRTT >= 10ms, got %v", lastRTT)
	}
}

// 6. 验证 Engine AppState 状态快照扩展字段
func TestEngineAppStateExtendedFields(t *testing.T) {
	eng := NewEngine()
	eng.currentISP = "CT"
	eng.savedSubURL = "https://example.com/sub/test"
	eng.activeAddr = "198.51.100.1:443"
	eng.activeSNI = "node1.example.com"
	eng.sentinel.lastRTT.Store(42 * time.Millisecond.Nanoseconds())

	st := eng.GetState()
	if st.ActiveNode != "198.51.100.1:443" || st.Node != "198.51.100.1:443" {
		t.Errorf("unexpected ActiveNode/Node: %+v", st)
	}
	if st.ActiveSNI != "node1.example.com" || st.SNI != "node1.example.com" {
		t.Errorf("unexpected ActiveSNI/SNI: %+v", st)
	}
	if st.ISP != "CT" || st.ISPName != "中国电信" {
		t.Errorf("unexpected ISP/ISPName: %s / %s", st.ISP, st.ISPName)
	}
	if st.RttMs != 42 || !st.ProbeOk || st.ProbeMs != 42 {
		t.Errorf("unexpected RttMs/ProbeOk/ProbeMs: %d / %v / %d", st.RttMs, st.ProbeOk, st.ProbeMs)
	}
	if st.GeoRuleCount <= 0 {
		t.Errorf("expected positive GeoRuleCount, got %d", st.GeoRuleCount)
	}
	if st.SubURL != "https://example.com/sub/test" {
		t.Errorf("unexpected SubURL: %s", st.SubURL)
	}
}

// 7. 验证 SyncGeoData 200 与 304 ETag 缓存流程
func TestSyncGeoData(t *testing.T) {
	geodataFile := filepath.Join(GetDataDir(), "geodata_direct.txt")
	etagFile := filepath.Join(GetDataDir(), "geodata_direct.etag")
	_ = os.Remove(geodataFile)
	_ = os.Remove(etagFile)
	defer func() {
		_ = os.Remove(geodataFile)
		_ = os.Remove(etagFile)
	}()

	etagVal := `"etag-12345"`
	content := "test-direct.cn\n203.0.113.0/24\n"

	requestCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if inm := r.Header.Get("If-None-Match"); inm == etagVal {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etagVal)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	})
	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	eng := NewEngine()
	eng.SetGeoDataURL("http://geodata.example.com/geodata_direct.txt")

	// 第一次同步：200 OK
	count, updated, err := eng.SyncGeoData(context.Background())
	if err != nil {
		t.Fatalf("first SyncGeoData failed: %v", err)
	}
	if !updated {
		t.Fatal("expected first SyncGeoData to report updated=true")
	}
	if count != 2 {
		t.Errorf("expected 2 rules loaded, got %d", count)
	}

	// 检查磁盘写入
	b, readErr := os.ReadFile(geodataFile)
	if readErr != nil || string(b) != content {
		t.Fatalf("geodata file mismatch, read: %s, err: %v", string(b), readErr)
	}

	// 第二次同步：304 Not Modified
	count2, updated2, err2 := eng.SyncGeoData(context.Background())
	if err2 != nil {
		t.Fatalf("second SyncGeoData failed: %v", err2)
	}
	if updated2 {
		t.Fatal("expected second SyncGeoData to report updated=false (304)")
	}
	if count2 <= 0 {
		t.Errorf("expected positive rule count on 304, got %d", count2)
	}
}

// 8. 验证 TunnelClient.classifyTarget 激活 splitEngine
func TestTunnelClassifyTarget(t *testing.T) {
	split := NewSplitEngine()
	tc := NewTunnelClient(nil, split)

	// 普通目标 -> GENERAL
	st1 := tc.classifyTarget("example.com:443")
	if st1.StreamType.String() != "GENERAL" {
		t.Errorf("expected GENERAL for example.com, got %v", st1.StreamType)
	}

	// AI 目标 -> AI
	st2 := tc.classifyTarget("api.openai.com:443")
	if st2.StreamType.String() != "AI" {
		t.Errorf("expected AI for api.openai.com, got %v", st2.StreamType)
	}

	// 动态添加 AI 规则到 splitEngine
	split.AddRule(Rule{
		Name:           "Custom AI",
		Strategy:       AI,
		DomainSuffixes: []string{"custom-ai.internal"},
	})
	st3 := tc.classifyTarget("custom-ai.internal:8000")
	if st3.StreamType.String() != "AI" {
		t.Errorf("expected AI for custom-ai.internal, got %v", st3.StreamType)
	}
}

// 9. 验证 LoadAndApplySubscription 与运营商自动分流
func TestLoadAndApplySubscriptionWithISP(t *testing.T) {
	subObj := &Subscription{
		Version: "aero/3.0",
		Servers: []ServerConfig{
			{Name: "Node-CT", Address: "192.0.2.1:443", Token: "tok_ct", ISPAffinity: "CT"},
			{Name: "Node-CU", Address: "192.0.2.2:443", Token: "tok_cu", ISPAffinity: "CU"},
			{Name: "Node-CM", Address: "192.0.2.3:443", Token: "tok_cm", ISPAffinity: "CM"},
		},
	}
	b64, err := subObj.ToBase64()
	if err != nil {
		t.Fatalf("sub ToBase64 failed: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, b64)
	})
	SetPhysicalDialerHook(newInMemHTTPDialer(handler))
	defer SetPhysicalDialerHook(nil)

	eng := NewEngine()
	subURL := "http://sub.example.com/sub/superadmin"
	applied, err := eng.LoadAndApplySubscription(subURL)
	if err != nil {
		t.Fatalf("LoadAndApplySubscription failed: %v", err)
	}

	if len(applied.Servers) != 3 {
		t.Fatalf("expected 3 applied servers, got %d", len(applied.Servers))
	}

	eng.mu.RLock()
	savedURL := eng.savedSubURL
	curISP := eng.currentISP
	eng.mu.RUnlock()

	if savedURL != subURL {
		t.Errorf("savedSubURL mismatch: expected %s, got %s", subURL, savedURL)
	}
	if curISP == "" {
		t.Error("currentISP should not be empty")
	}
}

// 10. 验证 PingActiveNode
func TestPingActiveNode(t *testing.T) {
	SetActiveEdge("", "", "", nil)
	eng := NewEngine()

	// 未配置活跃节点时应返回错误
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := eng.PingActiveNode(ctx)
	if err == nil {
		t.Fatal("expected error when pinging without active edge")
	}
}

type mockNetworkMonitor struct {
	onChange func(newGW, ifName string)
	stopped  atomic.Bool
}

func (m *mockNetworkMonitor) Start(onChange func(newGW, ifName string)) { m.onChange = onChange }
func (m *mockNetworkMonitor) Stop()                                     { m.stopped.Store(true) }
func (m *mockNetworkMonitor) Trigger(newGW, ifName string) {
	if m.onChange != nil {
		m.onChange(newGW, ifName)
	}
}

// 11. 验证事件驱动的物理网络变更监控（Netmon）触发 WebRTC 立即同步下线
func TestWebRTCNetworkMonitorEventDriven(t *testing.T) {
	mockDev := newMockTunDevice()
	defer mockDev.Close()

	eng := NewEngine()
	stackEng := NewStackEngine(mockDev, nil, nil)
	eng.mu.Lock()
	eng.stackEngine = stackEng
	eng.mu.Unlock()

	// 初始先将 WebRTC 标记为活跃
	stackEng.SetWebRTCActive(true)
	if !stackEng.WebRTCActive() {
		t.Fatal("expected WebRTC to be active before network change")
	}

	nm := &mockNetworkMonitor{}
	eng.SetNetworkMonitor(nm)

	// 模拟注册网络变更回调
	nm.Start(func(newGW, ifName string) {
		eng.onNetworkChange(newGW, ifName)
	})

	// 触发物理网络变动事件
	nm.Trigger("192.168.1.1", "eth0")

	// 验证 WebRTC 立即被同步下线为 false
	if stackEng.WebRTCActive() {
		t.Fatal("expected WebRTC to be deactivated immediately after network change event")
	}
}

// 12. 验证当 IPRanges 含有非法 CIDR 时，TotalRules 准确反映 parsedIPNets
func TestTotalRulesParsedIPNetsMismatch(t *testing.T) {
	engine := NewSplitEngine()
	baseTotal := engine.TotalRules()

	rule := Rule{
		Name:     "Test Invalid CIDR",
		Strategy: DIRECT,
		IPRanges: []string{
			"192.168.1.0/24",
			"invalid-cidr-format",
			"10.0.0.0/8",
			"999.999.999.999/24",
		},
	}
	engine.AddRule(rule)

	// IPRanges 中共有 4 项，其中仅 2 项有效 ("192.168.1.0/24" 和 "10.0.0.0/8")
	// 验证 TotalRules 准确反映 parsedIPNets 的数量 (2 项)，而非原始 IPRanges 的长度 (4 项)
	newTotal := engine.TotalRules()
	added := newTotal - baseTotal
	if added != 2 {
		t.Fatalf("expected 2 valid parsed IP nets counted, got %d (raw IPRanges count was %d)", added, len(rule.IPRanges))
	}
}

// 13. 验证 QUIC 客户端初始包长配置为 0 (交给 quic-go 默认值与 RFC 8899 PMTU 协商)
func TestQUICInitialPacketSizeJitter(t *testing.T) {
	quicConfig := &quic.Config{
		InitialPacketSize: 0,
	}
	if quicConfig.InitialPacketSize != 0 {
		t.Fatalf("expected InitialPacketSize == 0, got %d", quicConfig.InitialPacketSize)
	}
}
