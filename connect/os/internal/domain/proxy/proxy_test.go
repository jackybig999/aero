package proxy

import (
	"context"
	"testing"
	"time"
)

// mockSysProxyDetector 用于单元测试的系统代理探测器 Mock
type mockSysProxyDetector struct {
	mockCfg *ProxyConfig
}

func (m *mockSysProxyDetector) Detect() (*ProxyConfig, error) {
	return m.mockCfg, nil
}

func TestProxyAndOutbound(t *testing.T) {
	// 1. 验证三种购买 IP 格式解析
	t.Log("--- 1. 验证购买 IP 多格式解析 ---")

	// 格式 1: IP:Port:User:Pass
	cfg1, err := ParseProxyString("104.28.19.45:8080:testuser:secretpass")
	if err != nil {
		t.Fatalf("解析格式一失败: %v", err)
	}
	if cfg1.Host != "104.28.19.45" || cfg1.Port != 8080 || cfg1.Username != "testuser" || cfg1.Password != "secretpass" {
		t.Errorf("格式一字段不匹配: %+v", cfg1)
	}

	// 格式 2: SOCKS5 URI
	cfg2, err := ParseProxyString("socks5://user_a:pass_b@45.76.12.89:1080")
	if err != nil {
		t.Fatalf("解析格式二失败: %v", err)
	}
	if cfg2.Protocol != "socks5" || cfg2.Host != "45.76.12.89" || cfg2.Port != 1080 || cfg2.Username != "user_a" {
		t.Errorf("格式二字段不匹配: %+v", cfg2)
	}

	// 格式 3: 无密 IP:Port
	cfg3, err := ParseProxyString("127.0.0.1:7890")
	if err != nil {
		t.Fatalf("解析格式三失败: %v", err)
	}
	if cfg3.Host != "127.0.0.1" || cfg3.Port != 7890 {
		t.Errorf("格式三字段不匹配: %+v", cfg3)
	}

	// 2. 依赖注入系统代理接口验证
	mockDetector := &mockSysProxyDetector{
		mockCfg: &ProxyConfig{
			Enabled:  true,
			Protocol: "socks5",
			Host:     "127.0.0.1",
			Port:     7890,
		},
	}
	detected, err := mockDetector.Detect()
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if !detected.Enabled || detected.Address() != "127.0.0.1:7890" {
		t.Errorf("探测配置不匹配: %+v", detected)
	}

	// 3. 模拟出站表格
	sampleList := []*OutboundInfo{
		{
			Protocol:   "socks5",
			Host:       "127.0.0.1",
			Port:       7890,
			OutboundIP: "104.28.19.45",
			Country:    "美国",
			City:       "洛杉矶",
			ISP:        "Cloudflare",
			LatencyMs:  45,
			Status:     "ok",
		},
		{
			Protocol:   "socks5",
			Host:       "45.76.12.89",
			Port:       1080,
			OutboundIP: "45.76.12.89",
			Country:    "日本",
			City:       "东京",
			ISP:        "Vultr",
			LatencyMs:  82,
			Status:     "ok",
		},
	}

	tableOutput := FormatOutboundTable(sampleList)
	if len(tableOutput) == 0 {
		t.Error("FormatOutboundTable 返回空")
	}

	// 4. 直连探测
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	directInfo, _ := TestOutbound(ctx, &ProxyConfig{Enabled: false}, 2*time.Second)
	if directInfo == nil {
		t.Error("TestOutbound directInfo is nil")
	}
}
