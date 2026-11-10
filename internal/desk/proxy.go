package desk

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SysProxyDetector 定义平台系统代理探测接口（依赖注入）
type SysProxyDetector interface {
	Detect() (*ProxyConfig, error)
}

// NoopSysProxyDetector 零污染无操作代理探测器 (宿主机零污染，绝不篡改系统代理)
type NoopSysProxyDetector struct{}

// Detect 返回禁用状态代理，杜绝宿主机系统代理污染
func (d *NoopSysProxyDetector) Detect() (*ProxyConfig, error) {
	return &ProxyConfig{Enabled: false}, nil
}

// ProxyConfig 统一代理配置结构
type ProxyConfig struct {
	Enabled  bool   `json:"enabled"`
	Protocol string `json:"protocol"` // "http" 或 "socks5"
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Address 返回 host:port 格式
func (p *ProxyConfig) Address() string {
	if p == nil || p.Host == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", p.Host, p.Port)
}

// URLString 返回包含协议与账密的标准 URL
func (p *ProxyConfig) URLString() string {
	if p == nil || p.Host == "" {
		return ""
	}
	proto := strings.ToLower(p.Protocol)
	if proto == "" {
		proto = "http"
	}
	if p.Username != "" {
		userInfo := url.UserPassword(p.Username, p.Password)
		return fmt.Sprintf("%s://%s@%s:%d", proto, userInfo.String(), p.Host, p.Port)
	}
	return fmt.Sprintf("%s://%s:%d", proto, p.Host, p.Port)
}

// ChromeProxyArg 生成 Chrome 命令行所用的 --proxy-server 参数
func (p *ProxyConfig) ChromeProxyArg() string {
	if p == nil || !p.Enabled || p.Host == "" {
		return ""
	}
	proto := strings.ToLower(p.Protocol)
	if proto == "socks5" {
		return fmt.Sprintf("--proxy-server=socks5://%s:%d", p.Host, p.Port)
	}
	return fmt.Sprintf("--proxy-server=http://%s:%d", p.Host, p.Port)
}

// OutboundInfo 出站探测结果
type OutboundInfo struct {
	ProxyID    int64     `json:"proxy_id"`
	RawInput   string    `json:"raw_input"`
	Protocol   string    `json:"protocol"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	OutboundIP string    `json:"outbound_ip"`
	Country    string    `json:"country"`
	City       string    `json:"city"`
	ISP        string    `json:"isp"`
	Timezone   string    `json:"timezone"`
	LatencyMs  int64     `json:"latency_ms"`
	Status     string    `json:"status"` // "ok", "timeout", "auth_error", "failed"
	ErrorMsg   string    `json:"error_msg,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
}

// ParseProxyString 解析主流商用购买 IP 格式
func ParseProxyString(raw string) (*ProxyConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("代理字符串不能为空")
	}

	cfg := &ProxyConfig{
		Enabled:  true,
		Protocol: "http",
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("解析代理 URI 失败: %w", err)
		}
		cfg.Protocol = strings.ToLower(u.Scheme)
		cfg.Host = u.Hostname()
		portStr := u.Port()
		if portStr != "" {
			cfg.Port, _ = strconv.Atoi(portStr)
		} else {
			if cfg.Protocol == "socks5" {
				cfg.Port = 1080
			} else {
				cfg.Port = 8080
			}
		}
		if u.User != nil {
			cfg.Username = u.User.Username()
			cfg.Password, _ = u.User.Password()
		}
	} else if strings.Contains(raw, "@") {
		parts := strings.SplitN(raw, "@", 2)
		userPart := parts[0]
		hostPart := parts[1]

		if strings.Contains(userPart, ":") {
			up := strings.SplitN(userPart, ":", 2)
			cfg.Username = up[0]
			cfg.Password = up[1]
		} else {
			cfg.Username = userPart
		}

		host, portStr, err := net.SplitHostPort(hostPart)
		if err != nil {
			return nil, fmt.Errorf("解析代理主机端口失败: %w", err)
		}
		cfg.Host = host
		cfg.Port, _ = strconv.Atoi(portStr)
	} else {
		parts := strings.Split(raw, ":")
		if len(parts) == 4 {
			cfg.Host = parts[0]
			cfg.Port, _ = strconv.Atoi(parts[1])
			cfg.Username = parts[2]
			cfg.Password = parts[3]
		} else if len(parts) == 2 {
			cfg.Host = parts[0]
			cfg.Port, _ = strconv.Atoi(parts[1])
		} else {
			return nil, fmt.Errorf("无法识别的代理格式: %s", raw)
		}
	}

	if cfg.Host == "" {
		return nil, fmt.Errorf("代理主机不能为空: %s", raw)
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("非法代理端口号: %d", cfg.Port)
	}
	return cfg, nil
}

// BuildHTTPClient 根据 ProxyConfig 创建带超时的测试客户端
func BuildHTTPClient(cfg *ProxyConfig, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 0,
		}).DialContext,
	}

	if cfg != nil && cfg.Enabled && cfg.Host != "" {
		proxyURLStr := cfg.URLString()
		proxyURL, err := url.Parse(proxyURLStr)
		if err != nil {
			return nil, fmt.Errorf("构造代理 URL 失败: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// TestOutbound 发起真实公网出站探测
func TestOutbound(ctx context.Context, cfg *ProxyConfig, timeout time.Duration) (*OutboundInfo, error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	rawInput := ""
	proto := "direct"
	host := ""
	port := 0
	if cfg != nil {
		rawInput = cfg.URLString()
		proto = cfg.Protocol
		host = cfg.Host
		port = cfg.Port
	}

	info := &OutboundInfo{
		RawInput:  rawInput,
		Protocol:  proto,
		Host:      host,
		Port:      port,
		Status:    "ok",
		CheckedAt: time.Now(),
	}

	client, err := BuildHTTPClient(cfg, timeout)
	if err != nil {
		info.Status = "failed"
		info.ErrorMsg = err.Error()
		return info, err
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://ip-api.com/json/?fields=status,message,country,city,isp,query,timezone", nil)
	if err != nil {
		info.Status = "failed"
		info.ErrorMsg = err.Error()
		return info, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	info.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		if strings.Contains(err.Error(), "context deadline exceeded") || strings.Contains(err.Error(), "timeout") {
			info.Status = "timeout"
		} else if strings.Contains(err.Error(), "407") || strings.Contains(err.Error(), "Proxy Authentication Required") {
			info.Status = "auth_error"
		} else {
			info.Status = "failed"
		}
		info.ErrorMsg = err.Error()
		return info, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 407 {
		info.Status = "auth_error"
		info.ErrorMsg = "代理账密认证失败 (HTTP 407)"
		return info, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		info.Status = "failed"
		info.ErrorMsg = fmt.Sprintf("读取响应失败: %v", err)
		return info, nil
	}

	var res struct {
		Status   string `json:"status"`
		Message  string `json:"message"`
		Country  string `json:"country"`
		City     string `json:"city"`
		ISP      string `json:"isp"`
		Query    string `json:"query"`
		Timezone string `json:"timezone"`
	}

	if err := json.Unmarshal(body, &res); err == nil && res.Status == "success" {
		info.OutboundIP = res.Query
		info.Country = res.Country
		info.City = res.City
		info.ISP = res.ISP
		info.Timezone = res.Timezone
	} else {
		info.OutboundIP = strings.TrimSpace(string(body))
	}

	return info, nil
}

// FormatOutboundTable 生成整齐的状态展示表格
func FormatOutboundTable(list []*OutboundInfo) string {
	var sb strings.Builder
	sb.WriteString("================================ 当前可用代理与出站IP列表 ================================\n")
	sb.WriteString(fmt.Sprintf("%-4s  %-7s  %-20s  %-16s  %-20s  %-6s  %-6s\n", "序号", "协议", "输入地址", "实际出站IP", "归属地/运营商", "延迟", "状态"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")

	for i, item := range list {
		loc := item.Country
		if item.City != "" {
			loc += " " + item.City
		}
		if item.ISP != "" {
			loc += " / " + item.ISP
		}
		if len(loc) > 20 {
			loc = loc[:18] + ".."
		}

		outIP := item.OutboundIP
		if outIP == "" {
			outIP = "--"
		}

		lat := fmt.Sprintf("%dms", item.LatencyMs)
		if item.Status == "timeout" {
			lat = "超时"
		}

		statusTag := "[可用]"
		if item.Status != "ok" {
			statusTag = fmt.Sprintf("[%s]", item.Status)
		}

		addr := fmt.Sprintf("%s:%d", item.Host, item.Port)
		sb.WriteString(fmt.Sprintf("[%d]   %-7s  %-20s  %-16s  %-20s  %-6s  %-6s\n", i+1, strings.ToUpper(item.Protocol), addr, outIP, loc, lat, statusTag))
	}
	sb.WriteString("==========================================================================================\n")
	return sb.String()
}

// SaveProxyToDB 将代理及其出站检测结果保存入库
func SaveProxyToDB(db *sql.DB, userID int64, cfg *ProxyConfig, info *OutboundInfo) (int64, error) {
	stmt := `INSERT INTO proxies (
		user_id, raw_input, protocol, host, port, username, password,
		outbound_ip, country, city, isp, timezone, latency_ms, status, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`

	outIP := ""
	country := ""
	city := ""
	isp := ""
	tz := ""
	var latency int64
	status := "unknown"

	if info != nil {
		outIP = info.OutboundIP
		country = info.Country
		city = info.City
		isp = info.ISP
		tz = info.Timezone
		latency = info.LatencyMs
		status = info.Status
	}

	res, err := db.Exec(stmt,
		userID, cfg.URLString(), cfg.Protocol, cfg.Host, cfg.Port, cfg.Username, cfg.Password,
		outIP, country, city, isp, tz, latency, status,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}
