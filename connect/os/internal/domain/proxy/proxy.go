package proxy

import (
	"fmt"
	"net/url"
	"strings"
)

// SysProxyDetector 定义平台系统代理探测接口（依赖注入）
type SysProxyDetector interface {
	Detect() (*ProxyConfig, error)
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
