// AERO 配置文件结构体定义 v1.0
//
// 设计原则：
//   - 所有字段内嵌 AERO 语义，不与 Clash/sing-box 混淆
//   - 不支持 outbounds 等多协议概念
//   - 时间字段用 time.Duration，地址字段做 host:port 校验
package config

import "time"

// AeroConfig 顶层配置
type AeroConfig struct {
	Version string       `yaml:"version" json:"version"` // "1.0"
	Client  ClientConfig `yaml:"client" json:"client"`
	Server  ServerConfig `yaml:"server" json:"server"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	Log    LogConfig    `yaml:"log" json:"log"`
	Listen ListenConfig `yaml:"listen" json:"listen"`
	TUN    TUNConfig    `yaml:"tun" json:"tun"`
	Edge   EdgeConfig   `yaml:"edge" json:"edge"`
	Split  SplitConfig  `yaml:"split" json:"split"`
	QoS    QoSConfig    `yaml:"qos" json:"qos"`
}

// LogConfig 日志配置
type LogConfig struct {
	File   string `yaml:"file" json:"file"`     // 日志文件路径
	Format string `yaml:"format" json:"format"` // "text" | "json"
}

// ListenConfig 监听配置
type ListenConfig struct {
	SOCKS5 string `yaml:"socks5" json:"socks5"` // SOCKS5 监听地址
}

// TUNConfig TUN 虚拟网卡配置
type TUNConfig struct {
	Enabled bool      `yaml:"enabled" json:"enabled"`
	Device  string    `yaml:"device" json:"device"` // "aero0"
	MTU     int       `yaml:"mtu" json:"mtu"`       // 默认 1420
	IPv4    string    `yaml:"ipv4" json:"ipv4"`     // "10.88.0.2/24"
	IPv6    string    `yaml:"ipv6" json:"ipv6"`     // "fd00:aero::2/64"
	Routes  []string  `yaml:"routes" json:"routes"` // ["0.0.0.0/0", "::/0"]
	DNS     DNSConfig `yaml:"dns" json:"dns"`
}

// DNSConfig DNS 配置
type DNSConfig struct {
	Servers []string     `yaml:"servers" json:"servers"` // ["223.5.5.5", "8.8.8.8"]
	Hijack  bool         `yaml:"hijack" json:"hijack"`   // 是否劫持 53 端口
	FakeIP  FakeIPConfig `yaml:"fake_ip" json:"fake_ip"`
}

// FakeIPConfig Fake-IP 配置
type FakeIPConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Range   string `yaml:"range" json:"range"` // "198.18.0.0/15"
}

// EdgeConfig Edge 节点配置
type EdgeConfig struct {
	Pool      []EdgeNode      `yaml:"pool" json:"pool"`
	Selection SelectionConfig `yaml:"selection" json:"selection"`
	Transport TransportConfig `yaml:"transport" json:"transport"`
}

// EdgeNode 单个 Edge 节点
type EdgeNode struct {
	Name    string   `yaml:"name" json:"name"`
	Address string   `yaml:"address" json:"address"` // "host:port"
	Token   string   `yaml:"token" json:"token"`
	SNI     string   `yaml:"sni" json:"sni"`
	CACert  string   `yaml:"ca_cert" json:"ca_cert"` // CA 证书路径
	Weight  int      `yaml:"weight" json:"weight"`   // 默认 100
	Tags    []string `yaml:"tags" json:"tags"`
}

// SelectionConfig 节点选择策略
type SelectionConfig struct {
	Strategy      string        `yaml:"strategy" json:"strategy"` // rtt|least_fail|weighted|manual
	ProbeInterval time.Duration `yaml:"probe_interval" json:"probe_interval"`
	Cooldown      time.Duration `yaml:"cooldown" json:"cooldown"`
}

// TransportConfig 传输层配置
type TransportConfig struct {
	Fingerprint string    `yaml:"fingerprint" json:"fingerprint"` // chrome|firefox|safari|random
	ECH         ECHConfig `yaml:"ech" json:"ech"`
}

// ECHConfig ECH 配置
type ECHConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	ConfigB64 string `yaml:"config_b64" json:"config_b64"`
}

// SplitConfig 分流配置
type SplitConfig struct {
	Enabled bool        `yaml:"enabled" json:"enabled"`
	Default string      `yaml:"default" json:"default"` // direct|proxy|ai
	Rules   []SplitRule `yaml:"rules" json:"rules"`
}

// SplitRule 单条分流规则
type SplitRule struct {
	Name           string   `yaml:"name" json:"name"`
	Strategy       string   `yaml:"strategy" json:"strategy"` // direct|proxy|ai
	DomainSuffixes []string `yaml:"domain_suffixes" json:"domain_suffixes"`
	IPRanges       []string `yaml:"ip_ranges" json:"ip_ranges"`
}

// QoSConfig QoS 配置
type QoSConfig struct {
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval" json:"heartbeat_interval"`
	HeartbeatTimeout  time.Duration `yaml:"heartbeat_timeout" json:"heartbeat_timeout"`
	AI                AIQoSConfig   `yaml:"ai" json:"ai"`
}

// AIQoSConfig AI 流 QoS 参数
type AIQoSConfig struct {
	SSEKeepalive      time.Duration `yaml:"sse_keepalive" json:"sse_keepalive"`
	FirstTokenTimeout time.Duration `yaml:"first_token_timeout" json:"first_token_timeout"`
	ContextTTL        time.Duration `yaml:"context_ttl" json:"context_ttl"`
}

// ServerConfig 服务端配置
type ServerConfig struct {
	Listen ServerListenConfig `yaml:"listen" json:"listen"`
	TLS    ServerTLSConfig    `yaml:"tls" json:"tls"`
	ECH    ServerECHConfig    `yaml:"ech" json:"ech"`
	Auth   AuthConfig         `yaml:"auth" json:"auth"`
	Log    LogConfig          `yaml:"log" json:"log"`
}

// ServerListenConfig 服务端监听配置
type ServerListenConfig struct {
	Ports []int `yaml:"ports" json:"ports"` // [443, 8443, 80]
}

// ServerTLSConfig 服务端 TLS 配置
type ServerTLSConfig struct {
	Mode     string         `yaml:"mode" json:"mode"` // autocert|manual|self_signed
	CertFile string         `yaml:"cert_file" json:"cert_file"`
	KeyFile  string         `yaml:"key_file" json:"key_file"`
	AutoCert AutoCertConfig `yaml:"autocert" json:"autocert"`
}

// AutoCertConfig Let's Encrypt 自动证书配置
type AutoCertConfig struct {
	Domain   string `yaml:"domain" json:"domain"`
	Email    string `yaml:"email" json:"email"`
	CacheDir string `yaml:"cache_dir" json:"cache_dir"`
}

// ServerECHConfig 服务端 ECH 配置
type ServerECHConfig struct {
	PublicName string `yaml:"public_name" json:"public_name"`
}

// AuthConfig 认证配置
type AuthConfig struct {
	Tokens []AuthToken `yaml:"tokens" json:"tokens"`
}

// AuthToken 认证 Token
type AuthToken struct {
	Token string        `yaml:"token" json:"token"`
	User  string        `yaml:"user" json:"user"`
	TTL   time.Duration `yaml:"ttl" json:"ttl"`
}
