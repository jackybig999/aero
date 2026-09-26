// AERO 配置全局默认常量
package config

import "time"

const (
	DefaultVersion           = "1.0"
	DefaultListenSOCKS5      = "127.0.0.1:1080"
	DefaultTUNDevice         = "aero0"
	DefaultTUNMTU            = 1420
	DefaultTUNIPv4           = "10.88.0.2/24"
	DefaultTUNIPv6           = "fd00:aero::2/64"
	DefaultFakeIPRange       = "198.18.0.0/15"
	DefaultFingerprint       = "chrome"
	DefaultSplitStrategy     = "proxy"
	DefaultRTTProbeInterval  = 30 * time.Second
	DefaultCooldown          = 30 * time.Second
	DefaultHeartbeat         = 30 * time.Second
	DefaultHeartbeatTimeout  = 90 * time.Second
	DefaultSSEKeepalive      = 15 * time.Second
	DefaultFirstTokenTimeout = 60 * time.Second
	DefaultContextTTL        = 5 * time.Minute
	DefaultEdgeWeight        = 100
	DefaultMaxMessageSize    = 16 * 1024 * 1024 // 16MB
	DefaultSNI               = "cdn-aero.com"
	DefaultLogFormat         = "text"
	DefaultCertMode          = "self_signed"
	DefaultAuthTTL           = 8760 * time.Hour // 1 year
)

// DefaultClientConfig 返回客户端默认配置
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Log: LogConfig{Format: DefaultLogFormat},
		Listen: ListenConfig{
			SOCKS5: DefaultListenSOCKS5,
		},
		TUN: TUNConfig{
			Device: DefaultTUNDevice,
			MTU:    DefaultTUNMTU,
			IPv4:   DefaultTUNIPv4,
			IPv6:   DefaultTUNIPv6,
			Routes: []string{"0.0.0.0/0", "::/0"},
			DNS: DNSConfig{
				Servers: []string{"223.5.5.5", "8.8.8.8"},
				Hijack:  true,
				FakeIP: FakeIPConfig{
					Enabled: true,
					Range:   DefaultFakeIPRange,
				},
			},
		},
		Edge: EdgeConfig{
			Selection: SelectionConfig{
				Strategy:      "rtt",
				ProbeInterval: DefaultRTTProbeInterval,
				Cooldown:      DefaultCooldown,
			},
			Transport: TransportConfig{
				Fingerprint: DefaultFingerprint,
				ECH:         ECHConfig{Enabled: true},
			},
		},
		Split: SplitConfig{
			Enabled: true,
			Default: DefaultSplitStrategy,
		},
		QoS: QoSConfig{
			HeartbeatInterval: DefaultHeartbeat,
			HeartbeatTimeout:  DefaultHeartbeatTimeout,
			AI: AIQoSConfig{
				SSEKeepalive:      DefaultSSEKeepalive,
				FirstTokenTimeout: DefaultFirstTokenTimeout,
				ContextTTL:        DefaultContextTTL,
			},
		},
	}
}

// DefaultServerConfig 返回服务端默认配置
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Listen: ServerListenConfig{
			Ports: []int{8443},
		},
		TLS: ServerTLSConfig{
			Mode: DefaultCertMode,
		},
		ECH: ServerECHConfig{
			PublicName: DefaultSNI,
		},
		Log: LogConfig{Format: DefaultLogFormat},
	}
}
