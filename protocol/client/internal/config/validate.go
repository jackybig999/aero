// AERO 配置校验与默认值填充
package config

import (
	"fmt"
	"net"
	"strings"
)

// Validate 校验客户端配置并填充默认值
func (cfg *AeroConfig) Validate() error {
	if cfg.Version == "" {
		cfg.Version = DefaultVersion
	}
	if cfg.Version != "1.0" {
		return fmt.Errorf("unsupported config version: %s (expected 1.0)", cfg.Version)
	}

	if err := cfg.validateClient(); err != nil {
		return fmt.Errorf("client: %w", err)
	}
	return nil
}

func (cfg *AeroConfig) validateClient() error {
	c := &cfg.Client

	// Log 默认值
	if c.Log.Format == "" {
		c.Log.Format = DefaultLogFormat
	}

	// Listen 默认值
	if c.Listen.SOCKS5 == "" {
		c.Listen.SOCKS5 = DefaultListenSOCKS5
	}

	// TUN 校验
	if c.TUN.Enabled {
		if c.TUN.IPv4 != "" {
			if _, _, err := net.ParseCIDR(c.TUN.IPv4); err != nil {
				return fmt.Errorf("tun.ipv4 invalid CIDR: %s", c.TUN.IPv4)
			}
		}
		if c.TUN.MTU == 0 {
			c.TUN.MTU = DefaultTUNMTU
		}
		if c.TUN.Device == "" {
			c.TUN.Device = DefaultTUNDevice
		}
		if len(c.TUN.Routes) == 0 {
			c.TUN.Routes = []string{"0.0.0.0/0", "::/0"}
		}
	}

	// Edge 必填校验
	if len(c.Edge.Pool) == 0 {
		return fmt.Errorf("edge.pool must have at least one node")
	}
	for i, node := range c.Edge.Pool {
		if node.Address == "" {
			return fmt.Errorf("edge.pool[%d].address is required", i)
		}
		if node.Token == "" {
			return fmt.Errorf("edge.pool[%d].token is required", i)
		}
		if node.Weight == 0 {
			c.Edge.Pool[i].Weight = DefaultEdgeWeight
		}
		if !strings.Contains(node.Address, ":") {
			c.Edge.Pool[i].Address = node.Address + ":443"
		}
	}

	// Selection 默认值
	if c.Edge.Selection.Strategy == "" {
		c.Edge.Selection.Strategy = "rtt"
	}
	if c.Edge.Selection.ProbeInterval == 0 {
		c.Edge.Selection.ProbeInterval = DefaultRTTProbeInterval
	}
	if c.Edge.Selection.Cooldown == 0 {
		c.Edge.Selection.Cooldown = DefaultCooldown
	}

	// Transport 默认值
	if c.Edge.Transport.Fingerprint == "" {
		c.Edge.Transport.Fingerprint = DefaultFingerprint
	}

	// Split 默认值
	if c.Split.Default == "" {
		c.Split.Default = DefaultSplitStrategy
	}

	// QoS 默认值
	if c.QoS.HeartbeatInterval == 0 {
		c.QoS.HeartbeatInterval = DefaultHeartbeat
	}
	if c.QoS.HeartbeatTimeout == 0 {
		c.QoS.HeartbeatTimeout = DefaultHeartbeatTimeout
	}
	if c.QoS.AI.ContextTTL == 0 {
		c.QoS.AI.ContextTTL = DefaultContextTTL
	}

	return nil
}
