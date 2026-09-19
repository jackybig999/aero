// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package public 小 VPS 多用户档位预设（v1 冻结语义）。
package public

import "time"

// ProfileSettings 运行参数
type ProfileSettings struct {
	Name          string
	MaxConn       int
	MaxConnUser   int
	RateIP        int           // CONNECT/s/IP
	BandwidthUser int           // bytes/s/token，0=不限
	IdleTimeout   time.Duration // 无流量断开
	MaxLife       time.Duration // 单隧道最长寿命，0=不限
	MaxDial       int           // 同时拨号上限
	Quiet         bool
}

// GetProfile 返回档位；空或 unknown 返回 nil。
func GetProfile(name string) *ProfileSettings {
	switch name {
	case "tiny":
		return &ProfileSettings{
			// Browser tabs open many concurrent CONNECTs; 16 was too low → client 503 flood.
			Name: "tiny", MaxConn: 1024, MaxConnUser: 256, RateIP: 80,
			BandwidthUser: 2 << 20,
			IdleTimeout:   10 * time.Minute,
			MaxLife:       12 * time.Hour,
			MaxDial:       128,
			Quiet:         true,
		}
	case "small":
		return &ProfileSettings{
			Name: "small", MaxConn: 4096, MaxConnUser: 512, RateIP: 120,
			BandwidthUser: 5 << 20,
			IdleTimeout:   15 * time.Minute,
			MaxLife:       24 * time.Hour,
			MaxDial:       256,
			Quiet:         true,
		}
	case "medium":
		return &ProfileSettings{
			Name: "medium", MaxConn: 8192, MaxConnUser: 1024, RateIP: 200,
			BandwidthUser: 0,
			IdleTimeout:   20 * time.Minute,
			MaxLife:       0,
			MaxDial:       512,
			Quiet:         false,
		}
	default:
		return nil
	}
}
