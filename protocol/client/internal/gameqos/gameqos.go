// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package gameqos 实现游戏流量识别与低延迟策略判定。
package gameqos

// KnownGamePorts 常见游戏端口
var KnownGamePorts = map[int]bool{
	// Steam
	27015: true, 27016: true, 27017: true, 27018: true,
	27019: true, 27020: true, 27021: true, 27022: true,
	// Valorant / League of Legends
	5000: true, 5001: true, 5002: true, 5003: true,
	8393: true, 8400: true, 8401: true,
	// PUBG / Fortnite
	7000: true, 8000: true, 9000: true, 9001: true,
	// Overwatch
	1119: true, 3724: true,
	// Minecraft
	25565: true,
	// Roblox
	49152: true, 65535: true,
	// Call of Duty / Xbox Live
	3074: true,
	// FIFA / EA
	3659: true, 10000: true,
	// PlayStation
	3478: true, 3479: true, 3480: true,
	// Nintendo
	1024: true, 1025: true, 1026: true,
	// General game ports
	27000: true, 27001: true, 27002: true, 27003: true,
	27004: true, 27005: true, 27006: true, 27007: true,
	27008: true, 27009: true, 27010: true, 27011: true,
	27012: true, 27013: true, 27014: true,
}

// IsGameTraffic 判断目标地址是否为游戏流量
func IsGameTraffic(host string, port int) bool {
	return KnownGamePorts[port]
}
