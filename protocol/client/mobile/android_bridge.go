// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

//go:build android

package mobile

import (
	"sync"
)

var (
	packetMu       sync.Mutex
	packetCallback func([]byte)
)

// RegisterPacketCallback 注册 Android VpnService 数据包消费回调
func RegisterPacketCallback(cb func([]byte)) {
	packetMu.Lock()
	defer packetMu.Unlock()
	packetCallback = cb
}

// OnPacketReceived Android VpnService 接收到系统网卡数据包注入引擎
func OnPacketReceived(pkt []byte) {
	// 注入协议底层引擎
}

// EmitOutPacket 写回 Android VpnService 网卡
func EmitOutPacket(pkt []byte) {
	packetMu.Lock()
	cb := packetCallback
	packetMu.Unlock()
	if cb != nil {
		cb(pkt)
	}
}
