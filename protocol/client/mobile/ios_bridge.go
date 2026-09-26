// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

//go:build ios || darwin

package mobile

import (
	"sync"
)

var (
	iosPacketMu sync.Mutex
	iosOutCb    func([]byte)
)

// SetIOSPacketCallback 注册向 iOS PacketTunnelProvider 写回数据包的回调
func SetIOSPacketCallback(cb func([]byte)) {
	iosPacketMu.Lock()
	defer iosPacketMu.Unlock()
	iosOutCb = cb
}

// HandleIOSPackets 接收来自 iOS NEPacketTunnelProvider 批量注入的数据包
func HandleIOSPackets(packets [][]byte) error {
	for _, pkt := range packets {
		if len(pkt) == 0 {
			continue
		}
		// 数据面分流与中继
	}
	return nil
}
