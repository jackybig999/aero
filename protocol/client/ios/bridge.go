// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

//go:build ios && cgo

// Package ios 提供 Swift/ObjC 调用 Go 的 CGO 桥接接口。
//
// 编译要求：GOOS=ios CGO_ENABLED=1
// 使用 gomobile bind 或 xcodebuild 集成到 iOS 项目。
package ios

/*
#include <stdlib.h>

typedef void (*PacketOutCallback)(const char* data, int len);

static inline void invoke_packet_out(PacketOutCallback cb, const char* data, int len) {
    if (cb != NULL) {
        cb(data, len);
    }
}
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"
)

var (
	globalTunnel   *AeroTunnel
	tunnelMu       sync.RWMutex
	cPacketOutCb   C.PacketOutCallback
	cPacketOutMu   sync.Mutex
)

// AeroTunnelRegisterPacketCallback 注册由 Swift 提供的回包写回函数指针
//
//export AeroTunnelRegisterPacketCallback
func AeroTunnelRegisterPacketCallback(cb C.PacketOutCallback) {
	cPacketOutMu.Lock()
	cPacketOutCb = cb
	cPacketOutMu.Unlock()

	tunnelMu.RLock()
	t := globalTunnel
	tunnelMu.RUnlock()

	if t != nil {
		t.SetPacketCallback(func(pkt []byte) {
			if len(pkt) == 0 {
				return
			}
			cPacketOutMu.Lock()
			fn := cPacketOutCb
			cPacketOutMu.Unlock()
			if fn != nil {
				C.invoke_packet_out(fn, (*C.char)(unsafe.Pointer(&pkt[0])), C.int(len(pkt)))
			}
		})
	}
}

// AeroTunnelStart 启动 AERO 隧道（Swift 调用入口）
//
//export AeroTunnelStart
func AeroTunnelStart(configJSON *C.char) *C.char {
	jsonStr := C.GoString(configJSON)

	var cfg TunnelConfig
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return C.CString(fmt.Sprintf(`{"error":"parse config: %v"}`, err))
	}

	tunnelMu.Lock()
	defer tunnelMu.Unlock()

	if globalTunnel != nil && globalTunnel.IsRunning() {
		return C.CString(`{"error":"tunnel already running"}`)
	}

	t := NewAeroTunnel(cfg)

	// 挂载已经注册的 C 回包回调
	cPacketOutMu.Lock()
	fn := cPacketOutCb
	cPacketOutMu.Unlock()
	if fn != nil {
		t.SetPacketCallback(func(pkt []byte) {
			if len(pkt) == 0 {
				return
			}
			cPacketOutMu.Lock()
			callback := cPacketOutCb
			cPacketOutMu.Unlock()
			if callback != nil {
				C.invoke_packet_out(callback, (*C.char)(unsafe.Pointer(&pkt[0])), C.int(len(pkt)))
			}
		})
	}

	if err := t.StartTunnel(nil); err != nil {
		return C.CString(fmt.Sprintf(`{"error":"start tunnel: %v"}`, err))
	}

	globalTunnel = t
	return C.CString(`{"success":true}`)
}

// AeroTunnelStop 停止 AERO 隧道
//
//export AeroTunnelStop
func AeroTunnelStop() {
	tunnelMu.Lock()
	defer tunnelMu.Unlock()

	if globalTunnel != nil {
		_ = globalTunnel.StopTunnel("swift_stop")
		globalTunnel = nil
	}
}

// AeroTunnelHandlePacket 处理系统转发的 IP 包
//
//export AeroTunnelHandlePacket
func AeroTunnelHandlePacket(packet *C.char, length C.int) {
	tunnelMu.RLock()
	t := globalTunnel
	tunnelMu.RUnlock()

	if t == nil || !t.IsRunning() {
		return
	}

	goPkt := C.GoBytes(unsafe.Pointer(packet), length)
	_ = t.HandlePackets([][]byte{goPkt})
}

// AeroTunnelStats 返回隧道统计信息（JSON 字符串，调用者需 free）
//
//export AeroTunnelStats
func AeroTunnelStats() *C.char {
	tunnelMu.RLock()
	t := globalTunnel
	tunnelMu.RUnlock()

	if t == nil {
		return C.CString(`{"isRunning":false}`)
	}

	stats := t.Stats()
	data, _ := json.Marshal(stats)
	return C.CString(string(data))
}

// AeroTunnelUpdateRules 动态更新分流规则
//
//export AeroTunnelUpdateRules
func AeroTunnelUpdateRules(rulesJSON *C.char) *C.char {
	tunnelMu.RLock()
	t := globalTunnel
	tunnelMu.RUnlock()

	if t == nil {
		return C.CString(`{"error":"tunnel not running"}`)
	}

	rules := C.GoString(rulesJSON)
	if err := t.UpdateRules([]byte(rules)); err != nil {
		return C.CString(fmt.Sprintf(`{"error":"%v"}`, err))
	}

	return C.CString(`{"success":true}`)
}

// FreeCString 释放 C 字符串内存（Swift 调用后应释放返回值）
//
//export FreeCString
func FreeCString(s *C.char) {
	C.free(unsafe.Pointer(s))
}
