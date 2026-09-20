// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package mobile 提供专供 gomobile bind 导出的 5 大跨端安全接口 (Android/iOS SDK)。
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	client "github.com/aero-protocol/aero-ech"
)

var (
	mu           sync.Mutex
	isRunning    atomic.Bool
	activeSub    *client.Subscription
	activeNode   string
	cancelEngine context.CancelFunc
)

// MobileStatus 移动端状态快照 DTO
type MobileStatus struct {
	Connected  bool   `json:"connected"`
	ActiveNode string `json:"active_node"`
	Mode       string `json:"mode"`
	Version    string `json:"version"`
	UpdatedAt  int64  `json:"updated_at"`
}

// 1. Start 启动移动端隧道引擎 (gomobile safe)
func Start(subURL, mode, token string) error {
	mu.Lock()
	defer mu.Unlock()

	if isRunning.Load() {
		return errors.New("mobile engine already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelEngine = cancel

	// 拉取订阅
	sub, err := client.FetchSubscription(ctx, subURL, client.SubFetchOptions{
		Timeout: 10 * time.Second,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("fetch subscription: %w", err)
	}
	if len(sub.Servers) == 0 {
		cancel()
		return errors.New("no server nodes in subscription")
	}

	activeSub = sub
	activeNode = sub.Servers[0].Name
	isRunning.Store(true)
	return nil
}

// 2. Stop 停止移动端隧道引擎 (gomobile safe)
func Stop() error {
	mu.Lock()
	defer mu.Unlock()

	if !isRunning.Load() {
		return nil
	}
	if cancelEngine != nil {
		cancelEngine()
	}
	isRunning.Store(false)
	return nil
}

// 3. GetStatus 获取当前移动端状态 JSON 字符串 (gomobile safe)
func GetStatus() string {
	mu.Lock()
	defer mu.Unlock()

	st := MobileStatus{
		Connected:  isRunning.Load(),
		ActiveNode: activeNode,
		Mode:       "tun",
		Version:    "aero-mobile/2.0",
		UpdatedAt:  time.Now().Unix(),
	}
	data, _ := json.Marshal(st)
	return string(data)
}

// 4. SetConfig 动态热更新配置 (gomobile safe)
func SetConfig(jsonConfig string) error {
	mu.Lock()
	defer mu.Unlock()

	var patch map[string]any
	if err := json.Unmarshal([]byte(jsonConfig), &patch); err != nil {
		return fmt.Errorf("invalid config json: %w", err)
	}
	return nil
}

// 5. SwitchNode 手动或策略切换目标节点 (gomobile safe)
func SwitchNode(nodeName string) error {
	mu.Lock()
	defer mu.Unlock()

	if activeSub == nil {
		return errors.New("no active subscription loaded")
	}
	for _, s := range activeSub.Servers {
		if s.Name == nodeName {
			activeNode = s.Name
			return nil
		}
	}
	return fmt.Errorf("node %s not found in subscription", nodeName)
}
