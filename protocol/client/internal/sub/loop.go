// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package sub 包含订阅解析、应用、验证与周期性自愈热更循环。
package sub

import (
	"context"
	"log"
	"time"
)

// ReloadFunc 成功应用新订阅后由调用方重建节点池等
type ReloadFunc func(app *Applied) error

// LoopConfig 热更循环配置
type LoopConfig struct {
	Source   string
	Interval time.Duration
	Fetch    FetchOptions
	// OnChange 路由参数变化时调用；返回 error 则保留旧快照键
	OnChange ReloadFunc
}

// Loop 订阅热更循环
type Loop struct {
	cfg     LoopConfig
	lastKey string
}

// NewLoop 创建热更器；interval<=0 时默认 30m
func NewLoop(cfg LoopConfig) *Loop {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Minute
	}
	return &Loop{cfg: cfg}
}

// SetLastKey 设置已知快照（首次 load 后调用，避免立刻重复 OnChange）
func (l *Loop) SetLastKey(key string) {
	l.lastKey = key
}

// Run 阻塞直到 ctx 取消
func (l *Loop) Run(ctx context.Context) {
	if l.cfg.Source == "" || l.cfg.OnChange == nil {
		return
	}
	ticker := time.NewTicker(l.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.tick()
		}
	}
}

// TickOnce 单次拉取（测试用）
func (l *Loop) TickOnce() error {
	return l.tick()
}

func (l *Loop) tick() error {
	doc, err := Fetch(l.cfg.Source, l.cfg.Fetch)
	if err != nil {
		log.Printf("[SUB] refresh fetch failed: %v (keep old)", err)
		return err
	}
	app, err := Apply(doc)
	if err != nil {
		log.Printf("[SUB] refresh apply failed: %v (keep old)", err)
		return err
	}
	key := app.SnapshotKey()
	if key == l.lastKey {
		log.Printf("[SUB] refresh: unchanged")
		return nil
	}
	if err := l.cfg.OnChange(app); err != nil {
		log.Printf("[SUB] refresh onChange failed: %v (keep old)", err)
		return err
	}
	l.lastKey = key
	if len(doc.Servers) > 0 {
		log.Printf("[SUB] refreshed primary=%s servers=%d", doc.Servers[0].Address, len(doc.Servers))
	}
	return nil
}
