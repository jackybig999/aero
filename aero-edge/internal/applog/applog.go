// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package applog 提供结构化日志输出，支持文本/JSON格式和文件输出。
// 作为标准库 log 的薄包装，不改动任何业务代码中的 log.Printf 调用。
package applog

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Config 日志配置
type Config struct {
	FilePath string // 空 = stderr
	Format   string // "text" 或 "json"
}

var currentCloser io.Closer

// Init 初始化全局日志输出
// 默认行为与标准库一致（text 格式输出到 stderr），新增参数仅改变输出目标/格式
func Init(cfg Config) error {
	Close() // 关闭之前的日志文件

	var w io.Writer = os.Stderr
	if cfg.FilePath != "" {
		f, err := os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		w = f
		currentCloser = f
	}

	switch cfg.Format {
	case "json":
		log.SetOutput(&jsonWriter{w: w})
		log.SetFlags(0)
	case "text", "":
		log.SetOutput(w)
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	default:
		return fmt.Errorf("unsupported log format: %s", cfg.Format)
	}
	return nil
}

// Close 关闭当前日志文件（如果打开的是文件）
func Close() {
	if currentCloser != nil {
		currentCloser.Close()
		currentCloser = nil
	}
}

// jsonWriter 将标准库 log 的每一行输出包装为 JSON 对象
type jsonWriter struct {
	w  io.Writer
	mu sync.Mutex
}

func (j *jsonWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"level":     extractLevel(msg),
		"message":   msg,
		"service":   "aero-edge",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		// JSON 编码失败时回退到原始文本
		j.mu.Lock()
		defer j.mu.Unlock()
		return j.w.Write(p)
	}
	data = append(data, '\n')

	j.mu.Lock()
	defer j.mu.Unlock()
	_, err = j.w.Write(data)
	return len(p), err
}

func extractLevel(msg string) string {
	switch {
	case strings.Contains(msg, "[ERROR]") || strings.Contains(msg, "fatal") || strings.Contains(msg, "FATAL"):
		return "error"
	case strings.Contains(msg, "[WARN]") || strings.Contains(msg, "[WARNING]"):
		return "warn"
	case strings.Contains(msg, "[DEBUG]"):
		return "debug"
	default:
		return "info"
	}
}
