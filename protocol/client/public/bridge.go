// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package bridge 实现 Go 客户端与 Rust Core 的 Bridge 通信。
//
// 协议：4 字节大端长度 + JSON payload
// 职责：Go 只上报"发生了什么"，接收 Rust 返回的"该怎么做"
package public

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const defaultAddr = "127.0.0.1:19876"

const (
	maxRetries = 3
	baseDelay  = 500 * time.Millisecond
	maxDelay   = 5 * time.Second
)

// backoffDelay 计算指数退避延迟
func backoffDelay(attempt int) time.Duration {
	d := baseDelay * time.Duration(1<<attempt)
	if d > maxDelay {
		return maxDelay
	}
	return d
}

// Client Bridge 客户端
type BridgeClient struct {
	addr    string
	conn    net.Conn
	mu      sync.Mutex
	maxSize int
}

// NewClient 创建 Bridge 客户端
func NewBridgeClient(addr string) *BridgeClient {
	if addr == "" {
		addr = defaultAddr
	}
	return &BridgeClient{
		addr:    addr,
		maxSize: 64 * 1024,
	}
}

// Connect 连接到 Rust Bridge 服务器（带指数退避重试）
func (c *BridgeClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return nil
	}
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoffDelay(attempt - 1))
		}
		conn, err := net.DialTimeout("tcp", c.addr, 3*time.Second)
		if err == nil {
			c.conn = conn
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("dial bridge %s after %d attempts: %w", c.addr, maxRetries, lastErr)
}

// Close 关闭连接
func (c *BridgeClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// SendStreamOpened AI/其他流建立时上报
func (c *BridgeClient) SendStreamOpened(sessionID string, streamID uint32, targetHost string, targetPort uint16, streamType string, protocol string) (*StreamDecision, error) {
	msg := map[string]interface{}{
		"msg_type":     "stream_opened",
		"session_id":   sessionID,
		"stream_id":    streamID,
		"target_host":  targetHost,
		"target_port":  targetPort,
		"stream_type":  streamType,
		"protocol":     protocol,
		"timestamp_ms": time.Now().UnixMilli(),
	}
	resp, err := c.sendAndReceive(msg)
	if err != nil {
		return nil, err
	}
	return parseStreamDecision(resp)
}

// SendFirstToken 首字节到达时上报
func (c *BridgeClient) SendFirstToken(sessionID string, streamID uint32, latencyMs uint64, modelName string) (*StreamDecision, error) {
	msg := map[string]interface{}{
		"msg_type":   "first_token",
		"session_id": sessionID,
		"stream_id":  streamID,
		"latency_ms": latencyMs,
		"model_name": modelName,
	}
	resp, err := c.sendAndReceive(msg)
	if err != nil {
		return nil, err
	}
	return parseStreamDecision(resp)
}

// SendHeartbeat 心跳
func (c *BridgeClient) SendHeartbeat(sessionID string, sequence uint32) (*HeartbeatAck, error) {
	msg := map[string]interface{}{
		"msg_type":     "heartbeat",
		"session_id":   sessionID,
		"timestamp_ms": time.Now().UnixMilli(),
		"sequence":     sequence,
	}
	resp, err := c.sendAndReceive(msg)
	if err != nil {
		return nil, err
	}
	return parseHeartbeatAck(resp)
}

// SendMetrics 指标上报
func (c *BridgeClient) SendMetrics(sessionID string, rttMs, jitterMs uint32, lossRate float32, bytesSent, bytesRecv uint64) error {
	msg := map[string]interface{}{
		"msg_type":   "metrics",
		"session_id": sessionID,
		"rtt_ms":     rttMs,
		"jitter_ms":  jitterMs,
		"loss_rate":  lossRate,
		"bytes_sent": bytesSent,
		"bytes_recv": bytesRecv,
	}
	_, err := c.sendAndReceive(msg)
	return err
}

// SendStreamClosed 流关闭时上报（单向，不等待响应）
func (c *BridgeClient) SendStreamClosed(sessionID string, streamID uint32, bytesSent, bytesRecv uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil // 连接已关闭，静默忽略
	}
	msg := map[string]interface{}{
		"msg_type":   "stream_closed",
		"session_id": sessionID,
		"stream_id":  streamID,
		"bytes_sent": bytesSent,
		"bytes_recv": bytesRecv,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return writeFrame(c.conn, data)
}

// 内部：发送消息并等待响应（带指数退避重试）
//
// 重试策略：
// - 连接失败、写失败、读失败时自动重试最多 3 次
// - 每次重试前指数退避等待（500ms → 1s → 2s，封顶 5s）
// - JSON 序列化/反序列化错误不触发重试（数据问题无法通过重试解决）
func (c *BridgeClient) sendAndReceive(msg map[string]interface{}) (map[string]interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 序列化 JSON（在锁外做更好，但当前架构保持简单）
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			c.mu.Unlock()
			time.Sleep(backoffDelay(attempt - 1))
			c.mu.Lock()
			// 重试前关闭旧连接，强制重新 dial
			if c.conn != nil {
				c.conn.Close()
				c.conn = nil
			}
		}

		if c.conn == nil {
			conn, err := net.DialTimeout("tcp", c.addr, 3*time.Second)
			if err != nil {
				lastErr = err
				continue
			}
			c.conn = conn
		}

		if err := writeFrame(c.conn, data); err != nil {
			c.conn.Close()
			c.conn = nil
			lastErr = err
			continue
		}

		respData, err := readFrame(c.conn, c.maxSize)
		if err != nil {
			c.conn.Close()
			c.conn = nil
			lastErr = err
			continue
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(respData, &resp); err != nil {
			return nil, fmt.Errorf("unmarshal: %w", err)
		}
		return resp, nil
	}

	return nil, fmt.Errorf("sendAndReceive failed after %d attempts: %w", maxRetries, lastErr)
}

func writeFrame(conn net.Conn, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func readFrame(conn net.Conn, maxSize int) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length == 0 || int(length) > maxSize {
		return nil, fmt.Errorf("invalid frame size: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// StreamDecision Rust 返回的流决策
type StreamDecision struct {
	SessionID string            `json:"session_id"`
	StreamID  uint32            `json:"stream_id"`
	Action    string            `json:"action"`
	Params    map[string]string `json:"params"`
}

func parseStreamDecision(resp map[string]interface{}) (*StreamDecision, error) {
	if resp["msg_type"] != "stream_decision" {
		return nil, fmt.Errorf("unexpected response type: %v", resp["msg_type"])
	}
	sid, _ := resp["session_id"].(string)
	action, _ := resp["action"].(string)
	var streamID uint32
	if v, ok := resp["stream_id"].(float64); ok {
		streamID = uint32(v)
	}
	params := make(map[string]string)
	if p, ok := resp["params"].(map[string]interface{}); ok {
		for k, v := range p {
			if s, ok := v.(string); ok {
				params[k] = s
			}
		}
	}
	return &StreamDecision{
		SessionID: sid,
		StreamID:  streamID,
		Action:    action,
		Params:    params,
	}, nil
}

// HeartbeatAck 心跳确认
type HeartbeatAck struct {
	SessionID   string `json:"session_id"`
	Sequence    uint32 `json:"sequence"`
	TimestampMs uint64 `json:"timestamp_ms"`
}

func parseHeartbeatAck(resp map[string]interface{}) (*HeartbeatAck, error) {
	if resp["msg_type"] != "heartbeat_ack" {
		return nil, fmt.Errorf("unexpected response type: %v", resp["msg_type"])
	}
	sid, _ := resp["session_id"].(string)
	var seq uint32
	if v, ok := resp["sequence"].(float64); ok {
		seq = uint32(v)
	}
	var ts uint64
	if v, ok := resp["timestamp_ms"].(float64); ok {
		ts = uint64(v)
	}
	return &HeartbeatAck{SessionID: sid, Sequence: seq, TimestampMs: ts}, nil
}

// bridge namespace compatibility wrapper
var bridge = struct {
	NewClient func(string) *BridgeClient
}{
	NewClient: NewBridgeClient,
}
