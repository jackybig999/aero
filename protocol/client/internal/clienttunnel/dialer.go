// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package clienttunnel

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aero-protocol/aero-ech/internal/gameqos"
	"github.com/aero-protocol/aero-ech/internal/split"
	"github.com/aero-protocol/aero-ech/internal/transport"
	protocol "github.com/aero-protocol/proto"
)

// AERODialer 跨平台统一 AERO 出站拨号器（实现 tun.Dialer 接口）
type AERODialer struct {
	cfg       Config
	cfgMu     sync.RWMutex
	split     *split.Engine
	streamID  atomic.Uint64
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
	aiContext sync.Map // contextID -> struct{}{}
}

// NewAERODialer 创建拨号器实例
func NewAERODialer(cfg Config, splitEng *split.Engine) *AERODialer {
	if splitEng == nil {
		splitEng = split.NewEngine()
	}
	return &AERODialer{
		cfg:   cfg,
		split: splitEng,
	}
}

// UpdateConfig 动态更新配置（如切节点、更新 Token）
func (d *AERODialer) UpdateConfig(cfg Config) {
	d.cfgMu.Lock()
	d.cfg = cfg
	d.cfgMu.Unlock()
	transport.GlobalSessionPool.Reset()
}

func (d *AERODialer) getConfig() Config {
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	return d.cfg
}

// DialTCP 出站 TCP 连接（根据分流规则选择直连或 AERO 隧道）
func (d *AERODialer) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// 1. 检查私有网段与本地环回 -> 直连
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			var dialer net.Dialer
			dialer.Timeout = 10 * time.Second
			return dialer.DialContext(ctx, "tcp", addr)
		}
		// 阻断 fake-ip 泄漏
		if v4 := ip.To4(); v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return nil, fmt.Errorf("refuse fake-ip %s", addr)
		}
	}

	cfg := d.getConfig()

	// 2. 检查智能分流
	if cfg.SplitEnabled && d.split != nil {
		strat := d.split.MatchDomain(host)
		if strat == split.DIRECT {
			var dialer net.Dialer
			dialer.Timeout = 10 * time.Second
			return dialer.DialContext(ctx, "tcp", addr)
		}
	}

	// 3. 走 AERO 隧道
	return d.openAEROStream(ctx, addr, protocol.StreamType_GENERAL, false)
}

// DialUDP 出站 UDP 连接
func (d *AERODialer) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return d.openAEROStream(ctx, addr, protocol.StreamType_UDP, true)
}

// openAEROStream 建立 AERO 协议流
func (d *AERODialer) openAEROStream(ctx context.Context, target string, defaultType protocol.StreamType, udp bool) (net.Conn, error) {
	cfg := d.getConfig()
	st := d.classifyTarget(target, defaultType, udp)

	// 1. 建立底层传输通道 (H2 CONNECT 或 QUIC)
	tunnel, err := d.dialTransport(ctx, target, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial transport: %w", err)
	}

	streamID := uint32(d.streamID.Add(1))

	// 2. AERO 协议握手
	_ = tunnel.SetDeadline(time.Now().Add(15 * time.Second))
	if err := d.handshake(tunnel, st, streamID, cfg.Token); err != nil {
		_ = tunnel.Close()
		return nil, fmt.Errorf("aero handshake: %w", err)
	}
	_ = tunnel.SetDeadline(time.Time{})

	// 3. AI 协议流头处理
	if st.StreamType == protocol.StreamType_AI {
		d.maybeSendAIHeader(tunnel, st, streamID)
	}

	// 4. 包装为 AERO 流连接
	return NewStreamConn(tunnel, streamID, target, udp, &d.bytesSent, &d.bytesRecv), nil
}

func (d *AERODialer) dialTransport(ctx context.Context, target string, cfg Config) (net.Conn, error) {
	_ = target
	return d.dialQUIC(ctx, cfg)
}

func (d *AERODialer) dialQUIC(ctx context.Context, cfg Config) (net.Conn, error) {
	qcfg := transport.DefaultQUICConfig(cfg.ServerAddress, cfg.SNIName)
	qcfg.TLSConfig = transport.BuildClientConfig(cfg.SNIName)
	qcfg.TLSConfig.NextProtos = []string{"h3"}

	client, err := transport.GlobalSessionPool.Get(ctx, qcfg)
	if err != nil {
		return nil, err
	}

	stream, err := client.OpenStreamAsync(ctx)
	if err != nil {
		// 流开启失败说明连接已失效，主动从池中剔除，下一次请求自动重建
		transport.GlobalSessionPool.Remove(cfg.ServerAddress)
		return nil, err
	}

	return &quicWrapper{stream: stream, client: client}, nil
}

type quicWrapper struct {
	stream io.ReadWriteCloser
	client *transport.QUICClient
	closed atomic.Bool
}

func (q *quicWrapper) Read(p []byte) (int, error)  { return q.stream.Read(p) }
func (q *quicWrapper) Write(p []byte) (int, error) { return q.stream.Write(p) }
func (q *quicWrapper) Close() error {
	if q.closed.Swap(true) {
		return nil
	}
	// 契约设计：仅关闭当前 Stream，绝对不关闭底层复用的持久 QUIC Client 会话！
	return q.stream.Close()
}
func (q *quicWrapper) LocalAddr() net.Addr  { return q.client.LocalAddr() }
func (q *quicWrapper) RemoteAddr() net.Addr { return q.client.RemoteAddr() }
func (q *quicWrapper) SetDeadline(t time.Time) error {
	if s, ok := q.stream.(interface{ SetDeadline(time.Time) error }); ok {
		return s.SetDeadline(t)
	}
	return nil
}
func (q *quicWrapper) SetReadDeadline(t time.Time) error {
	if s, ok := q.stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		return s.SetReadDeadline(t)
	}
	return nil
}
func (q *quicWrapper) SetWriteDeadline(t time.Time) error {
	if s, ok := q.stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return s.SetWriteDeadline(t)
	}
	return nil
}

func (d *AERODialer) handshake(tunnel net.Conn, st streamTarget, streamID uint32, token string) error {
	req := &protocol.ConnectRequest{
		Version:      "aero/2.0",
		Token:        token,
		Nonce:        generateNonce(),
		Timestamp:    uint64(time.Now().UnixMilli()),
		UdpAvailable: true,
		Streams: []*protocol.StreamSpec{{
			StreamId:   streamID,
			StreamType: st.StreamType,
			TargetHost: st.Host,
			TargetPort: st.Port,
		}},
	}
	if err := protocol.WriteMessage(tunnel, req); err != nil {
		return fmt.Errorf("write ConnectRequest: %w", err)
	}

	var resp protocol.ConnectResponse
	if err := protocol.ReadMessage(tunnel, &resp); err != nil {
		return fmt.Errorf("read ConnectResponse: %w", err)
	}
	if !resp.Accepted {
		return fmt.Errorf("connect rejected by edge: %s", resp.Message)
	}
	return nil
}

func (d *AERODialer) maybeSendAIHeader(tunnel net.Conn, st streamTarget, streamID uint32) {
	ctxID := fmt.Sprintf("ai_%s_%d", st.Host, time.Now().Unix()/300)
	_, already := d.aiContext.Load(ctxID)
	if !already {
		d.aiContext.Store(ctxID, struct{}{})
	}
	header := &protocol.AiStreamHeader{
		StreamId:  streamID,
		ModelName: inferModelName(st.Host),
		ContextId: ctxID,
		Resume:    already,
	}
	_ = protocol.TypedWriteMessage(tunnel, protocol.MsgTypeAiStreamHeader, header)
}

type streamTarget struct {
	Raw        string
	Host       string
	Port       uint32
	StreamType protocol.StreamType
}

func (d *AERODialer) classifyTarget(raw string, defaultType protocol.StreamType, udp bool) streamTarget {
	st := streamTarget{Raw: raw, StreamType: defaultType}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		st.Host = raw
		return st
	}
	st.Host = host
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	st.Port = uint32(port)

	if udp && gameqos.IsGameTraffic(raw, port) {
		st.StreamType = protocol.StreamType_UDP
		return st
	}
	if isAITraffic(host) {
		st.StreamType = protocol.StreamType_AI
	}
	return st
}

func generateNonce() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		ts := time.Now().UnixNano()
		for i := 0; i < 8 && i < len(b); i++ {
			b[i] = byte(ts >> (i * 8))
		}
	}
	return b
}

func isAITraffic(host string) bool {
	aiDomains := []string{
		"openai.com", "api.openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
		"anthropic.com", "claude.ai", "api.anthropic.com",
		"gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
		"copilot.microsoft.com",
		"api.groq.com", "groq.com", "api.perplexity.ai", "perplexity.ai", "api.cohere.ai", "cohere.com",
		"api.together.xyz", "together.xyz", "together.ai", "api.mistral.ai", "mistral.ai", "api.replicate.com", "replicate.com",
		"api.deepseek.com", "deepseek.com", "platform.moonshot.cn", "api.siliconflow.cn", "siliconflow.cn",
		"api.qwen.ai", "api.baichuan-ai.com", "api.minimax.chat",
		"api.sparkdesk.cn", "huggingface.co", "api-inference.huggingface.co",
		"openrouter.ai", "api.fireworks.ai", "fireworks.ai",
		"cursor.com", "cursor.sh", "poe.com", "midjourney.com",
	}
	hostLower := strings.ToLower(host)
	for _, d := range aiDomains {
		if strings.HasSuffix(hostLower, d) || hostLower == d || strings.Contains(hostLower, d) {
			return true
		}
	}
	return false
}

func inferModelName(host string) string {
	switch {
	case strings.Contains(host, "openai.com") || strings.Contains(host, "chatgpt.com"):
		return "openai-gpt"
	case strings.Contains(host, "anthropic.com") || strings.Contains(host, "claude.ai"):
		return "anthropic-claude"
	case strings.Contains(host, "gemini.google.com") || strings.Contains(host, "generativelanguage"):
		return "google-gemini"
	case strings.Contains(host, "groq.com"):
		return "groq-llama"
	case strings.Contains(host, "deepseek.com"):
		return "deepseek-chat"
	case strings.Contains(host, "cursor"):
		return "cursor-ai"
	case strings.Contains(host, "perplexity"):
		return "perplexity"
	default:
		return "ai-service"
	}
}
