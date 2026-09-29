// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package quic 实现 QUIC 传输层，支持多路复用、0-RTT、连接迁移。
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// TransportConfig QUIC 传输配置
type TransportConfig struct {
	Address             string
	TLSServerName       string
	TLSConfig           *tls.Config
	Enable0RTT          bool
	ConnectionMigration bool // 启用连接迁移（WiFi↔4G 切换不断连）
	MaxStreams          int64
	IdleTimeout         time.Duration
	ConnectTimeout      time.Duration
}

// DefaultConfig 返回默认 QUIC 配置
func DefaultConfig(addr, sni string) *TransportConfig {
	return &TransportConfig{
		Address:             addr,
		TLSServerName:       sni,
		Enable0RTT:          true,
		ConnectionMigration: true, // 默认启用连接迁移
		MaxStreams:          100,
		IdleTimeout:         30 * time.Second,
		ConnectTimeout:      10 * time.Second,
	}
}

// PacketConnFactory creates a net.PacketConn for QUIC outbounds (e.g. pinned to physical NIC)
type PacketConnFactory func(ctx context.Context, network string) (net.PacketConn, error)

var (
	globalPacketConnFactory PacketConnFactory
	factoryMu               sync.RWMutex
)

// SetPacketConnFactory 注册底层物理接口绑定的 UDP Socket 工厂函数
func SetPacketConnFactory(f PacketConnFactory) {
	factoryMu.Lock()
	defer factoryMu.Unlock()
	globalPacketConnFactory = f
}

// Client QUIC 客户端
type Client struct {
	conn       *quic.Conn
	stream     *quic.Stream
	config     *TransportConfig
	lastActive atomic.Int64 // unix milli
}

var (
	globalSessionCache = tls.NewLRUClientSessionCache(128)
)

// defaultTLSConfig 构造默认 QUIC TLS 配置，若全局 CA 池已设置则启用验证
func defaultTLSConfig(serverName string) *tls.Config {
	cfg := &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3"},
		ClientSessionCache: globalSessionCache,
		InsecureSkipVerify: true,
	}
	if pool := RootCAs(); pool != nil {
		cfg.RootCAs = pool
		cfg.InsecureSkipVerify = false
	}
	return cfg
}

// Dial 建立 QUIC 连接
func Dial(ctx context.Context, cfg *TransportConfig) (*Client, error) {
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = defaultTLSConfig(cfg.TLSServerName)
	}

	quicConfig := &quic.Config{
		MaxIncomingStreams:      cfg.MaxStreams,
		MaxIncomingUniStreams:   cfg.MaxStreams,
		HandshakeIdleTimeout:    cfg.ConnectTimeout,
		MaxIdleTimeout:          cfg.IdleTimeout,
		Allow0RTT:               cfg.Enable0RTT,
		EnableDatagrams:         true,             // DATAGRAM 扩展（用于 UDP 转发）
		DisablePathMTUDiscovery: false,            // 连接迁移需要 PMTUD
		KeepAlivePeriod:         20 * time.Second, // 20s 强制保活心跳，彻底防止路由器 NAT 状态表超时老化断流
		InitialPacketSize:       1350,             // 限制单包尺寸，杜绝跨洋公网 IP 分片丢包
	}

	var pconn net.PacketConn
	factoryMu.RLock()
	factory := globalPacketConnFactory
	factoryMu.RUnlock()

	if factory != nil {
		if pc, perr := factory(ctx, "udp4"); perr == nil {
			pconn = pc
		}
	}

	var conn *quic.Conn
	var err error
	if pconn != nil {
		udpAddr, rerr := net.ResolveUDPAddr("udp", cfg.Address)
		if rerr != nil {
			_ = pconn.Close()
			return nil, fmt.Errorf("resolve quic addr %s: %w", cfg.Address, rerr)
		}
		if cfg.Enable0RTT {
			conn, err = quic.DialEarly(ctx, pconn, udpAddr, cfg.TLSConfig, quicConfig)
		} else {
			conn, err = quic.Dial(ctx, pconn, udpAddr, cfg.TLSConfig, quicConfig)
		}
		if err != nil {
			_ = pconn.Close()
			return nil, fmt.Errorf("quic dial %s: %w", cfg.Address, err)
		}
	} else {
		if cfg.Enable0RTT {
			conn, err = quic.DialAddrEarly(ctx, cfg.Address, cfg.TLSConfig, quicConfig)
		} else {
			conn, err = quic.DialAddr(ctx, cfg.Address, cfg.TLSConfig, quicConfig)
		}
		if err != nil {
			return nil, fmt.Errorf("quic dial %s: %w", cfg.Address, err)
		}
	}

	client := &Client{
		conn:   conn,
		config: cfg,
	}
	client.lastActive.Store(time.Now().UnixMilli())
	return client, nil
}

// OpenStream 打开新的双向流（类似 TCP 连接）
func (c *Client) OpenStream() (io.ReadWriteCloser, error) {
	c.lastActive.Store(time.Now().UnixMilli())
	stream, err := c.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	return &streamWrapper{stream: stream}, nil
}

// OpenStreamAsync 异步打开流
func (c *Client) OpenStreamAsync(ctx context.Context) (io.ReadWriteCloser, error) {
	c.lastActive.Store(time.Now().UnixMilli())
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	return &streamWrapper{stream: stream}, nil
}

// LocalAddr 返回本地地址
func (c *Client) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr 返回远程地址
func (c *Client) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// ConnectionState 返回连接状态
func (c *Client) ConnectionState() quic.ConnectionState {
	return c.conn.ConnectionState()
}

// Close 关闭连接
func (c *Client) Close() error {
	return c.conn.CloseWithError(0, "client closed")
}

// Is0RTT 检查当前连接是否使用 0-RTT
func (c *Client) Is0RTT() bool {
	return c.conn.ConnectionState().Used0RTT
}

// streamWrapper 包装 quic.Stream 实现 io.ReadWriteCloser
type streamWrapper struct {
	stream *quic.Stream
}

func (s *streamWrapper) Read(p []byte) (int, error) {
	return s.stream.Read(p)
}

func (s *streamWrapper) Write(p []byte) (int, error) {
	return s.stream.Write(p)
}

func (s *streamWrapper) Close() error {
	return s.stream.Close()
}

func (s *streamWrapper) SetDeadline(t time.Time) error {
	return s.stream.SetDeadline(t)
}

func (s *streamWrapper) SetReadDeadline(t time.Time) error {
	return s.stream.SetReadDeadline(t)
}

func (s *streamWrapper) SetWriteDeadline(t time.Time) error {
	return s.stream.SetWriteDeadline(t)
}

// Server QUIC 服务端
type Server struct {
	listener *quic.Listener
	config   *quic.Config
}

// Listen 启动 QUIC 服务端监听
func Listen(addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (*Server, error) {
	if quicConfig == nil {
		quicConfig = &quic.Config{
			MaxIncomingStreams:    1000,
			MaxIncomingUniStreams: 1000,
			MaxIdleTimeout:        60 * time.Second,
			EnableDatagrams:       true,
		}
	}

	ln, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic listen %s: %w", addr, err)
	}

	return &Server{listener: ln, config: quicConfig}, nil
}

// Accept 接受新连接
func (s *Server) Accept(ctx context.Context) (*quic.Conn, error) {
	return s.listener.Accept(ctx)
}

// AcceptStream 从连接接受新流
func AcceptStream(ctx context.Context, conn *quic.Conn) (*quic.Stream, error) {
	return conn.AcceptStream(ctx)
}

// Close 关闭监听器
func (s *Server) Close() error {
	return s.listener.Close()
}

// Addr 返回监听地址
func (s *Server) Addr() net.Addr {
	return s.listener.Addr()
}

// DialWith0RTT 使用 0-RTT 快速重连（利用全局 Session Ticket 缓存）
func DialWith0RTT(ctx context.Context, cfg *TransportConfig, sessionTicket []byte) (*Client, error) {
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = defaultTLSConfig(cfg.TLSServerName)
	}
	cfg.Enable0RTT = true
	_ = sessionTicket
	return Dial(ctx, cfg)
}

// QUIC aliases exported for aeroTLS
type QUICClient = Client
type QUICTransportConfig = TransportConfig

func DefaultQUICConfig(addr, sni string) *TransportConfig {
	return DefaultConfig(addr, sni)
}

func DialQUIC(ctx context.Context, cfg *TransportConfig) (*Client, error) {
	return Dial(ctx, cfg)
}

// SessionPool maintains persistent QUIC connections per edge address for true HTTP/3 multiplexing.
type SessionPool struct {
	mu      sync.Mutex
	clients map[string]*Client
}

// GlobalSessionPool is the default session pool for the client.
var GlobalSessionPool = NewSessionPool()

// NewSessionPool creates a new QUIC session pool.
func NewSessionPool() *SessionPool {
	return &SessionPool{clients: make(map[string]*Client)}
}

// Get returns an existing live QUIC client or dials a new one using a deadlock-free double-checked pattern.
func (p *SessionPool) Get(ctx context.Context, cfg *TransportConfig) (*Client, error) {
	p.mu.Lock()
	c, ok := p.clients[cfg.Address]
	if ok && c != nil && c.conn != nil && c.conn.Context().Err() == nil {
		last := c.lastActive.Load()
		if last > 0 && time.Since(time.UnixMilli(last)) <= 45*time.Second {
			p.mu.Unlock()
			return c, nil
		}
		// 若距上次通信已超 45 秒（服务端空闲超时通常为 60s），判定为休眠挂起陈旧连接，主动剔除并重新极速建连
		_ = c.Close()
		delete(p.clients, cfg.Address)
	}
	p.mu.Unlock()

	// 锁外执行网络拨号，防止网络超时或握手阻塞互斥锁，杜绝并发死锁
	newClient, err := Dial(ctx, cfg)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// 双重检查：避免并发重复建连
	if existing, ok := p.clients[cfg.Address]; ok && existing != nil && existing.conn != nil && existing.conn.Context().Err() == nil {
		_ = newClient.Close() // 显式关闭竞争失败的冗余新建连接，规避泄漏
		return existing, nil
	}
	if old, ok := p.clients[cfg.Address]; ok && old != nil {
		_ = old.Close() // 显式清理旧的已失效连接
	}
	p.clients[cfg.Address] = newClient
	return newClient, nil
}

// Remove closes and removes a client from the pool (e.g. when a stream creation fails on a broken connection).
func (p *SessionPool) Remove(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[addr]; ok {
		if c != nil {
			_ = c.Close() // 显式释放剔除的失效连接
		}
		delete(p.clients, addr)
	}
}

// Reset closes and clears all pooled QUIC clients (e.g. on node switch or disconnect).
func (p *SessionPool) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, c := range p.clients {
		if c != nil {
			_ = c.Close() // 显式释放重置的连接
		}
		delete(p.clients, addr)
	}
}
