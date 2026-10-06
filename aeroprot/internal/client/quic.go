// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

var (
	// CurrentMaxDatagramSize 动态最大数据报载荷（初始 1336，对齐 Next-MTU 1360）
	CurrentMaxDatagramSize atomic.Int32

	mtuSetterMu     sync.RWMutex
	globalMTUSetter func(mtu int) error

	pinsMu  sync.RWMutex
	pinsSet = make(map[string]struct{})

	globalSessionCache = tls.NewLRUClientSessionCache(128)

	factoryMu               sync.RWMutex
	globalPacketConnFactory PacketConnFactory
)

func init() {
	CurrentMaxDatagramSize.Store(1336)
}

// GetCurrentMaxDatagramSize 获取当前最大数据报有效载荷大小
func GetCurrentMaxDatagramSize() int {
	sz := int(CurrentMaxDatagramSize.Load())
	if sz <= 0 {
		return 1336
	}
	return sz
}

// SetCurrentMaxDatagramSize 更新当前最大数据报有效载荷大小
func SetCurrentMaxDatagramSize(sz int) {
	if sz > 0 {
		CurrentMaxDatagramSize.Store(int32(sz))
	}
}

// RegisterVirtualNICMTUSetter 注册虚拟网卡动态 MTU 设置回调
func RegisterVirtualNICMTUSetter(setter func(mtu int) error) {
	mtuSetterMu.Lock()
	defer mtuSetterMu.Unlock()
	globalMTUSetter = setter
}

// SetVirtualNICMTU 动态调用虚拟网卡 MTU 设置器
func SetVirtualNICMTU(mtu int) {
	mtuSetterMu.RLock()
	setter := globalMTUSetter
	mtuSetterMu.RUnlock()
	if setter != nil {
		if err := setter(mtu); err != nil {
			log.Printf("[QUIC] dynamic update virtual NIC MTU=%d failed: %v", mtu, err)
		} else {
			log.Printf("[QUIC] dynamic updated virtual NIC MTU=%d", mtu)
		}
	}
}

// PacketConnFactory 物理底层 UDP Socket 工厂函数
type PacketConnFactory func(ctx context.Context, network string) (net.PacketConn, error)

// SetPacketConnFactory 注册底层物理接口绑定的 UDP Socket 工厂
func SetPacketConnFactory(f PacketConnFactory) {
	factoryMu.Lock()
	defer factoryMu.Unlock()
	globalPacketConnFactory = f
}

// AddPins 添加 SPKI 钉扎
func AddPins(pins ...string) {
	pinsMu.Lock()
	defer pinsMu.Unlock()
	for _, p := range pins {
		p = strings.TrimSpace(p)
		if p != "" {
			pinsSet[p] = struct{}{}
		}
	}
}

// ClearPins 清空 SPKI 钉扎
func ClearPins() {
	pinsMu.Lock()
	defer pinsMu.Unlock()
	pinsSet = make(map[string]struct{})
}

// CertSPKI 计算证书 RawSubjectPublicKeyInfo 的 SHA-256 Base64
func CertSPKI(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// MakeVerifyPeerCertificate 构造严格证书校验器：
// 1. 系统根证书先校验（若上层未构建 verifiedChains 则强制执行系统根证书链校验）；
// 2. 系统根证书校验通过后，若配置了 SPKI 钉扎，进一步核对 SPKI 钉扎；
// 3. 两者均满足才放行。
func MakeVerifyPeerCertificate(serverName string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("tls: no certificates presented by peer")
		}

		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("tls: failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		leaf := certs[0]

		// 1. 系统根证书先校验
		if len(verifiedChains) == 0 {
			opts := x509.VerifyOptions{
				DNSName:       serverName,
				Intermediates: x509.NewCertPool(),
			}
			for i := 1; i < len(certs); i++ {
				opts.Intermediates.AddCert(certs[i])
			}
			var err error
			verifiedChains, err = leaf.Verify(opts)
			if err != nil {
				return fmt.Errorf("tls: system CA verification failed: %w", err)
			}
		}

		// 2. 核对 SPKI 钉扎
		pinsMu.RLock()
		hasPins := len(pinsSet) > 0
		if hasPins {
			leafSPKI := CertSPKI(leaf)
			_, ok := pinsSet[leafSPKI]
			pinsMu.RUnlock()
			if !ok {
				return fmt.Errorf("tls: SPKI pin mismatch for %s", serverName)
			}
			return nil
		}
		pinsMu.RUnlock()

		return nil
	}
}

// TransportConfig QUIC 传输配置
type TransportConfig struct {
	Address           string
	TLSServerName     string
	TLSConfig         *tls.Config
	Enable0RTT        bool
	MaxStreams        int64
	IdleTimeout       time.Duration
	ConnectTimeout    time.Duration
	RemoteUDPAddr     *net.UDPAddr      // 已解析物理目标地址，避免二次裸查
	PacketConnFactory PacketConnFactory // 可选针对单次传输定制的底层工厂
	ECHConfigList     []byte            // 仅在订阅或配置显式携带 ECH 配置列表时生效
	ObfsPassword      string
	PaddingJitter     bool
	AltPorts          []int // 多端口跳频备选端口 (Multi-port Hopping)
}

var (
	quicDialHookMu sync.RWMutex
	quicDialHook   func(ctx context.Context, pconn net.PacketConn, remoteAddr net.Addr, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error)
)

// SetQUICDialHook 允许单元测试注入自定义 QUIC 拨号逻辑 (如模拟 UDP 阻断)
func SetQUICDialHook(fn func(ctx context.Context, pconn net.PacketConn, remoteAddr net.Addr, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error)) {
	quicDialHookMu.Lock()
	defer quicDialHookMu.Unlock()
	quicDialHook = fn
}

// DefaultTransportConfig 构造默认传输配置，锁定物理域名 SNI
func DefaultTransportConfig(addr, sni string) *TransportConfig {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil && h != "" {
		host = h
	}
	// 方案 A：物理域名 SNI 锁死为节点真实 host，杜绝伪装 SNI 破坏 TLS 链
	if net.ParseIP(host) == nil && host != "" {
		sni = host
	}

	return &TransportConfig{
		Address:        addr,
		TLSServerName:  sni,
		Enable0RTT:     false,
		MaxStreams:     100,
		IdleTimeout:    90 * time.Second,
		ConnectTimeout: 10 * time.Second,
	}
}

// defaultTLSConfig 构造默认 TLS 配置（生产强制严格验证证书）
func defaultTLSConfig(serverName string) *tls.Config {
	cfg := &tls.Config{
		ServerName:            serverName,
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{"h3"},
		ClientSessionCache:    globalSessionCache,
		InsecureSkipVerify:    false, // 显式设为 false，禁止跳过系统根证书校验
		VerifyPeerCertificate: MakeVerifyPeerCertificate(serverName),
	}
	return cfg
}

// Client QUIC 连接客户端
type Client struct {
	conn       *quic.Conn
	config     *TransportConfig
	actualPort int
	lastActive atomic.Int64
}

// ActualPort 返回当前连接实际建立的物理端口
func (c *Client) ActualPort() int {
	if c == nil {
		return 0
	}
	return c.actualPort
}

// Dial 建立 QUIC 连接
func Dial(ctx context.Context, cfg *TransportConfig) (*Client, error) {
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = defaultTLSConfig(cfg.TLSServerName)
	}

	// 客户端仅在订阅或配置显式携带 ECH 配置列表时，才设置 EncryptedClientHelloConfigList
	if len(cfg.ECHConfigList) > 0 {
		cfg.TLSConfig.EncryptedClientHelloConfigList = cfg.ECHConfigList
	}

	quicConfig := &quic.Config{
		MaxIncomingStreams:             cfg.MaxStreams,
		MaxIncomingUniStreams:          cfg.MaxStreams,
		HandshakeIdleTimeout:           cfg.ConnectTimeout,
		MaxIdleTimeout:                 cfg.IdleTimeout,
		Allow0RTT:                      cfg.Enable0RTT,
		EnableDatagrams:                true,
		DisablePathMTUDiscovery:        false,
		KeepAlivePeriod:                10 * time.Second,
		InitialStreamReceiveWindow:     16 * 1024 * 1024,
		MaxStreamReceiveWindow:         32 * 1024 * 1024,
		InitialConnectionReceiveWindow: 32 * 1024 * 1024,
		MaxConnectionReceiveWindow:     64 * 1024 * 1024,
		InitialPacketSize:              0,
	}

	factory := cfg.PacketConnFactory
	if factory == nil {
		factoryMu.RLock()
		factory = globalPacketConnFactory
		factoryMu.RUnlock()
	}

	if factory == nil {
		return nil, fmt.Errorf("physical packet conn factory not registered")
	}
	pconn, perr := factory(ctx, "udp4")
	if perr != nil {
		return nil, fmt.Errorf("factory physical packet conn: %w", perr)
	}

	if cfg.RemoteUDPAddr == nil {
		_ = pconn.Close()
		return nil, fmt.Errorf("RemoteUDPAddr is required for quic dial %s", cfg.Address)
	}
	udpAddr := cfg.RemoteUDPAddr

	if cfg.ObfsPassword != "" {
		pconn = NewSalamanderPacketConn(pconn, cfg.ObfsPassword, cfg.PaddingJitter)
	}

	actualPort := 0
	if udpAddr != nil {
		actualPort = udpAddr.Port
	}

	quicDialHookMu.RLock()
	hook := quicDialHook
	quicDialHookMu.RUnlock()
	if hook != nil {
		conn, err := hook(ctx, pconn, udpAddr, cfg.TLSConfig, quicConfig)
		if err != nil && len(cfg.AltPorts) > 0 && udpAddr != nil {
			for _, altPort := range cfg.AltPorts {
				if altPort <= 0 || altPort == udpAddr.Port {
					continue
				}
				altAddr := &net.UDPAddr{IP: udpAddr.IP, Port: altPort, Zone: udpAddr.Zone}
				altConn, aerr := hook(ctx, pconn, altAddr, cfg.TLSConfig, quicConfig)
				if aerr == nil {
					conn = altConn
					err = nil
					actualPort = altPort
					log.Printf("[QUIC] Multi-port hopping (hook): primary port %d failed, connected via alt port %d", udpAddr.Port, altPort)
					cfg.RemoteUDPAddr.Port = altPort
					host, _, splitErr := net.SplitHostPort(cfg.Address)
					if splitErr == nil {
						cfg.Address = net.JoinHostPort(host, strconv.Itoa(altPort))
					}
					break
				}
			}
		}
		if err != nil {
			_ = pconn.Close()
			return nil, fmt.Errorf("quic dial %s: %w", cfg.Address, err)
		}
		client := &Client{
			conn:       conn,
			config:     cfg,
			actualPort: actualPort,
		}
		client.lastActive.Store(time.Now().UnixMilli())
		return client, nil
	}

	var conn *quic.Conn
	var err error
	if cfg.Enable0RTT {
		conn, err = quic.DialEarly(ctx, pconn, udpAddr, cfg.TLSConfig, quicConfig)
	} else {
		conn, err = quic.Dial(ctx, pconn, udpAddr, cfg.TLSConfig, quicConfig)
	}
	if err != nil && len(cfg.AltPorts) > 0 && udpAddr != nil {
		for _, altPort := range cfg.AltPorts {
			if altPort <= 0 || altPort == udpAddr.Port {
				continue
			}
			altAddr := &net.UDPAddr{IP: udpAddr.IP, Port: altPort, Zone: udpAddr.Zone}
			var altConn *quic.Conn
			var aerr error
			if cfg.Enable0RTT {
				altConn, aerr = quic.DialEarly(ctx, pconn, altAddr, cfg.TLSConfig, quicConfig)
			} else {
				altConn, aerr = quic.Dial(ctx, pconn, altAddr, cfg.TLSConfig, quicConfig)
			}
			if aerr == nil {
				conn = altConn
				err = nil
				actualPort = altPort
				log.Printf("[QUIC] Multi-port hopping: primary port %d failed, connected via alt port %d", udpAddr.Port, altPort)
				cfg.RemoteUDPAddr.Port = altPort
				host, _, splitErr := net.SplitHostPort(cfg.Address)
				if splitErr == nil {
					cfg.Address = net.JoinHostPort(host, strconv.Itoa(altPort))
				}
				break
			}
		}
	}
	if err != nil {
		_ = pconn.Close()
		return nil, fmt.Errorf("quic dial %s: %w", cfg.Address, err)
	}

	client := &Client{
		conn:       conn,
		config:     cfg,
		actualPort: actualPort,
	}
	client.lastActive.Store(time.Now().UnixMilli())
	return client, nil
}

// Conn returns the underlying quic.Conn.
func (c *Client) Conn() *quic.Conn {
	if c == nil {
		return nil
	}
	return c.conn
}

// Stream 统一流接口
type Stream interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// OpenStream 打开双向流
func (c *Client) OpenStream(ctx context.Context) (Stream, error) {
	if c == nil || c.conn == nil {
		return nil, errors.New("client connection closed")
	}
	c.lastActive.Store(time.Now().UnixMilli())
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	return &quicStreamWrapper{stream: stream}, nil
}

// SendDatagram 发送数据报并捕获 DatagramTooLargeError
func (c *Client) SendDatagram(payload []byte) error {
	if c == nil || c.conn == nil {
		return errors.New("client connection closed")
	}
	c.lastActive.Store(time.Now().UnixMilli())
	maxSize := GetCurrentMaxDatagramSize()
	if len(payload) > maxSize {
		return fmt.Errorf("datagram size %d exceeds max %d", len(payload), maxSize)
	}

	err := c.conn.SendDatagram(payload)
	if err != nil {
		var dtle *quic.DatagramTooLargeError
		if errors.As(err, &dtle) {
			newSize := int(dtle.MaxDatagramPayloadSize)
			if newSize > 0 && newSize < maxSize {
				SetCurrentMaxDatagramSize(newSize)
				SetVirtualNICMTU(newSize + 24)
			}
		}
		return err
	}
	return nil
}

// ReceiveDatagram 接收数据报
func (c *Client) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if c == nil || c.conn == nil {
		return nil, errors.New("client connection closed")
	}
	c.lastActive.Store(time.Now().UnixMilli())
	return c.conn.ReceiveDatagram(ctx)
}

// Close 关闭连接
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.CloseWithError(0, "client closed")
	}
	return nil
}

// LocalAddr 本地地址
func (c *Client) LocalAddr() net.Addr {
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	return nil
}

// RemoteAddr 远程地址
func (c *Client) RemoteAddr() net.Addr {
	if c.conn != nil {
		return c.conn.RemoteAddr()
	}
	return nil
}

type quicStreamWrapper struct {
	stream *quic.Stream
}

func (s *quicStreamWrapper) Read(p []byte) (int, error)  { return s.stream.Read(p) }
func (s *quicStreamWrapper) Write(p []byte) (int, error) { return s.stream.Write(p) }
func (s *quicStreamWrapper) Close() error                { return s.stream.Close() }

func (s *quicStreamWrapper) SetDeadline(t time.Time) error {
	return s.stream.SetDeadline(t)
}
func (s *quicStreamWrapper) SetReadDeadline(t time.Time) error {
	return s.stream.SetReadDeadline(t)
}
func (s *quicStreamWrapper) SetWriteDeadline(t time.Time) error {
	return s.stream.SetWriteDeadline(t)
}

// ISessionPool 会话池抽象接口
type ISessionPool interface {
	Get(ctx context.Context, cfg *TransportConfig) (*Client, error)
	Remove(addr string)
	Reset()
}

// SessionPool 维护多路复用连接池
type SessionPool struct {
	mu      sync.Mutex
	clients map[string]*Client
}

// GlobalSessionPool 全局会话池
var GlobalSessionPool = NewSessionPool()

// NewSessionPool 创建会话池
func NewSessionPool() *SessionPool {
	return &SessionPool{clients: make(map[string]*Client)}
}

// Get 获取可用客户端或创建新连接
func (p *SessionPool) Get(ctx context.Context, cfg *TransportConfig) (*Client, error) {
	p.mu.Lock()
	c, ok := p.clients[cfg.Address]
	if ok && c != nil && c.conn != nil && c.conn.Context().Err() == nil {
		p.mu.Unlock()
		return c, nil
	}
	if ok && c != nil {
		_ = c.Close()
		delete(p.clients, cfg.Address)
	}
	p.mu.Unlock()

	origAddr := cfg.Address
	newClient, err := Dial(ctx, cfg)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if origAddr != cfg.Address {
		delete(p.clients, origAddr)
	}
	if existing, ok := p.clients[cfg.Address]; ok && existing != nil && existing.conn != nil && existing.conn.Context().Err() == nil {
		_ = newClient.Close()
		return existing, nil
	}
	if old, ok := p.clients[cfg.Address]; ok && old != nil {
		_ = old.Close()
	}
	p.clients[cfg.Address] = newClient
	return newClient, nil
}

// Remove 仅在底层物理连接彻底损坏断开时移除
func (p *SessionPool) Remove(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[addr]; ok {
		if c != nil {
			_ = c.Close()
		}
		delete(p.clients, addr)
	}
}

// Reset 清空会话池全部连接（切节点或断开时使用）
func (p *SessionPool) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, c := range p.clients {
		if c != nil {
			_ = c.Close()
		}
		delete(p.clients, addr)
	}
}

// DrainGraceful 平滑排空全部客户端连接（旧客户端在超时后真正关闭，锁不覆盖超时时间）
func (p *SessionPool) DrainGraceful(drainTimeout time.Duration) {
	p.mu.Lock()
	oldClients := make([]*Client, 0, len(p.clients))
	for addr, c := range p.clients {
		if c != nil {
			oldClients = append(oldClients, c)
		}
		delete(p.clients, addr)
	}
	p.mu.Unlock()

	if len(oldClients) > 0 {
		time.AfterFunc(drainTimeout, func() {
			for _, c := range oldClients {
				_ = c.Close()
			}
		})
	}
}
