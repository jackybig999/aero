// AERO TUN 引擎：平台无关的数据流协调
//
// 职责：
//  1. 从 TUN 设备读取 IP 包
//  2. 解析包 → 查会话表/分流规则
//  3. DIRECT → 系统直接拨号
//  4. PROXY/AI → 封装为 AERO TcpFrame/UdpFrame
//
// TUN 引擎只做编排，不包含平台特定代码。
package tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

// Engine TUN 引擎（平台无关）
type Engine struct {
	device   Device        // 平台 TUN 设备
	sessions *SessionTable // 五元组会话表
	fakeIP   *FakeIPTable  // Fake-IP 映射
	dns      *DNSHandler   // DNS 劫持处理
	split    SplitDecider  // 分流决策器
	dialer   Dialer        // 出站拨号器
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	done     chan struct{}
	mtu      int
	gvEP     *channel.Endpoint
	gvStack  *stack.Stack
	udpSess  sync.Map
}

// Device 平台 TUN 设备接口（由各平台文件实现）
type Device interface {
	Read(p []byte) (int, error)  // 读取一个 IP 包
	Write(p []byte) (int, error) // 写入一个 IP 包
	Close() error
	Name() string
}

// SplitDecider 分流决策接口
type SplitDecider interface {
	Decide(domain string) string // 返回 "direct" | "proxy" | "ai"
}

// Dialer 出站拨号接口
type Dialer interface {
	DialTCP(ctx context.Context, addr string) (net.Conn, error)
	DialUDP(ctx context.Context, addr string) (net.Conn, error)
}

// Config TUN 引擎配置
type Config struct {
	MTU          int
	IPv4         string // CIDR
	IPv6         string // CIDR
	Routes       []string
	DNSServers   []string
	FakeIPRange  string // "198.18.0.0/15"
	FakeIPEnable bool
}

// DefaultConfig 返回默认配置
func DefaultConfig() Config {
	return Config{
		MTU:          1420,
		IPv4:         "10.88.0.2/24",
		IPv6:         "fd00:aero::2/64",
		Routes:       []string{"0.0.0.0/0", "::/0"},
		DNSServers:   []string{"223.5.5.5", "8.8.8.8"},
		FakeIPRange:  "198.18.0.0/15",
		FakeIPEnable: true,
	}
}

// New 创建 TUN 引擎
func New(dev Device, cfg Config, split SplitDecider, dialer Dialer) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{
		device:   dev,
		sessions: NewSessionTable(5 * time.Minute),
		fakeIP:   DefaultFakeIPTable,
		dns:      NewDNSHandler(cfg.DNSServers),
		split:    split,
		dialer:   dialer,
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
		mtu:      cfg.MTU,
	}
	if cfg.FakeIPEnable {
		e.dns.SetFakeIP(e.fakeIP)
	}
	e.dns.SetSplit(split)
	return e
}

// SetEdge 绑定当前激活 Edge 节点的公网域名与 IP，防止 DNS 拦截自回环
func (e *Engine) SetEdge(host string, ip net.IP) {
	if e.dns != nil {
		e.dns.SetEdge(host, ip)
	}
}

// Start runs the gVisor userspace stack until Stop. Homemade TCP reconstruct is unused.
func (e *Engine) Start() error {
	if err := e.startGvisor(); err != nil {
		close(e.done)
		return err
	}
	<-e.ctx.Done()
	close(e.done)
	waitWG(e, 400*time.Millisecond)
	e.destroyGvisor()
	return nil
}

// Stop signals the read loop. Device is closed by runtime. Do not wait for
// gVisor Destroy here — that blocked disconnect past the UI 8s fetch timeout.
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	select {
	case <-e.done:
	case <-time.After(400 * time.Millisecond):
		log.Printf("[TUN] engine stop: start loop still busy")
	}
	log.Printf("[TUN] Engine stopped")
}

func waitWG(e *Engine, d time.Duration) {
	ch := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(ch)
	}()
	select {
	case <-ch:
	case <-time.After(d):
		log.Printf("[TUN] engine stop: wait timed out (%s)", d)
	}
}

// handlePacket 处理单个 IP 包（历史自研重构实现，仅保留作为单元测试与离线模拟参考；生产环境由 gVisor 协议栈托管）
func (e *Engine) handlePacket(pkt []byte) {
	defer e.wg.Done()

	ipVer := (pkt[0] >> 4) & 0x0F
	switch ipVer {
	case 4:
		e.handleIPv4(pkt)
	case 6:
		e.handleIPv6(pkt)
	default:
		// 无法识别的 IP 版本，丢弃
	}
}

var tunPktN atomic.Uint64

func (e *Engine) handleIPv4(pkt []byte) {
	hdr, err := ParseIPv4Header(pkt)
	if err != nil {
		return
	}
	n := tunPktN.Add(1)
	if n <= 30 || n%200 == 0 {
		log.Printf("[TUN] pkt#%d proto=%d %s -> %s", n, hdr.Protocol, hdr.SrcIP, hdr.DstIP)
	}

	switch hdr.Protocol {
	case IPProtoTCP:
		e.handleTCP(pkt, &hdr)
	case IPProtoUDP:
		e.handleUDP(pkt, &hdr)
	}
}

func (e *Engine) handleIPv6(pkt []byte) {
	hdr, err := ParseIPv6Header(pkt)
	if err != nil {
		return
	}
	switch hdr.NextHeader {
	case IPProtoTCP:
		e.handleTCPv6(pkt, &hdr)
	case IPProtoUDP:
		e.handleUDPv6(pkt, &hdr)
	}
}

// --- TCP 处理（含包头重建）---

func (e *Engine) handleTCP(pkt []byte, ip *IPv4Header) {
	ipHdrLen := int(ip.IHL) * 4
	srcPort, dstPort, err := TCPPorts(pkt, ipHdrLen)
	if err != nil {
		return
	}
	key := SessionKey{SrcIP: ip.SrcIP.String(), DstIP: ip.DstIP.String(), SrcPort: srcPort, DstPort: dstPort, Proto: IPProtoTCP}

	// 提取 TCP 序列号
	var tcpSeq uint32
	if len(pkt) >= ipHdrLen+4 {
		tcpSeq = binary.BigEndian.Uint32(pkt[ipHdrLen+4 : ipHdrLen+8])
	}

	if IsTCP_SYN(pkt, ipHdrLen) {
		e.handleTCPSYN(key, ip, pkt, ipHdrLen, srcPort, dstPort, tcpSeq)
	} else if IsTCP_RST(pkt, ipHdrLen) {
		e.sessions.Remove(key)
	} else if sess := e.sessions.Get(key); sess != nil {
		payload := TCPPayload(pkt, ipHdrLen)
		if sess.TCP != nil && len(payload) > 0 {
			sess.TCP.UpdateFromClientData(len(payload))
			ack := sess.TCP.BuildResponseIPv4(nil, 0x10)
			_, _ = e.device.Write(ack)
		}
		if len(payload) > 0 && sess.Conn != nil {
			_, _ = sess.Conn.Write(payload)
		}
	}
}

func (e *Engine) handleTCPSYN(key SessionKey, ip *IPv4Header, pkt []byte, ipHdrLen int, srcPort, dstPort uint16, tcpSeq uint32) {
	// 确定真实目标
	realDst := net.JoinHostPort(ip.DstIP.String(), fmt.Sprintf("%d", dstPort))
	if e.fakeIP.IsFakeIP(ip.DstIP) {
		if host, ok := e.fakeIP.Lookup(ip.DstIP); ok {
			realDst = net.JoinHostPort(host, fmt.Sprintf("%d", dstPort))
		}
	}

	// 建立到真实目标的连接
	conn, err := e.dialer.DialTCP(e.ctx, realDst)
	if err != nil {
		log.Printf("[TUN] TCP dial %s failed: %v", realDst, err)
		// 发送 RST
		e.sendRST(ip, pkt, ipHdrLen, srcPort, dstPort, tcpSeq)
		return
	}

	// 初始化 TCP 状态
	tcp := &TCPState{}
	tcp.InitFromSYN(ip.SrcIP, ip.DstIP, srcPort, dstPort, tcpSeq)

	// 创建会话
	sess := e.sessions.Put(key, conn)
	sess.TCP = tcp

	// 发送 SYN-ACK 回 TUN
	synAck := tcp.BuildSYNACK()
	e.device.Write(synAck)

	log.Printf("[TUN] TCP session: %s -> %s (fake=%v)", key.String(), realDst, e.fakeIP.IsFakeIP(ip.DstIP))

	// 启动双向转发
	go e.tcpCopyToTUN(sess)
	go e.tcpCopyFromTUN(sess)
}

func (e *Engine) handleTCPv6(pkt []byte, ip *IPv6Header) {
	srcPort, dstPort, err := TCPPorts(pkt, 40)
	if err != nil {
		return
	}
	key := SessionKey{SrcIP: ip.SrcIP.String(), DstIP: ip.DstIP.String(), SrcPort: srcPort, DstPort: dstPort, Proto: IPProtoTCP}

	if IsTCP_SYN(pkt, 40) {
		e.handleTCPSYNv6(key, ip, pkt, srcPort, dstPort)
	} else if IsTCP_RST(pkt, 40) {
		e.sessions.Remove(key)
	} else if sess := e.sessions.Get(key); sess != nil {
		payload := TCPPayload(pkt, 40)
		if len(payload) > 0 && sess.Conn != nil {
			sess.Conn.Write(payload)
		}
	}
}

func (e *Engine) handleTCPSYNv6(key SessionKey, ip *IPv6Header, pkt []byte, srcPort, dstPort uint16) {
	realDst := net.JoinHostPort(ip.DstIP.String(), fmt.Sprintf("%d", dstPort))
	conn, err := e.dialer.DialTCP(e.ctx, realDst)
	if err != nil {
		return
	}
	tcp := &TCPState{}
	tcp.InitFromSYN(ip.SrcIP, ip.DstIP, srcPort, dstPort, 0)
	sess := e.sessions.Put(key, conn)
	sess.TCP = tcp
	go e.tcpCopyToTUN(sess)
	go e.tcpCopyFromTUN(sess)
}

// sendRST 发送 RST 包拒绝连接
func (e *Engine) sendRST(ip *IPv4Header, pkt []byte, ipHdrLen int, srcPort, dstPort uint16, tcpSeq uint32) {
	tcp := &TCPState{}
	tcp.InitFromSYN(ip.SrcIP, ip.DstIP, srcPort, dstPort, tcpSeq)
	rst := tcp.BuildRST()
	e.device.Write(rst)
}

// tcpCopyToTUN: 从目标 Conn 读取数据 → 封装 TCP/IP 头 → 写入 TUN
func (e *Engine) tcpCopyToTUN(sess *Session) {
	defer e.sessions.Remove(sess.Key)
	defer func() {
		if sess.TCP != nil {
			fin := sess.TCP.BuildFIN()
			e.device.Write(fin)
		}
	}()

	buf := make([]byte, e.mtu-40) // 减去 IP+TCP 头开销
	for {
		select {
		case <-sess.Done:
			return
		case <-e.ctx.Done():
			return
		default:
		}
		n, err := sess.Conn.Read(buf)
		if err != nil {
			return
		}
		if sess.TCP != nil {
			resp := sess.TCP.BuildResponseIPv4(buf[:n], 0x18) // ACK+PSH
			e.device.Write(resp)
		} else {
			e.device.Write(buf[:n])
		}
	}
}

// tcpCopyFromTUN: 从 TUN 收到数据的 goroutine 已在 handleTCP 中直接 Write 到 Conn
// 此 goroutine 只负责监听 Done 信号并清理
func (e *Engine) tcpCopyFromTUN(sess *Session) {
	<-sess.Done
	if sess.Conn != nil {
		sess.Conn.Close()
	}
}

// --- UDP 处理 ---

func (e *Engine) handleUDP(pkt []byte, ip *IPv4Header) {
	srcPort, dstPort, err := UDPPorts(pkt, int(ip.IHL)*4)
	if err != nil {
		return
	}
	key := SessionKey{SrcIP: ip.SrcIP.String(), DstIP: ip.DstIP.String(), SrcPort: srcPort, DstPort: dstPort, Proto: IPProtoUDP}

	if dstPort == 53 {
		udpPay := UDPPayload(pkt, int(ip.IHL)*4)
		if resp := e.dns.HandleQuery(udpPay, ip.SrcIP, srcPort); resp != nil {
			out := buildUDPv4(ip.DstIP, ip.SrcIP, dstPort, srcPort, resp)
			_, _ = e.device.Write(out)
			return
		}
	}

	payload := UDPPayload(pkt, int(ip.IHL)*4)
	if sess := e.sessions.Get(key); sess != nil {
		if len(payload) > 0 {
			sess.Conn.Write(payload)
		}
		return
	}

	// 新 UDP "会话"
	realDst := net.JoinHostPort(ip.DstIP.String(), fmt.Sprintf("%d", dstPort))
	if e.fakeIP.IsFakeIP(ip.DstIP) {
		if host, ok := e.fakeIP.Lookup(ip.DstIP); ok {
			realDst = net.JoinHostPort(host, fmt.Sprintf("%d", dstPort))
		}
	}
	conn, err := e.dialer.DialUDP(e.ctx, realDst)
	if err != nil {
		return
	}
	sess := e.sessions.Put(key, conn)
	if len(payload) > 0 {
		conn.Write(payload)
	}
	go e.udpCopyToTUN(sess)
}

func (e *Engine) handleUDPv6(pkt []byte, ip *IPv6Header) {
	srcPort, dstPort, err := UDPPorts(pkt, 40)
	if err != nil {
		return
	}
	key := SessionKey{SrcIP: ip.SrcIP.String(), DstIP: ip.DstIP.String(), SrcPort: srcPort, DstPort: dstPort, Proto: IPProtoUDP}

	if dstPort == 53 {
		if resp := e.dns.HandleQuery(pkt, ip.SrcIP, srcPort); resp != nil {
			e.device.Write(resp)
			return
		}
	}

	payload := UDPPayload(pkt, 40)
	if sess := e.sessions.Get(key); sess != nil && len(payload) > 0 {
		sess.Conn.Write(payload)
	}
}

func (e *Engine) udpCopyToTUN(sess *Session) {
	defer e.sessions.Remove(sess.Key)
	buf := make([]byte, e.mtu)
	srcIP := net.ParseIP(sess.Key.DstIP).To4()
	dstIP := net.ParseIP(sess.Key.SrcIP).To4()
	if srcIP == nil || dstIP == nil {
		return
	}
	for {
		select {
		case <-sess.Done:
			return
		case <-e.ctx.Done():
			return
		default:
		}
		n, err := sess.Conn.Read(buf)
		if err != nil {
			return
		}
		pkt := buildUDPv4(srcIP, dstIP, sess.Key.DstPort, sess.Key.SrcPort, buf[:n])
		_, _ = e.device.Write(pkt)
	}
}

func buildUDPv4(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	ipChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	udpChecksum(pkt[20:], srcIP.To4(), dstIP.To4())
	return pkt
}

// BuildUDPv4 is the exported helper for simulation / tests.
func BuildUDPv4(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	return buildUDPv4(srcIP, dstIP, srcPort, dstPort, payload)
}

func udpChecksum(udp []byte, src, dst net.IP) {
	sum := uint32(0)
	for i := 0; i < 4; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dst[i : i+2]))
	}
	sum += 17
	sum += uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		if i == 6 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], cs)
}
