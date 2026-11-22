// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ipMux 把 default 会话与可选的 ai 会话合成一个 IPPacketConn（ADR-0017），数据泵、TUN 和 DNS 不需要改动。
//
//   - 上行：flowClassifier 按流选择会话；走 ai 的包先把源地址改成 ai 会话的地址（natUplink）。
//   - 下行：两个会话的包合并到一个队列；ai 会话的包把目的地址改回 TUN 地址（natDownlink）。
//   - 隔离：ai 会话的上行有独立队列与写协程，队列满就丢尾（内层 TCP 自己退让），绝不阻塞 default 会话的上行；
//     ai 会话的任何读写错误只让 ai 降级（回调 onAIDown），不让泵报错；只有 default 会话失败才使整条隧道断线重连。
//   - fail-closed：ai 会话不可用时，新建的 AI TCP 连接得到 ICMP 不可达，已建立的流静默丢包；不会改走 default。

const (
	muxRxLen     = 256 // 下行合并队列（包数）
	muxAITxLen   = 128 // ai 上行队列（包数）；满则丢尾
	muxBufSize   = 2048
	muxCloseWait = time.Second
)

var muxBufPool = sync.Pool{New: func() any { b := make([]byte, muxBufSize); return &b }}

// muxGetBuf 返回长度为 n 的缓冲；n 不超过 muxBufSize 时来自池。
func muxGetBuf(n int) []byte {
	if n <= muxBufSize {
		b := *(muxBufPool.Get().(*[]byte))
		return b[:n]
	}
	return make([]byte, n)
}

func muxPutBuf(b []byte) {
	if cap(b) == muxBufSize {
		b = b[:muxBufSize]
		muxBufPool.Put(&b)
	}
}

// aiLink 是一条已接入的 ai 会话及其上行队列。
type aiLink struct {
	conn IPPacketConn
	addr netip.Addr // ai 会话的地址（源地址改写的目标）
	tx   chan []byte
	done chan struct{}
	once sync.Once
}

func (l *aiLink) stop() { l.once.Do(func() { close(l.done) }) }

// ipMux 的统计，用于诊断与测试。
type muxStats struct {
	aiTxDropped    atomic.Uint64 // ai 上行队列满而丢弃
	aiUnavailable  atomic.Uint64 // ai 会话不可用而丢弃
	aiRxBadDest    atomic.Uint64 // ai 会话下行的包目的地址不是它的地址
	aiLinksFailed  atomic.Uint64 // ai 会话失败次数
	aiPacketsUp    atomic.Uint64
	aiPacketsDown  atomic.Uint64
	defaultPackets atomic.Uint64
}

type ipMux struct {
	d       IPPacketConn
	tunAddr netip.Addr
	cls     *flowClassifier

	rx        chan []byte
	closeCh   chan struct{}
	closeOnce sync.Once
	errMu     sync.Mutex
	err       error // 使 ReadPacket 返回的错误：default 会话失败，或 net.ErrClosed

	mu     sync.Mutex
	link   *aiLink
	aiDown func(error)
	closed bool

	wg    sync.WaitGroup
	stats muxStats
}

var _ IPPacketConn = (*ipMux)(nil)

// newIPMux 创建复用层并开始读取 default 会话。tunAddr 是 TUN 网卡的地址（default 会话分到的地址）。
func newIPMux(d IPPacketConn, tunAddr netip.Addr, cls *flowClassifier) *ipMux {
	m := &ipMux{d: d, tunAddr: tunAddr, cls: cls, rx: make(chan []byte, muxRxLen), closeCh: make(chan struct{})}
	m.wg.Add(1)
	go m.readDefault()
	return m
}

// SetAIDownHandler 设置 ai 会话失败时的回调（在独立协程中调用，参数是失败原因）。
func (m *ipMux) SetAIDownHandler(f func(error)) {
	m.mu.Lock()
	m.aiDown = f
	m.mu.Unlock()
}

// AIAvailable 报告 ai 会话当前是否已接入。
func (m *ipMux) AIAvailable() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.link != nil
}

// AttachAI 接入（或替换）ai 会话。conn 的所有权转给复用层。复用层已关闭时关闭 conn 并返回错误。
func (m *ipMux) AttachAI(conn IPPacketConn, addr netip.Addr) error {
	if !addr.Is4() {
		_ = conn.Close()
		return errors.New("ai session address is not IPv4")
	}
	l := &aiLink{conn: conn, addr: addr, tx: make(chan []byte, muxAITxLen), done: make(chan struct{})}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	old := m.link
	m.link = l
	m.wg.Add(2)
	m.mu.Unlock()
	if old != nil {
		m.dropLink(old)
	}
	go m.readAI(l)
	go m.writeAI(l)
	return nil
}

// DetachAI 主动断开 ai 会话，不触发 onAIDown 回调。
func (m *ipMux) DetachAI() {
	m.mu.Lock()
	l := m.link
	m.link = nil
	m.mu.Unlock()
	if l != nil {
		m.dropLink(l)
	}
}

// dropLink 停止一条链路、关闭其连接并释放排队的包。
func (m *ipMux) dropLink(l *aiLink) {
	l.stop()
	_ = l.conn.Close()
	for {
		select {
		case p := <-l.tx:
			muxPutBuf(p)
		default:
			return
		}
	}
}

// aiFailed 处理 ai 会话的读写错误：只让 ai 降级，并通知引擎重拨。
func (m *ipMux) aiFailed(l *aiLink, err error) {
	m.mu.Lock()
	current := m.link == l
	if current {
		m.link = nil
	}
	closed := m.closed
	cb := m.aiDown
	m.mu.Unlock()
	if !current { // 已被替换、主动断开或复用层已关闭
		return
	}
	m.stats.aiLinksFailed.Add(1)
	m.dropLink(l)
	if cb != nil && !closed {
		go cb(err)
	}
}

// readDefault 读取 default 会话；它失败就是整条隧道失败，ReadPacket 返回该错误。
func (m *ipMux) readDefault() {
	defer m.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, err := m.d.ReadPacket(buf)
		if err != nil {
			m.fail(err)
			return
		}
		if n < 20 {
			continue
		}
		p := muxGetBuf(n)
		copy(p, buf[:n])
		m.stats.defaultPackets.Add(1)
		if !m.deliver(p) {
			return
		}
	}
}

// readAI 读取 ai 会话，把目的地址改回 TUN 地址后交给下行队列。
func (m *ipMux) readAI(l *aiLink) {
	defer m.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, err := l.conn.ReadPacket(buf)
		if err != nil {
			m.aiFailed(l, err)
			return
		}
		if n < 20 {
			continue
		}
		p := muxGetBuf(n)
		copy(p, buf[:n])
		if !natDownlink(p, l.addr, m.tunAddr) {
			m.stats.aiRxBadDest.Add(1)
			muxPutBuf(p)
			continue
		}
		m.stats.aiPacketsDown.Add(1)
		select {
		case m.rx <- p:
		case <-l.done: // 链路被丢弃（失败、替换、主动断开）：不再等下行队列
			muxPutBuf(p)
			return
		case <-m.closeCh:
			muxPutBuf(p)
			return
		}
	}
}

// writeAI 是 ai 会话的上行写协程：与泵解耦，反压只作用于 ai 自己的队列。
func (m *ipMux) writeAI(l *aiLink) {
	defer m.wg.Done()
	for {
		select {
		case <-l.done:
			return
		case p := <-l.tx:
			_, err := l.conn.WritePacket(p)
			muxPutBuf(p)
			if err != nil {
				m.aiFailed(l, err)
				return
			}
		}
	}
}

// deliver 把下行包放入合并队列；复用层关闭时返回 false 并释放缓冲。
func (m *ipMux) deliver(p []byte) bool {
	select {
	case m.rx <- p:
		return true
	case <-m.closeCh:
		muxPutBuf(p)
		return false
	}
}

// fail 记录使 ReadPacket 返回的错误并唤醒它（只记录第一次）。
func (m *ipMux) fail(err error) {
	m.errMu.Lock()
	if m.err == nil {
		m.err = err
	}
	m.errMu.Unlock()
	m.closeOnce.Do(func() { close(m.closeCh) })
}

func (m *ipMux) readErr() error {
	m.errMu.Lock()
	defer m.errMu.Unlock()
	if m.err != nil {
		return m.err
	}
	return net.ErrClosed
}

// ReadPacket 实现 IPPacketConn：返回下行合并队列里的下一个包。
func (m *ipMux) ReadPacket(b []byte) (int, error) {
	select {
	case p := <-m.rx:
		n := copy(b, p)
		muxPutBuf(p)
		return n, nil
	case <-m.closeCh:
		return 0, m.readErr()
	}
}

// WritePacket 实现 IPPacketConn：按流选择会话。ai 会话的任何问题都不会作为错误返回给泵
// （否则泵会断开整条隧道）；需要通知应用的情况（新连接被拒）通过返回的 ICMP 包回写到 TUN。
func (m *ipMux) WritePacket(b []byte) ([]byte, error) {
	class, newTCP := m.cls.classify(b)
	if class == flowDefault {
		return m.d.WritePacket(b)
	}
	m.mu.Lock()
	l := m.link
	m.mu.Unlock()
	if l == nil {
		m.stats.aiUnavailable.Add(1)
		if newTCP {
			return buildICMPv4Unreachable(b, icmpHostUnreachable), nil
		}
		return nil, nil
	}
	p := muxGetBuf(len(b))
	copy(p, b)
	if !natUplink(p, m.tunAddr, l.addr) {
		// 源地址不是 TUN 地址（不是本机应用发的包）：不改写、不走 ai，按 default 处理。
		muxPutBuf(p)
		return m.d.WritePacket(b)
	}
	select {
	case l.tx <- p:
		m.stats.aiPacketsUp.Add(1)
	default:
		m.stats.aiTxDropped.Add(1)
		muxPutBuf(p)
	}
	return nil, nil
}

// Close 实现 IPPacketConn：关闭两个会话并等待内部协程退出（最长 muxCloseWait）。可重复调用。
func (m *ipMux) Close() error {
	m.mu.Lock()
	already := m.closed
	m.closed = true
	l := m.link
	m.link = nil
	m.mu.Unlock()
	if already {
		return nil
	}
	m.closeOnce.Do(func() { close(m.closeCh) })
	if l != nil {
		m.dropLink(l)
	}
	err := m.d.Close()
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(muxCloseWait):
	}
	for { // 释放下行队列里未读的包
		select {
		case p := <-m.rx:
			muxPutBuf(p)
		default:
			return err
		}
	}
}

// ---- ICMP 目的不可达 ----

const (
	icmpHostUnreachable = 1 // 类型 3 代码 1
)

// buildICMPv4Unreachable 为原报文 orig 构造 ICMP 目的不可达（类型 3），发给原报文的发送者；
// 源地址取原报文的目的地址（相当于对端主机回复）。带上原 IP 头和前 8 字节载荷。orig 不合法返回 nil。
func buildICMPv4Unreachable(orig []byte, code byte) []byte {
	ihl := ipv4Header(orig)
	if ihl == 0 || orig[9] == 1 { // 不对 ICMP 回 ICMP
		return nil
	}
	quote := ihl + 8
	if quote > len(orig) {
		quote = len(orig)
	}
	total := 20 + 8 + quote
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8], pkt[9] = 64, 1
	copy(pkt[12:16], orig[16:20]) // 源：原报文的目的
	copy(pkt[16:20], orig[12:16]) // 目的：原报文的源
	binary.BigEndian.PutUint16(pkt[10:12], onesComplementSum(pkt[:20]))
	pkt[20], pkt[21] = 3, code
	copy(pkt[28:], orig[:quote])
	binary.BigEndian.PutUint16(pkt[22:24], onesComplementSum(pkt[20:]))
	return pkt
}
