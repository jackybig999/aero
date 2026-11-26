// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"
)

// 逐连接的只读监控（诊断用，不改任何包）：在 TUN 数据面上按 (协议, 远端地址, 端口) 统计每条连接的
// 握手耗时、字节、平均/峰值下行速率，以及内层 TCP 的重传（序号不前进的数据包）。
// 用来区分“浏览器的小连接”“AI 的长连接”“大文件下载”各自慢在哪：
//   - syn=…：SYN 发出到收到 SYN-ACK 的时间，等于一个往返加排队；浏览器页面慢通常先体现在这里。
//   - retx up/down：本机发出的重传 / 节点转来的重传。down 多说明下行路径丢了包（内层 TCP 在补）。
//   - path：D 数据报；R 可靠会话（ADR-0017）；AI 是 AI 域名的连接。
// 本机代理（55555 的 SOCKS/HTTP CONNECT）不经过 TUN，由 relayTraffic 另行记 [PROXY]。
// AERO_FLOWLOG=0 关闭。

const (
	flowMeterMaxFlows  = 4096
	flowMeterTick      = 5 * time.Second
	flowMeterIdle      = 8 * time.Second
	flowMeterBigBytes  = 32 * 1024 // 低于它的连接只计入“小连接”汇总
	flowMeterProgress  = 10 * time.Second
	flowMeterProgBytes = 256 * 1024
)

// flowLogEnabled 由环境变量控制，默认开启。
func flowLogEnabled() bool { return os.Getenv("AERO_FLOWLOG") != "0" }

type flowKey struct {
	proto  uint8
	remote netip.Addr
	rport  uint16
	lport  uint16
}

type flowRec struct {
	path        string
	first, last time.Time
	synAt       time.Time
	synAckAt    time.Time
	up, down    uint64
	pktsUp      uint64
	pktsDown    uint64
	endUp       uint32
	endDown     uint32
	haveUp      bool
	haveDown    bool
	retxUp      uint32
	retxDown    uint32
	closing     bool
	closeAt     time.Time
	secStart    time.Time
	secBytes    uint64
	peak        uint64
	progAt      time.Time
	progBytes   uint64
}

type flowMeter struct {
	name func(netip.Addr) string // 地址 → 域名（可为 nil）

	mu       sync.Mutex
	flows    map[flowKey]*flowRec
	overflow uint64
	smallSyn []time.Duration // 本周期结束的小连接握手耗时
	smallNo  int             // 小连接中 SYN 发出后没有任何回应的数量
	smallAt  time.Time

	stopCh chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

// newFlowMeter 创建并启动汇总协程；关闭开关时返回 nil（nil 的各方法都是空操作）。
func newFlowMeter(name func(netip.Addr) string) *flowMeter {
	if !flowLogEnabled() {
		return nil
	}
	m := &flowMeter{name: name, flows: make(map[flowKey]*flowRec), stopCh: make(chan struct{}), smallAt: time.Now()}
	m.wg.Add(1)
	go m.run()
	return m
}

// stop 结束汇总协程并输出所有未结束的连接。
func (m *flowMeter) stop() {
	if m == nil {
		return
	}
	m.once.Do(func() { close(m.stopCh) })
	m.wg.Wait()
}

// ipv4L4 解析 IPv4 的 TCP/UDP 头；其他协议、分片后续包、畸形包返回 ok=false。
func ipv4L4(b []byte) (proto uint8, src, dst netip.Addr, sp, dp uint16, ihl, total int, ok bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return
	}
	ihl = int(b[0]&0x0f) * 4
	total = int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || total > len(b) || total < ihl+8 || binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return
	}
	proto = b[9]
	if proto != 6 && proto != 17 {
		return
	}
	src = netip.AddrFrom4([4]byte(b[12:16]))
	dst = netip.AddrFrom4([4]byte(b[16:20]))
	sp = binary.BigEndian.Uint16(b[ihl : ihl+2])
	dp = binary.BigEndian.Uint16(b[ihl+2 : ihl+4])
	ok = true
	return
}

// up 记录一个本机发往隧道的包（原始包，源地址还是 TUN 地址）。path 是复用层的选择结果。
func (m *flowMeter) up(b []byte, path string) {
	if m == nil {
		return
	}
	proto, _, dst, sp, dp, ihl, total, ok := ipv4L4(b)
	if !ok || dp == 53 {
		return
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.get(flowKey{proto, dst, dp, sp}, path, now)
	if r == nil {
		return
	}
	r.last = now
	r.pktsUp++
	r.up += uint64(total)
	if proto != 6 || len(b) < ihl+20 {
		return
	}
	flags := b[ihl+13]
	if flags&0x12 == 0x02 && r.synAt.IsZero() { // SYN（不含 SYN-ACK）
		r.synAt = now
	}
	if flags&0x05 != 0 { // FIN 或 RST
		r.closing, r.closeAt = true, now
	}
	if payload := total - ihl - int(b[ihl+12]>>4)*4; payload > 0 {
		end := binary.BigEndian.Uint32(b[ihl+4:ihl+8]) + uint32(payload)
		if r.haveUp && int32(end-r.endUp) <= 0 {
			r.retxUp++
		} else {
			r.endUp, r.haveUp = end, true
		}
	}
}

// down 记录一个从隧道回到本机的包（已改回 TUN 地址）。
func (m *flowMeter) down(b []byte) {
	if m == nil {
		return
	}
	proto, src, _, sp, dp, ihl, total, ok := ipv4L4(b)
	if !ok || sp == 53 {
		return
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.get(flowKey{proto, src, sp, dp}, "?", now)
	if r == nil {
		return
	}
	r.last = now
	r.pktsDown++
	r.down += uint64(total)
	if now.Sub(r.secStart) >= time.Second {
		r.peak = max(r.peak, r.secBytes)
		r.secStart, r.secBytes = now, 0
	}
	r.secBytes += uint64(total)
	if proto != 6 || len(b) < ihl+20 {
		return
	}
	flags := b[ihl+13]
	if flags&0x12 == 0x12 && r.synAckAt.IsZero() {
		r.synAckAt = now
	}
	if flags&0x05 != 0 {
		r.closing, r.closeAt = true, now
	}
	if payload := total - ihl - int(b[ihl+12]>>4)*4; payload > 0 {
		end := binary.BigEndian.Uint32(b[ihl+4:ihl+8]) + uint32(payload)
		if r.haveDown && int32(end-r.endDown) <= 0 {
			r.retxDown++
		} else {
			r.endDown, r.haveDown = end, true
		}
	}
}

// get 在持锁时取得或创建记录；表满时不再新增（计数）。
func (m *flowMeter) get(k flowKey, path string, now time.Time) *flowRec {
	if r, ok := m.flows[k]; ok {
		if path != "?" && r.path == "?" {
			r.path = path
		}
		return r
	}
	if len(m.flows) >= flowMeterMaxFlows {
		m.overflow++
		return nil
	}
	r := &flowRec{path: path, first: now, last: now, secStart: now, progAt: now}
	m.flows[k] = r
	return r
}

func (m *flowMeter) run() {
	defer m.wg.Done()
	t := time.NewTicker(flowMeterTick)
	defer t.Stop()
	for {
		select {
		case <-m.stopCh:
			m.sweep(true)
			return
		case <-t.C:
			m.sweep(false)
		}
	}
}

// sweep 结束空闲的连接并输出；final 为真时结束全部。
func (m *flowMeter) sweep(final bool) {
	now := time.Now()
	var lines []string
	m.mu.Lock()
	for k, r := range m.flows {
		idle := now.Sub(r.last)
		done := final || idle >= flowMeterIdle || (r.closing && now.Sub(r.closeAt) >= 2*time.Second && idle >= 2*time.Second)
		if !done {
			if tot := r.up + r.down; tot-r.progBytes >= flowMeterProgBytes && now.Sub(r.progAt) >= flowMeterProgress {
				lines = append(lines, m.line(k, r, now, "进行中"))
				r.progAt, r.progBytes = now, tot
			}
			continue
		}
		delete(m.flows, k)
		if r.up+r.down >= flowMeterBigBytes {
			lines = append(lines, m.line(k, r, now, "结束"))
		} else if k.proto == 6 && !r.synAt.IsZero() {
			if r.synAckAt.IsZero() {
				m.smallNo++
			} else {
				m.smallSyn = append(m.smallSyn, r.synAckAt.Sub(r.synAt))
			}
		}
	}
	if final || now.Sub(m.smallAt) >= 2*flowMeterTick {
		if s := m.smallLine(); s != "" {
			lines = append(lines, s)
		}
		m.smallAt = now
		if m.overflow > 0 {
			lines = append(lines, fmt.Sprintf("[FLOW] 连接表已满（%d 条），%d 个新连接未统计", flowMeterMaxFlows, m.overflow))
			m.overflow = 0
		}
	}
	m.mu.Unlock()
	for _, l := range lines {
		log.Print(l)
	}
}

// smallLine 汇总本周期结束的小连接（浏览器的主要形态）：握手耗时的分布与无回应数。
func (m *flowMeter) smallLine() string {
	n := len(m.smallSyn)
	if n == 0 && m.smallNo == 0 {
		return ""
	}
	sort.Slice(m.smallSyn, func(i, j int) bool { return m.smallSyn[i] < m.smallSyn[j] })
	var p50, p90, mx time.Duration
	if n > 0 {
		p50, p90, mx = m.smallSyn[n/2], m.smallSyn[n*9/10], m.smallSyn[n-1]
	}
	s := fmt.Sprintf("[FLOW] 小连接 n=%d syn p50=%dms p90=%dms max=%dms 无回应=%d", n, p50.Milliseconds(), p90.Milliseconds(), mx.Milliseconds(), m.smallNo)
	m.smallSyn, m.smallNo = m.smallSyn[:0], 0
	return s
}

func (m *flowMeter) line(k flowKey, r *flowRec, now time.Time, state string) string {
	dur := r.last.Sub(r.first)
	if dur < time.Millisecond {
		dur = time.Millisecond
	}
	peak := max(r.peak, r.secBytes)
	proto := "tcp"
	if k.proto == 17 {
		proto = "udp"
	}
	host := ""
	if m.name != nil {
		host = m.name(k.remote)
	}
	syn := "-"
	if !r.synAt.IsZero() {
		if r.synAckAt.IsZero() {
			syn = "无回应"
		} else {
			syn = fmt.Sprintf("%dms", r.synAckAt.Sub(r.synAt).Milliseconds())
		}
	}
	return fmt.Sprintf("[FLOW] %s %s path=%s %s(%s:%d) 用时%.1fs 上行%dKB 下行%dKB 平均下行%.0fKB/s 峰值%.0fKB/s syn=%s 重传 up=%d down=%d 包 up=%d down=%d",
		state, proto, r.path, host, k.remote, k.rport, dur.Seconds(), r.up/1024, r.down/1024,
		float64(r.down)/1024/dur.Seconds(), float64(peak)/1024, syn, r.retxUp, r.retxDown, r.pktsUp, r.pktsDown)
}
