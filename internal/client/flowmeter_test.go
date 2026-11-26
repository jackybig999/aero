// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// tcpPkt 构造一个最小的 IPv4+TCP 包（无选项）。
func tcpPkt(src, dst netip.Addr, sp, dp uint16, seq uint32, flags byte, payload int) []byte {
	b := make([]byte, 40+payload)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8], b[9] = 64, 6
	s4, d4 := src.As4(), dst.As4()
	copy(b[12:16], s4[:])
	copy(b[16:20], d4[:])
	binary.BigEndian.PutUint16(b[20:22], sp)
	binary.BigEndian.PutUint16(b[22:24], dp)
	binary.BigEndian.PutUint32(b[24:28], seq)
	b[32] = 5 << 4
	b[33] = flags
	return b
}

func TestFlowMeterCountsRetransAndSyn(t *testing.T) {
	m := &flowMeter{flows: map[flowKey]*flowRec{}}
	local, remote := netip.MustParseAddr("10.88.0.2"), netip.MustParseAddr("93.184.216.34")
	m.up(tcpPkt(local, remote, 50000, 443, 100, 0x02, 0), "R")
	time.Sleep(5 * time.Millisecond)
	m.down(tcpPkt(remote, local, 443, 50000, 900, 0x12, 0))
	m.down(tcpPkt(remote, local, 443, 50000, 901, 0x10, 1000)) // 新数据
	m.down(tcpPkt(remote, local, 443, 50000, 901, 0x10, 1000)) // 同序号再来一次：重传
	m.up(tcpPkt(local, remote, 50000, 443, 101, 0x18, 200), "R")
	m.up(tcpPkt(local, remote, 50000, 443, 101, 0x18, 200), "R") // 重传

	r := m.flows[flowKey{6, remote, 443, 50000}]
	if r == nil {
		t.Fatal("flow not recorded")
	}
	if r.path != "R" || r.retxDown != 1 || r.retxUp != 1 {
		t.Fatalf("path=%q retxDown=%d retxUp=%d", r.path, r.retxDown, r.retxUp)
	}
	if r.synAt.IsZero() || r.synAckAt.IsZero() || !r.synAckAt.After(r.synAt) {
		t.Fatalf("syn timing not recorded: %v %v", r.synAt, r.synAckAt)
	}
	if r.down != 3*uint64(40)+2000 {
		t.Fatalf("down bytes = %d", r.down)
	}
}

func TestFlowMeterIgnoresDNSAndNonTCPUDP(t *testing.T) {
	m := &flowMeter{flows: map[flowKey]*flowRec{}}
	local, remote := netip.MustParseAddr("10.88.0.2"), netip.MustParseAddr("10.88.0.1")
	m.up(tcpPkt(local, remote, 50000, 53, 1, 0x02, 0), "D")
	icmp := tcpPkt(local, remote, 1, 2, 0, 0, 0)
	icmp[9] = 1
	m.up(icmp, "D")
	m.up([]byte{1, 2, 3}, "D")
	if len(m.flows) != 0 {
		t.Fatalf("unexpected flows: %d", len(m.flows))
	}
	var nilMeter *flowMeter
	nilMeter.up(icmp, "D") // nil 接收者是空操作
	nilMeter.down(icmp)
	nilMeter.stop()
}

func TestFlowMeterSweepEndsIdleFlows(t *testing.T) {
	m := &flowMeter{flows: map[flowKey]*flowRec{}, smallAt: time.Now()}
	local, remote := netip.MustParseAddr("10.88.0.2"), netip.MustParseAddr("93.184.216.34")
	m.up(tcpPkt(local, remote, 50000, 443, 1, 0x02, 0), "D")
	m.sweep(false)
	if len(m.flows) != 1 {
		t.Fatal("active flow must stay")
	}
	m.flows[flowKey{6, remote, 443, 50000}].last = time.Now().Add(-2 * flowMeterIdle)
	m.sweep(false)
	if len(m.flows) != 0 {
		t.Fatal("idle flow must end")
	}
	if m.smallNo != 1 { // SYN 没有任何回应的小连接
		t.Fatalf("smallNo = %d", m.smallNo)
	}
	m.up(tcpPkt(local, remote, 50001, 443, 1, 0x02, 0), "D")
	m.sweep(true)
	if len(m.flows) != 0 {
		t.Fatal("final sweep must end all flows")
	}
}
