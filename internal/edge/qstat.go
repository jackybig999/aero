// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package edge

import (
	"log"
	"time"

	"github.com/quic-go/quic-go"
)

// QUIC 层的周期统计（只读诊断，不影响数据面）。
// 客户端统计的是“本端发出的包”：节点上的 lost 对应下行（下载）丢失。
// 丢包数是 QUIC 判定的丢失，包含乱序造成的误判（RFC 9002 §6.1.1，包数阈值 3），所以它是“发送方认为的丢包”，不一定是网络真的丢了。
const qstatInterval = 5 * time.Second

// qstatMinBytes 是一个统计周期内收发合计低于它就不打印，避免空闲时刷屏。
const qstatMinBytes = 64 * 1024

// startQUICStats 在 conn 存活期间每 qstatInterval 记一行 [QSTAT]；连接关闭后协程退出。
func startQUICStats(conn *quic.Conn, tag string, port int) {
	if conn == nil {
		return
	}
	go func() {
		t := time.NewTicker(qstatInterval)
		defer t.Stop()
		prev := conn.ConnectionStats()
		for {
			select {
			case <-conn.Context().Done():
				cur := conn.ConnectionStats()
				if cur.BytesSent+cur.BytesReceived < qstatMinBytes {
					return // 哨兵探测等短连接不记
				}
				log.Printf("[QSTAT] %s closed port=%d total sent=%d lost=%d (%.2f%%) recv=%d minrtt=%v srtt=%v",
					tag, port, cur.PacketsSent, cur.PacketsLost, pct(cur.PacketsLost, cur.PacketsSent), cur.PacketsReceived,
					cur.MinRTT.Round(time.Millisecond), cur.SmoothedRTT.Round(time.Millisecond))
				return
			case <-t.C:
				cur := conn.ConnectionStats()
				dTx, dRx := cur.BytesSent-prev.BytesSent, cur.BytesReceived-prev.BytesReceived
				if dTx+dRx >= qstatMinBytes {
					dSent := cur.PacketsSent - prev.PacketsSent
					dLost := cur.PacketsLost - prev.PacketsLost // 累计值可回落（丢失后又收到），差值为负时按 0 记
					if cur.PacketsLost < prev.PacketsLost {
						dLost = 0
					}
					secs := qstatInterval.Seconds()
					log.Printf("[QSTAT] %s port=%d remote=%v rtt min=%v srtt=%v latest=%v dev=%v | tx %.0fKB/s pkts=%d lost=%d (%.1f%%) | rx %.0fKB/s pkts=%d",
						tag, port, conn.RemoteAddr(), cur.MinRTT.Round(time.Millisecond), cur.SmoothedRTT.Round(time.Millisecond),
						cur.LatestRTT.Round(time.Millisecond), cur.MeanDeviation.Round(time.Millisecond),
						float64(dTx)/1024/secs, dSent, dLost, pct(dLost, dSent),
						float64(dRx)/1024/secs, cur.PacketsReceived-prev.PacketsReceived)
				}
				prev = cur
			}
		}
	}()
}

func pct(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}
