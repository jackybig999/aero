// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import "os"

// CongestionControlEnv 选择本端 QUIC 发送方使用的拥塞控制：lossy（默认）或 cubic（上游行为，用于回退）。
// 背景见 ADR-0019：上游基于丢包的拥塞控制在往返约 190ms、随机丢包 ≥0.1% 的跨境链路上吞吐只有 1~5 Mbit/s。
// 每一端只决定自己发出的数据：客户端的设置影响上行，服务端的设置影响下行（下载）。
const CongestionControlEnv = "AERO_CONGESTION_CONTROL"

// congestionControl 返回传给 quic.Config.CongestionControl 的值；未设置或取值无效时用默认的 lossy。
func congestionControl() string {
	if v := os.Getenv(CongestionControlEnv); v == "cubic" || v == "lossy" {
		return v
	}
	return "lossy"
}
