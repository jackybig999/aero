// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package api

// Runtime 由 main 注入；API 只转发意图，不拥有隧道实现。
// 新增能力只能加方法，不得改已有语义。
type Runtime interface {
	Connect() error
	Disconnect() error
	ImportSub(src string) error
	SwitchNode(addr string) error
	IsRunning() bool
	// ActiveNode 当前拨号 Edge 地址
	ActiveNode() string
	// Nodes 节点池快照
	Nodes() []NodeInfo
	// AIStats 可演示 AI 指标（可选；nil 表示未实现）
	AIStats() map[string]interface{}
	// SetMode socks|sysproxy|tun；sysproxy 写系统代理，tun 需权限
	SetMode(mode string) error
	// Mode 当前模式
	Mode() string
	// ListenAddr SOCKS 监听
	ListenAddr() string
	// SubSource 当前订阅源 URL（可空）
	SubSource() string
	// Probe optional live path check (google via local proxy). May return nil.
	Probe() map[string]interface{}
	// ISPInfo 返回识别到的运营商标识与显示名 (isp, ispName)
	ISPInfo() (string, string)
	// ActiveSNI 返回当前使用的伪装 SNI
	ActiveSNI() string
}

// SetRuntime 注入运行时（可 nil）
func (s *Server) SetRuntime(rt Runtime) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runtime = rt
}

func (s *Server) runtimeOrNil() Runtime {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runtime
}

// syncFromRuntime 用 Runtime 刷新 Connected/Node/Nodes（status/nodes 调用）
func (s *Server) syncFromRuntime() {
	rt := s.runtimeOrNil()
	if rt == nil {
		return
	}
	nodes := rt.Nodes()
	active := rt.ActiveNode()
	running := rt.IsRunning()
	mode := rt.Mode()
	listen := rt.ListenAddr()
	sub := rt.SubSource()
	isp, ispName := rt.ISPInfo()
	sni := rt.ActiveSNI()
	var rtt uint32
	for _, n := range nodes {
		if n.Active || (active != "" && n.Address == active) {
			if n.RTTMs > 0 {
				rtt = uint32(n.RTTMs)
			}
			break
		}
	}
	if rtt == 0 {
		for _, n := range nodes {
			if n.Reachable && n.RTTMs > 0 {
				rtt = uint32(n.RTTMs)
				break
			}
		}
	}
	s.UpdateState(func(st *AppState) {
		st.Connected = running
		if isp != "" {
			st.ISP = isp
			st.ISPName = ispName
		}
		if sni != "" {
			st.SNI = sni
		}
		if active != "" {
			st.Node = active
		}
		if nodes != nil {
			st.Nodes = nodes
		}
		if mode != "" {
			st.Mode = mode
		}
		if listen != "" {
			st.Listen = listen
		}
		// Mixed: HTTP + HTTPS + SOCKS5 same port
		if listen != "" {
			st.HTTPListen = listen
		} else if st.HTTPListen == "" {
			st.HTTPListen = "127.0.0.1:55555"
		}
		switch mode {
		case "tun":
			st.Hint = "TUN 全局已开（与 box TUN 同类）。指纹填 " + listen + "。不要再开系统代理。"
		case "socks":
			st.Hint = "仅本地混合口 " + listen + "（未接管系统、未开 TUN）。"
		default:
			st.Hint = "已接管系统代理 → " + listen + "。Grok 请完全退出再开。断开/退出会清空临时 HTTP_PROXY。"
		}
		if sub != "" {
			st.SubURL = sub
			st.SubURLMask = maskSubURL(sub)
		}
		if rtt > 0 {
			st.RTTMs = rtt
		}
	})
}

func maskSubURL(u string) string {
	// https://host/sub/SECRET → https://host/sub/****abcd
	const mark = "/sub/"
	i := -1
	for j := 0; j+len(mark) <= len(u); j++ {
		if u[j:j+len(mark)] == mark {
			i = j
			break
		}
	}
	if i < 0 {
		if len(u) > 16 {
			return u[:8] + "…"
		}
		return u
	}
	prefix := u[:i+len(mark)]
	sec := u[i+len(mark):]
	if len(sec) <= 8 {
		return prefix + "****"
	}
	return prefix + "****" + sec[len(sec)-4:]
}
