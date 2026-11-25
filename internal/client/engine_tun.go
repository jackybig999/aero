// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"
)

// Engine 与宿主网络的唯一接口（ADR-0013、ADR-0014）：只经 tunHost 修改宿主，全部状态挂在自有网卡上；
// 释放只有一个入口 releaseTunLocked。

var (
	openTunHostFn      = openTunHost
	systemDNSServersFn = systemDNSServers
)

const (
	tunName = "aero0"
	tunMTU  = 1224 // 隧道 IPv4 内层 MTU：PMTU 探测完成前单个 QUIC DATAGRAM 可承载的上限
)

// tunAddress 把 edge 分配的地址（/32）放到隧道地址池 tunPool 的前缀长度下：池内其余地址（含虚拟网关）
// 经地址池路由进入 TUN。地址不在池内时拒绝。
func tunAddress(assigned netip.Prefix) (netip.Prefix, error) {
	a := assigned.Addr()
	if !a.Is4() || !tunPool.Contains(a) {
		return netip.Prefix{}, fmt.Errorf("assigned address %v is outside the tunnel pool %v", assigned, tunPool)
	}
	return netip.PrefixFrom(a, tunPool.Bits()), nil
}

// tunGateway 返回地址池内的虚拟网关（本网卡 DNS）：池内第一个主机地址，与本机地址相同时取下一个。
func tunGateway(p netip.Prefix) netip.Addr {
	gw := p.Masked().Addr().Next()
	if gw == p.Addr() {
		gw = gw.Next()
	}
	return gw
}

// tunPlanInputLocked 由当前订阅、直连名单与系统 DNS 生成路由规划输入。调用方持 e.mu（读）。
// 订阅中全部节点地址与当前活跃节点都放入 Bypass，切换到订阅内节点无需改路由。
func (e *Engine) tunPlanInputLocked(extra ...net.IP) RoutePlanInput {
	var in RoutePlanInput
	// 直连网段 = 内置 APNIC 快照 ∪ 服务端下发的 IPv4 网段；分流引擎尚未创建时退回内置快照
	var cidrs []string
	if e.splitEngine != nil {
		cidrs = e.splitEngine.ChinaCIDRs()
	} else if GlobalDefaultChinaMatcher != nil {
		cidrs = GlobalDefaultChinaMatcher.ExportCIDRs()
	}
	for _, s := range cidrs {
		if p, err := netip.ParsePrefix(s); err == nil {
			in.Direct = append(in.Direct, p)
		}
	}
	addBypass := func(ip net.IP) {
		if a, ok := netip.AddrFromSlice(ip); ok && a.IsValid() && !a.IsUnspecified() {
			in.Bypass = append(in.Bypass, a.Unmap())
		}
	}
	if e.appliedSub != nil {
		for _, s := range e.appliedSub.IPs {
			addBypass(net.ParseIP(s))
		}
	}
	if _, _, _, active := getActiveEdge(); active != nil { // 当前节点可能是运行时解析出的地址
		addBypass(active)
	}
	for _, ip := range extra {
		addBypass(ip)
	}
	dns, err := systemDNSServersFn()
	if err != nil {
		// 读不到时仍由各平台 DNS 防护（WFP、resolved 链路配置）兜底
		log.Printf("[ENGINE] read system DNS servers: %v", err)
	}
	in.Capture = dns
	return e.withinRouteBudget(in)
}

// withinRouteBudget 保证路由规划不超过 maxTUNRoutes。挂到 TUN 上的是“全集减去直连”的补集，
// 下发的 IPv4 网段若很稀疏（大量互不相邻的小网段），每段空隙都会被拆成多条前缀，条数远超网段数，
// 行数上限与覆盖率总闸都挡不住。此时丢弃下发网段、只用内置快照，保证 TUN 能起来。
func (e *Engine) withinRouteBudget(in RoutePlanInput) RoutePlanInput {
	if !e.splitEngine.hasDirectV4() {
		return in
	}
	_, err := PlanTUNRoutes(in)
	if err == nil {
		return in
	}
	log.Printf("[ENGINE] downloaded direct ranges exceed the TUN route budget, using built-in ranges only: %v", err)
	in.Direct = in.Direct[:0:0]
	for _, s := range e.splitEngine.BuiltinChinaCIDRs() {
		if p, err := netip.ParsePrefix(s); err == nil {
			in.Direct = append(in.Direct, p)
		}
	}
	return in
}

// refreshTunRoutes 在订阅、直连名单、系统 DNS 或节点地址变化后重新规划并增量下发路由。
// 下发失败时网卡状态不确定：记录错误并停止引擎，避免在未知路由下继续运行。
func (e *Engine) refreshTunRoutes(extra ...net.IP) {
	e.mu.RLock()
	host := e.tunHost
	in := e.tunPlanInputLocked(extra...)
	e.mu.RUnlock()
	if host == nil {
		return
	}
	plan, err := PlanTUNRoutes(in)
	if err == nil {
		err = host.ApplyRoutes(plan)
	}
	if errors.Is(err, errTunHostClosed) {
		return // 引擎已停止
	}
	if err != nil {
		log.Printf("[ENGINE] refresh TUN routes failed, stopping: %v", err)
		e.SetLastError(fmt.Sprintf("refresh TUN routes: %v", err))
		go func() { _ = e.Stop() }()
	}
}

// bringUpTunLocked 建立 CONNECT-IP、创建自有网卡并启动数据面。失败时已建立的部分全部释放。
// startCtx 是本次启动的取消域：Stop/Close/BeginStop 取消它即可中断拨号，不必等持 lifecycleMu 的启动自然超时。
func (e *Engine) bringUpTunLocked(startCtx context.Context, nodeIP net.IP) error {
	tr := e.startTr.Load() // 只写日志；直接调用（测试）时为 nil，各方法对 nil 安全
	dialCtx, cancel := context.WithTimeout(startCtx, 8*time.Second)
	ipConn, prefixStr, err := dialIPFn(dialCtx, e.sessionMgr)
	cancel()
	if err != nil {
		return fmt.Errorf("dial CONNECT-IP: %w", err)
	}
	prefix, err := netip.ParsePrefix(prefixStr)
	if err == nil {
		prefix, err = tunAddress(prefix)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("CONNECT-IP assigned prefix %q: %w", prefixStr, err), ipConn.Close())
	}

	// 节点声明了 capsule 时接入 ai 会话（失败不影响隧道，见 wrapAI）；否则 ipConn 原样使用。
	// 放在路由下发之前：拨号最长 aiDialTimeout，期间不能让整机流量落进还没有数据面的 TUN。
	tr.enter("ai-session")
	ipConn = e.wrapAI(startCtx, ipConn, prefix)
	tr.enter("tun-open")
	closeConn := func() error { e.retireAIConn(ipConn); return ipConn.Close() }

	e.mu.RLock()
	in := e.tunPlanInputLocked(nodeIP)
	e.mu.RUnlock()
	plan, err := PlanTUNRoutes(in)
	if err != nil {
		return errors.Join(fmt.Errorf("plan TUN routes: %w", err), closeConn())
	}
	host, err := openTunHostFn(tunHostConfig{Name: tunName, MTU: tunMTU, IPv4: prefix, DNS: tunGateway(prefix), Plan: plan})
	if err != nil {
		return errors.Join(fmt.Errorf("%w: open TUN: %w", ErrTunUnavailable, err), closeConn())
	}
	e.mu.Lock() // refreshTunRoutes 在 e.mu 下读取 tunHost
	e.tunHost = host
	e.mu.Unlock()

	tr.enter("data-plane")
	e.stackEngine = NewStackEngineWithConn(host.Device(), ipConn, e.dnsHandler)
	e.stackEngine.SetKillSwitch(e.killSwitch.Load())
	if err := e.stackEngine.Start(); err != nil {
		e.releaseTunLocked()
		return fmt.Errorf("start data plane: %w", err)
	}
	// 断线恢复：数据泵断开后自动重建 CONNECT-IP（M2-9）
	e.startReconnector(e.rootCtx, e.stackEngine, host, prefix)
	e.stackEngine.SetWebRTCActive(true)
	SetGlobalMobileWebRTCActive(true)
	tr.finish()
	log.Printf("[ENGINE] TUN %s up: %s, %d IPv4 + %d IPv6 routes", tunName, prefix, len(plan.IPv4), len(plan.IPv6))
	return nil
}

// releaseTunLocked 停止数据面并销毁自有网卡（其上的地址、路由、DNS 及防护规则随之清除）；幂等。
// 调用方不得持有 e.mu（本函数在 e.mu 下摘下 tunHost，再在锁外关闭）。
func (e *Engine) releaseTunLocked() {
	e.resetAIState()
	if e.stackEngine != nil {
		e.stackEngine.SetWebRTCActive(false)
		SetGlobalMobileWebRTCActive(false)
		e.stackEngine.Stop()
		e.stackEngine = nil
	}
	e.mu.Lock()
	host := e.tunHost
	e.tunHost = nil
	e.mu.Unlock()
	if host != nil {
		if err := host.Close(); err != nil {
			log.Printf("[ENGINE] close TUN: %v", err)
		}
	}
}
