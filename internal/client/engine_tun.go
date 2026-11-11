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
	if GlobalDefaultChinaMatcher != nil {
		for _, s := range GlobalDefaultChinaMatcher.ExportCIDRs() {
			if p, err := netip.ParsePrefix(s); err == nil {
				in.Direct = append(in.Direct, p)
			}
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
func (e *Engine) bringUpTunLocked(nodeIP net.IP) error {
	dialCtx, cancel := context.WithTimeout(e.rootCtx, 8*time.Second)
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

	e.mu.RLock()
	in := e.tunPlanInputLocked(nodeIP)
	e.mu.RUnlock()
	plan, err := PlanTUNRoutes(in)
	if err != nil {
		return errors.Join(fmt.Errorf("plan TUN routes: %w", err), ipConn.Close())
	}
	host, err := openTunHostFn(tunHostConfig{Name: tunName, MTU: tunMTU, IPv4: prefix, DNS: tunGateway(prefix), Plan: plan})
	if err != nil {
		return errors.Join(fmt.Errorf("open TUN: %w", err), ipConn.Close())
	}
	e.tunHost = host

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
	log.Printf("[ENGINE] TUN %s up: %s, %d IPv4 + %d IPv6 routes", tunName, prefix, len(plan.IPv4), len(plan.IPv6))
	return nil
}

// releaseTunLocked 停止数据面并销毁自有网卡（其上的地址、路由、DNS 及防护规则随之清除）；幂等。
func (e *Engine) releaseTunLocked() {
	if e.stackEngine != nil {
		e.stackEngine.SetWebRTCActive(false)
		SetGlobalMobileWebRTCActive(false)
		e.stackEngine.Stop()
		e.stackEngine = nil
	}
	if e.tunHost != nil {
		if err := e.tunHost.Close(); err != nil {
			log.Printf("[ENGINE] close TUN: %v", err)
		}
		e.tunHost = nil
	}
}
