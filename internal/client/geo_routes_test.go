// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Aero AI System

package client

import (
	"context"
	"net/netip"
	"testing"
)

func planCovers(plan RoutePlan, a netip.Addr) bool {
	for _, p := range plan.IPv4 {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// TUN 运行中同步到新的直连网段后，TUN 路由必须随之刷新（新直连网段不再进 TUN）。
// 此前只换了分流名单、没有刷新路由：新增的直连网段仍被路由进 TUN，数据泵又把“直连”目标的包丢掉，
// 那一批站点成了黑洞，直到重连。连接后约 3 秒的自动 geo 同步每次都会触发。
func TestGeoSyncRefreshesTunRoutes(t *testing.T) {
	geoTestEnv(t)
	hosts := useFakeTunHost(t, nil)
	stubCloseTestDial(t, okCloseTestDial)
	eng := newCloseTestEngine(t, hosts)
	SetPhysicalDialerHook(newInMemHTTPDialer(serveRules("9.9.9.0/24\n", nil)))
	t.Cleanup(func() { SetPhysicalDialerHook(nil) })
	eng.SetGeoDataURL("http://geodata.example.com" + geoDataAPIPath)

	if err := eng.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	host := hosts.last()
	if host == nil {
		t.Fatal("没有创建假网卡")
	}
	addr := netip.MustParseAddr("9.9.9.5")
	_, _, plans := host.snapshot()
	if len(plans) == 0 {
		// 启动时的路由随网卡创建一起下发（tunHostConfig.Plan），不在 ApplyRoutes 里
		if !planCovers(host.cfg.Plan, addr) {
			t.Fatal("前提：同步前 9.9.9.5 不在直连名单里，应被路由进 TUN")
		}
	}

	if _, updated, err := eng.SyncGeoData(context.Background()); err != nil || !updated {
		t.Fatalf("同步 = (%v,%v)", updated, err)
	}
	if got := eng.splitEngine.MatchIP(addr.AsSlice()); got != DIRECT {
		t.Fatalf("同步后 9.9.9.5 应命中直连名单: %v", got)
	}
	_, _, plans = host.snapshot()
	if len(plans) == 0 {
		t.Fatal("geo 同步后没有刷新 TUN 路由（ApplyRoutes 从未被调用）：新直连网段仍在 TUN 里")
	}
	if last := plans[len(plans)-1]; planCovers(last, addr) {
		t.Fatalf("刷新后的路由仍覆盖新直连地址 9.9.9.5：它会进 TUN")
	}
}
