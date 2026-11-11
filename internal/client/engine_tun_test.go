package client

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// 单元测试中 Engine 不得创建真实网卡（root 开发机上会改宿主网络）：默认入口直接报错，
// 需要 TUN 的测试必须调用 useFakeTunHost。真实网卡测试直接调用 openTunHost，且在隔离环境中运行。
func init() {
	openTunHostFn = func(tunHostConfig) (tunHost, error) {
		return nil, errors.New("real TUN is forbidden in unit tests; call useFakeTunHost")
	}
}

// fakeTunHost 记录 Engine 对宿主网络的全部操作，不触碰真实网卡。
type fakeTunHost struct {
	mu      sync.Mutex
	cfg     tunHostConfig
	dev     TunDevice
	addrs   []netip.Prefix
	plans   []RoutePlan
	closed  bool
	failApp error // 非空时 ApplyRoutes 返回该错误
}

func (f *fakeTunHost) Device() TunDevice { return f.dev }

func (f *fakeTunHost) SetIPv4(p netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errTunHostClosed
	}
	f.addrs = append(f.addrs, p)
	return nil
}

func (f *fakeTunHost) ApplyRoutes(plan RoutePlan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errTunHostClosed
	}
	if f.failApp != nil {
		return f.failApp
	}
	f.plans = append(f.plans, plan)
	return nil
}

func (f *fakeTunHost) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeTunHost) snapshot() (closed bool, addrs []netip.Prefix, plans []RoutePlan) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed, append([]netip.Prefix(nil), f.addrs...), append([]RoutePlan(nil), f.plans...)
}

// fakeTunHosts 收集测试期间创建的全部假网卡。
type fakeTunHosts struct {
	mu    sync.Mutex
	hosts []*fakeTunHost
}

func (fs *fakeTunHosts) last() *fakeTunHost {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.hosts) == 0 {
		return nil
	}
	return fs.hosts[len(fs.hosts)-1]
}

// useFakeTunHost 以假网卡替换宿主网络入口（dev 为 nil 时使用 newMockTunDevice），并屏蔽第三方 TUN 检测
// 与系统 DNS 读取，测试结束自动恢复。
func useFakeTunHost(t *testing.T, dev TunDevice) *fakeTunHosts {
	t.Helper()
	origOpen, origDNS, origDetect := openTunHostFn, systemDNSServersFn, detectThirdPartyTUN
	t.Cleanup(func() { openTunHostFn, systemDNSServersFn, detectThirdPartyTUN = origOpen, origDNS, origDetect })
	fs := &fakeTunHosts{}
	openTunHostFn = func(cfg tunHostConfig) (tunHost, error) {
		if err := cfg.validate(); err != nil {
			return nil, err
		}
		d := dev
		if d == nil {
			d = newMockTunDevice()
		}
		h := &fakeTunHost{cfg: cfg, dev: d}
		fs.mu.Lock()
		fs.hosts = append(fs.hosts, h)
		fs.mu.Unlock()
		return h, nil
	}
	systemDNSServersFn = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.168.1.1")}, nil }
	detectThirdPartyTUN = func() (bool, string, error) { return false, "", nil }
	return fs
}

// forbidTunHost 让任何宿主网络操作直接判测试失败（用于本地代理模式）。
func forbidTunHost(t *testing.T) {
	t.Helper()
	origOpen := openTunHostFn
	t.Cleanup(func() { openTunHostFn = origOpen })
	openTunHostFn = func(tunHostConfig) (tunHost, error) {
		t.Errorf("openTunHost called; local proxy mode must not touch the host")
		return nil, errors.New("forbidden")
	}
}

func TestTunAddress(t *testing.T) {
	got, err := tunAddress(netip.MustParsePrefix("10.88.3.7/32"))
	if err != nil || got != netip.MustParsePrefix("10.88.3.7/16") {
		t.Fatalf("tunAddress(10.88.3.7/32) = %v, %v", got, err)
	}
	if gw := tunGateway(got); gw != netip.MustParseAddr("10.88.0.1") {
		t.Fatalf("gateway for %v = %v, want 10.88.0.1", got, gw)
	}
	for _, bad := range []string{"192.168.1.2/32", "10.89.0.2/32", "fd00::2/128"} {
		if _, err := tunAddress(netip.MustParsePrefix(bad)); err == nil {
			t.Errorf("tunAddress(%s) accepted an address outside the pool", bad)
		}
	}
}

func TestTunGateway(t *testing.T) {
	for in, want := range map[string]string{
		"10.88.0.2/16": "10.88.0.1",
		"10.88.0.1/16": "10.88.0.2",
		"10.88.5.9/24": "10.88.5.1",
	} {
		if got := tunGateway(netip.MustParsePrefix(in)); got.String() != want {
			t.Errorf("tunGateway(%s) = %s, want %s", in, got, want)
		}
	}
}

// 订阅中的全部节点地址与额外地址都进入 Bypass；系统 DNS 进入 Capture。
func TestTunPlanInputBypassesAllNodes(t *testing.T) {
	useFakeTunHost(t, nil)
	eng := NewEngine()
	eng.appliedSub = &Applied{IPs: map[string]string{"a:443": "198.51.100.1", "b:443": "198.51.100.2", "c:443": "bad"}}
	in := eng.tunPlanInputLocked(net.ParseIP("203.0.113.9"))
	want := map[netip.Addr]bool{
		netip.MustParseAddr("198.51.100.1"): true, netip.MustParseAddr("198.51.100.2"): true, netip.MustParseAddr("203.0.113.9"): true,
	}
	if len(in.Bypass) != len(want) {
		t.Fatalf("bypass = %v", in.Bypass)
	}
	for _, a := range in.Bypass {
		if !want[a] {
			t.Errorf("unexpected bypass %v", a)
		}
	}
	if len(in.Capture) != 1 || in.Capture[0] != netip.MustParseAddr("192.168.1.1") {
		t.Errorf("capture = %v", in.Capture)
	}
}

// 引擎已停止（网卡已关闭）时刷新路由是正常竞态，不得触发停止或记录错误。
func TestRefreshTunRoutesIgnoresClosedHost(t *testing.T) {
	useFakeTunHost(t, nil)
	eng := NewEngine()
	h := &fakeTunHost{dev: newMockTunDevice(), closed: true}
	eng.tunHost = h
	eng.refreshTunRoutes()
	if st := eng.GetState(); st.LastError != "" {
		t.Fatalf("closed host produced error %q", st.LastError)
	}
}
