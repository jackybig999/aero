package client

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 默认端口被占用/被禁止时（Windows 的端口排除段、被其他程序独占），常驻代理自动回退，
// 状态里报告真实地址与“在监听”。每个用例都隔离数据目录，避免写到真实用户目录。
func residentTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AERO_DATA_DIR", dir)
	return dir
}

func blockDefaultPort(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", defaultMixedListen)
	if err != nil {
		t.Skipf("默认端口已被占用，无法构造场景: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func dialable(t *testing.T, addr string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Errorf("%s 应可连接: %v", addr, err)
		return
	}
	_ = c.Close()
}

func TestResidentProxyFallsBackWhenDefaultPortUnavailable(t *testing.T) {
	dir := residentTestEnv(t)
	blockDefaultPort(t)

	eng := NewEngine()
	defer eng.Close()
	if err := eng.StartResidentMixedProxy(defaultMixedListen); err != nil {
		t.Fatalf("默认端口不可用时应回退，got %v", err)
	}
	got := eng.GetListenAddr()
	if got == defaultMixedListen {
		t.Fatalf("监听地址仍是默认端口 %s，应已回退", got)
	}
	st := eng.GetState()
	if !st.ResidentListening || st.Listen != got {
		t.Errorf("状态应报告真实地址与监听中，got listening=%v listen=%s", st.ResidentListening, st.Listen)
	}
	dialable(t, got)
	// 成功回退后记住端口
	if b, err := os.ReadFile(filepath.Join(dir, residentPortFile)); err != nil || !strings.HasSuffix(got, ":"+strings.TrimSpace(string(b))) {
		t.Errorf("应记住回退端口: file=%q err=%v got=%s", b, err, got)
	}
}

// 记住的端口优先于固定备用端口（让浏览器里填的端口尽量保持稳定）。
func TestResidentProxyPrefersRememberedPort(t *testing.T) {
	dir := residentTestEnv(t)
	blockDefaultPort(t)

	tmp, err := net.Listen("tcp", "127.0.0.1:0") // 找一个当前空闲的端口，用完即放
	if err != nil {
		t.Fatal(err)
	}
	remembered := tmp.Addr().(*net.TCPAddr).Port
	_ = tmp.Close()
	if err := os.WriteFile(filepath.Join(dir, residentPortFile), []byte(strconv.Itoa(remembered)), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine()
	defer eng.Close()
	if err := eng.StartResidentMixedProxy(defaultMixedListen); err != nil {
		t.Fatal(err)
	}
	if want := net.JoinHostPort("127.0.0.1", strconv.Itoa(remembered)); eng.GetListenAddr() != want {
		t.Errorf("应使用记住的端口 %s，got %s", want, eng.GetListenAddr())
	}
}

// 记住的端口文件损坏/越界：忽略，照常走固定备用端口。
func TestResidentProxyIgnoresBadRememberedPort(t *testing.T) {
	dir := residentTestEnv(t)
	blockDefaultPort(t)
	for _, bad := range []string{"", "abc", "80", "99999", "-1"} {
		if err := os.WriteFile(filepath.Join(dir, residentPortFile), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, a := range residentFallbackAddrs() {
			if strings.HasSuffix(a, ":80") || strings.HasSuffix(a, ":99999") || strings.HasSuffix(a, ":-1") {
				t.Errorf("坏的记忆值 %q 不应进入候选: %s", bad, a)
			}
		}
	}
}

// 固定备用端口全被占用：最后让系统分配一个，常驻代理仍然能起来。
func TestResidentProxyLastResortSystemAssignedPort(t *testing.T) {
	residentTestEnv(t)
	blockers := []net.Listener{blockDefaultPort(t)}
	for _, p := range mixedFallbackPorts {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", p))
		if err != nil {
			t.Skipf("端口 %s 已被占用，无法构造场景: %v", p, err)
		}
		blockers = append(blockers, l)
	}
	defer func() {
		for _, b := range blockers {
			_ = b.Close()
		}
	}()

	eng := NewEngine()
	defer eng.Close()
	if err := eng.StartResidentMixedProxy(defaultMixedListen); err != nil {
		t.Fatalf("所有固定端口都不可用时应由系统分配端口，got %v", err)
	}
	got := eng.GetListenAddr()
	for _, p := range append([]string{"55555"}, mixedFallbackPorts...) {
		if strings.HasSuffix(got, ":"+p) {
			t.Fatalf("不应是被占用的端口: %s", got)
		}
	}
	if !eng.GetState().ResidentListening {
		t.Error("应在监听")
	}
	dialable(t, got)
}

// 用户显式指定的地址失败时不回退，如实报错；状态为“未监听”。
func TestResidentProxyExplicitAddressDoesNotFallBack(t *testing.T) {
	residentTestEnv(t)
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	taken := blocker.Addr().String()

	eng := NewEngine()
	defer eng.Close()
	if err := eng.StartResidentMixedProxy(taken); err == nil {
		t.Fatal("显式指定且被占用的地址应报错，而不是悄悄换端口")
	}
	if eng.GetListenAddr() != taken {
		t.Errorf("显式地址不应被改写，got %s", eng.GetListenAddr())
	}
	if eng.GetState().ResidentListening {
		t.Error("没有监听时状态应为 false")
	}
}

func TestHostDescriptionAndElevationAvailable(t *testing.T) {
	if HostDescription() == "" {
		t.Error("系统描述不应为空")
	}
	_ = ProcessElevated() // 只要不 panic；结果取决于运行环境
}

// 固定备用端口：2~3 个，落在 8000–11000 之间，互不相同，且不是常见软件的默认端口。
func TestMixedFallbackPortsInAgreedRange(t *testing.T) {
	if n := len(mixedFallbackPorts); n < 2 || n > 3 {
		t.Fatalf("备用端口数 = %d, 期望 2~3 个", n)
	}
	common := map[int]string{8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-proxy", 8088: "http-alt",
		8118: "privoxy", 8123: "ha", 8200: "vault", 8443: "https-alt", 8500: "consul", 8545: "eth-rpc", 8787: "rstudio",
		8888: "jupyter", 8889: "alt", 8899: "alt", 9000: "php-fpm/minio", 9001: "tor-orport", 9042: "cassandra",
		9050: "tor-socks", 9051: "tor-control", 9090: "prometheus", 9091: "transmission", 9092: "kafka", 9100: "node-exporter",
		9200: "elasticsearch", 9300: "elasticsearch", 9418: "git", 9443: "alt-tls", 9999: "alt", 10000: "webmin",
		10001: "alt", 10050: "zabbix", 10051: "zabbix", 10250: "kubelet", 10808: "v2ray-socks", 10809: "v2ray-http"}
	seen := map[int]bool{}
	for _, s := range mixedFallbackPorts {
		p, err := strconv.Atoi(s)
		if err != nil || p < 8000 || p > 11000 {
			t.Errorf("备用端口 %q 不在 8000–11000 之间", s)
		}
		if seen[p] {
			t.Errorf("备用端口重复: %d", p)
		}
		seen[p] = true
		if name, bad := common[p]; bad {
			t.Errorf("备用端口 %d 是常见软件的默认端口（%s）", p, name)
		}
	}
}
