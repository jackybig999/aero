//go:build linux

package edge

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestEdgeTunIfreqUsesKernelSizedStruct(t *testing.T) {
	ifr, err := newEdgeTunIfreq("aero-tun0")
	if err != nil {
		t.Fatalf("newEdgeTunIfreq: %v", err)
	}
	if got := ifr.Name(); got != "aero-tun0" {
		t.Fatalf("Name() = %q, want aero-tun0", got)
	}
	if got := ifr.Uint16(); got != unix.IFF_TUN|unix.IFF_NO_PI {
		t.Fatalf("flags = %#x, want IFF_TUN|IFF_NO_PI (%#x)", got, unix.IFF_TUN|unix.IFF_NO_PI)
	}
}

func TestEdgeTunIfreqRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{"", strings.Repeat("x", unix.IFNAMSIZ)} {
		if _, err := newEdgeTunIfreq(name); err == nil {
			t.Errorf("newEdgeTunIfreq(%q) succeeded, want error", name)
		}
	}
}

// 回归（v1.3.0 线上故障）：os.OpenFile 打开 /dev/net/tun 后 Read 立即返回 "not pollable"，
// 共享 TUN 下行读取协程一启动即退出，CONNECT-IP 无回包。本测试真正从设备读包，
// 并验证 Close 能唤醒阻塞中的 Read。在独立用户 + 网络命名空间中运行，不触碰宿主网络。
func TestGlobalTunnelDeviceReadsPacketsAndCloseUnblocks(t *testing.T) {
	if os.Getenv("AERO_NETNS") != "1" {
		if _, err := exec.LookPath("unshare"); err != nil {
			t.Skip("unshare not available")
		}
		out, err := exec.Command("unshare", "-rn", "env", "AERO_NETNS=1", os.Args[0],
			"-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v").CombinedOutput()
		if err != nil {
			if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "unshare failed") {
				t.Skipf("user/net namespaces not permitted: %s", out)
			}
			t.Fatalf("netns run failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
			t.Fatalf("netns run did not pass:\n%s", out)
		}
		return
	}

	d, err := openGlobalTunnelDevice("zztun0")
	if err != nil {
		t.Fatalf("openGlobalTunnelDevice: %v", err)
	}
	for _, args := range [][]string{{"link", "set", "zztun0", "up"}, {"addr", "add", "10.99.0.1/24", "dev", "zztun0"}} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	// 发往 10.99.0.2 的包经 zztun0 进入设备；用 UDP 发送，不依赖 ping 权限。
	conn, err := net.Dial("udp4", "10.99.0.2:9")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	found := false
	for i := 0; i < 20 && !found; i++ { // 跳过系统在新网卡上发出的 IPv6 RS/MLD 等报文
		n, err := d.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		found = n >= 20 && buf[0]>>4 == 4 && net.IP(buf[16:20]).Equal(net.IPv4(10, 99, 0, 2))
	}
	if !found {
		t.Fatal("IPv4 probe to 10.99.0.2 not read from the device")
	}

	// Close 必须唤醒阻塞中的 Read（停机时读取协程才能退出）
	done := make(chan error, 1)
	go func() {
		_, err := d.Read(buf)
		done <- err
	}()
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read after Close returned %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock a pending Read")
	}
}
