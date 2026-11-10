package edge

import (
	"strings"
	"testing"
)

func newLockTestServer(t *testing.T, dir string) (*Server, error) {
	t.Helper()
	return NewServer(ServerConfig{Listen: "127.0.0.1:0", DataDir: dir, Domain: "example.test", AllowSelfSignedCertForTest: true})
}

// 回归（ADR-0005）：第二个实例使用同一数据目录时曾避让到其他端口照常启动，
// 与前一实例同时读写 tokens.json / sub_meta.json。必须拒绝启动。
func TestInstanceLockSecondServerOnSameDataDirFails(t *testing.T) {
	dir := t.TempDir()
	first, err := newLockTestServer(t, dir)
	if err != nil {
		t.Fatalf("first NewServer: %v", err)
	}

	second, err := newLockTestServer(t, dir)
	if err == nil {
		second.Close()
		first.Close()
		t.Fatal("second NewServer on the same data dir succeeded")
	}
	if !strings.Contains(err.Error(), "another edge instance") {
		t.Fatalf("unexpected error: %v", err)
	}

	first.Close()
	third, err := newLockTestServer(t, dir)
	if err != nil {
		t.Fatalf("NewServer after the first instance closed: %v", err)
	}
	third.Close()
}

// 不同数据目录互不影响。
func TestInstanceLockDifferentDataDirsAreIndependent(t *testing.T) {
	a, err := newLockTestServer(t, t.TempDir())
	if err != nil {
		t.Fatalf("NewServer a: %v", err)
	}
	defer a.Close()
	b, err := newLockTestServer(t, t.TempDir())
	if err != nil {
		t.Fatalf("NewServer b: %v", err)
	}
	b.Close()
}
