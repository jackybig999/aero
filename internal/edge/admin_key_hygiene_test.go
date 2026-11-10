package edge

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// 回归：自动生成的 AdminKey 曾以明文写入启动日志（journald 等日志的读者即可获得管理权限）。
func TestAdminKeyHygieneGeneratedKeyIsNotLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	srv, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", DataDir: t.TempDir(), Domain: "example.test", AllowSelfSignedCertForTest: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	key := srv.cfg.AdminKey
	if len(key) < 32 {
		t.Fatalf("generated admin key too short: %d", len(key))
	}
	if strings.Contains(buf.String(), key) {
		t.Fatal("generated admin key appears in plaintext in the log")
	}
}
