package sub

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"
)

func legacySHA256Hash(salt, password string) string {
	return fmt.Sprintf("sha256:%s:%x", salt, sha256.Sum256([]byte(salt+password)))
}

func TestHashPasswordArgon2id(t *testing.T) {
	h1, h2 := HashPassword("MySecureP@ssw0rd999"), HashPassword("MySecureP@ssw0rd999")
	if h1 == h2 {
		t.Fatal("same password produced identical hashes (salt not random)")
	}
	if !strings.HasPrefix(h1, "argon2id$v=19$m=19456,t=2,p=1$") || strings.Count(h1, "$") != 4 {
		t.Fatalf("unexpected format: %s", h1)
	}
	if !CheckPassword("MySecureP@ssw0rd999", h1) || !CheckPassword("MySecureP@ssw0rd999", h2) {
		t.Fatal("correct password rejected")
	}
	if CheckPassword("MySecureP@ssw0rd998", h1) || CheckPassword("", h1) {
		t.Fatal("wrong password accepted")
	}
	if passwordNeedsRehash(h1) {
		t.Fatal("current hash flagged for rehash")
	}
}

func TestCheckPasswordLegacyAndMalformed(t *testing.T) {
	legacy := legacySHA256Hash("0123456789abcdef0123456789abcdef", "OldPassword1")
	if !CheckPassword("OldPassword1", legacy) || CheckPassword("OldPassword2", legacy) {
		t.Fatal("legacy sha256 hash not verified correctly")
	}
	if !passwordNeedsRehash(legacy) {
		t.Fatal("legacy hash not flagged for rehash")
	}
	for _, bad := range []string{
		"", "plain", "sha256:1234:5678", "argon2id$v=19$m=19456,t=2,p=1$bad$bad",
		"argon2id$v=18$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5",
		// 构造的超大内存参数必须被拒绝，不能真的分配
		"argon2id$v=19$m=4294967295,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5",
		"argon2id$v=19$m=19456,t=4294967295,p=1$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5",
	} {
		start := time.Now()
		if CheckPassword("x", bad) {
			t.Errorf("malformed hash %q accepted", bad)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("malformed hash %q took %v (parameter bomb not rejected)", bad, d)
		}
	}
}

// 旧格式密码在登录成功时迁移为 argon2id；登录失败不改动；不存在的用户返回同一错误。
func TestLoginMigratesLegacyHash(t *testing.T) {
	store := NewMemoryUserStore()
	svc := NewUserService(store, "hmac-test-secret")
	id, err := store.CreateUser(&User{UUID: "u_1", Username: "alice", PasswordHash: legacySHA256Hash("00112233445566778899aabbccddeeff", "AlicePass123"), Status: true, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Login("alice", "WrongPass123"); err != ErrInvalidCredentials {
		t.Fatalf("wrong password: err = %v", err)
	}
	if u, _ := store.GetUser(id); !strings.HasPrefix(u.PasswordHash, "sha256:") {
		t.Fatal("hash changed after a failed login")
	}
	if _, _, err := svc.Login("alice", "AlicePass123"); err != nil {
		t.Fatalf("correct legacy password rejected: %v", err)
	}
	u, _ := store.GetUser(id)
	if !strings.HasPrefix(u.PasswordHash, argonPrefix) || !CheckPassword("AlicePass123", u.PasswordHash) {
		t.Fatalf("legacy hash not migrated: %s", u.PasswordHash)
	}
	if _, _, err := svc.Login("alice", "AlicePass123"); err != nil {
		t.Fatalf("login after migration failed: %v", err)
	}
	if _, _, err := svc.Login("nobody", "AlicePass123"); err != ErrInvalidCredentials {
		t.Fatalf("unknown user: err = %v", err)
	}
}
