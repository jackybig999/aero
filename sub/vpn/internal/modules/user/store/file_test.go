package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/domain"
)

func TestUserFileStorePersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "user_file_store_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "users.json")
	fs1, err := NewFileStore(filePath)
	if err != nil {
		t.Fatalf("new file store 1: %v", err)
	}

	u := &domain.User{
		Username:     "jacky",
		PasswordHash: "sha256:salted_hash_xyz",
		Email:        "jacky@test.com",
		Status:       true,
		IsStaff:      false,
		SubSlug:      "jacky888abc",
		SubToken:     "usr_token_9999",
		ExpireAt:     time.Now().AddDate(1, 0, 0),
	}
	id, err := fs1.CreateUser(u)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if id != 1 {
		t.Fatalf("expected id 1, got %d", id)
	}

	// 模拟重启进程：新建 FileStore 加载同一个文件
	fs2, err := NewFileStore(filePath)
	if err != nil {
		t.Fatalf("new file store 2: %v", err)
	}

	loaded, err := fs2.GetUserBySlug("jacky888abc")
	if err != nil {
		t.Fatalf("get by slug after restart: %v", err)
	}
	if loaded.Username != "jacky" || loaded.SubToken != "usr_token_9999" {
		t.Fatalf("user data mismatch after restart: %+v", loaded)
	}

	// 测试更新与持久化
	newEmail := "jacky_updated@test.com"
	err = fs2.UpdateUser(id, &newEmail, nil, nil)
	if err != nil {
		t.Fatalf("update user: %v", err)
	}

	fs3, err := NewFileStore(filePath)
	if err != nil {
		t.Fatalf("new file store 3: %v", err)
	}
	loaded3, _ := fs3.GetUser(id)
	if loaded3.Email != newEmail {
		t.Fatalf("expected updated email %s, got %s", newEmail, loaded3.Email)
	}
}
