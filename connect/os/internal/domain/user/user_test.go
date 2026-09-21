package user

import (
	"os"
	"path/filepath"
	"testing"

	"aisys/connect/os/internal/infra/db"
)

func TestUserAuth(t *testing.T) {
	tempDir := t.TempDir()
	testDBPath := filepath.Join(tempDir, "test_user.db")
	defer os.Remove(testDBPath)

	database, err := db.InitDB(testDBPath)
	if err != nil {
		t.Fatalf("InitDB 失败: %v", err)
	}
	defer db.CloseDB()

	// 1. 注册新用户
	u, err := RegisterUser(database, "admin", "SecurePass123!")
	if err != nil {
		t.Fatalf("注册用户失败: %v", err)
	}
	if u.Username != "admin" {
		t.Errorf("用户名不匹配: 期望 admin, 得到 %s", u.Username)
	}

	// 2. 重复注册拦截
	_, err = RegisterUser(database, "admin", "AnotherPass")
	if err != ErrUserExists {
		t.Errorf("重复注册未被正确拦截: %v", err)
	}

	// 3. 密码错误登录
	_, _, err = AuthenticateUser(database, "admin", "WrongPass")
	if err != ErrInvalidPassword {
		t.Errorf("密码错误未被识别: %v", err)
	}

	// 4. 正确密码登录与 Token 签发
	loggedUser, token, err := AuthenticateUser(database, "admin", "SecurePass123!")
	if err != nil || token == "" {
		t.Fatalf("登录失败: %v", err)
	}

	// 5. Token 校验
	validatedUser, err := ValidateToken(token)
	if err != nil || validatedUser.ID != loggedUser.ID {
		t.Fatalf("Token 校验失败: %v", err)
	}

	// 6. 验证通用标准注册与邮箱登录
	user2, err := RegisterUserWithEmail(database, "jacky", "jacky@aero.com", "SecretPass666")
	if err != nil {
		t.Fatalf("标准注册失败: %v", err)
	}

	loginByEmailUser, emailToken, err := AuthenticateUser(database, "jacky@aero.com", "SecretPass666")
	if err != nil || emailToken == "" || loginByEmailUser.ID != user2.ID {
		t.Fatalf("邮箱登录失败: %v", err)
	}

	// 7. 统计用户数量
	count, err := CountUsers(database)
	if err != nil || count != 2 {
		t.Errorf("用户总数统计异常: %d, err: %v", count, err)
	}

	// 8. 验证持久化活跃会话 (Remember Me)
	err = SaveSessionUser(database, user2.ID)
	if err != nil {
		t.Fatalf("保存会话失败: %v", err)
	}
	savedUser, err := GetSavedSessionUser(database)
	if err != nil || savedUser == nil || savedUser.Username != "jacky" {
		t.Fatalf("读取持久化会话失败: %v", err)
	}

	err = ClearSessionUser(database)
	if err != nil {
		t.Fatalf("清除会话失败: %v", err)
	}
	clearedUser, _ := GetSavedSessionUser(database)
	if clearedUser != nil {
		t.Fatalf("清除会话后仍存在残留")
	}
}
