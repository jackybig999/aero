package sub

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 管理员账号引导（替代 SeedAdmin）。旧实现的问题：固定 slug "superadmin"（可匿名猜中）、
// 默认密码 admin123456、错误全部丢弃。规则：
//   - 初始密码来自 ADMIN_INIT_PASSWORD；未设置时随机生成，只写入 <dataDir>/initial_admin_password（0600），不进日志。
//   - 账号仍是旧默认密码时强制换成随机密码（同样写入该文件）。
//   - 管理员订阅 slug 必须是 "admin" + 128 位随机十六进制；遗留的 "superadmin" 或低熵 slug 一律轮换。
//   - 管理员订阅不限量（limit_bytes=0）、不限期（零值 expire_at）。

const (
	adminUsername        = "admin"
	adminSlugPrefix      = "admin"
	adminSlugRandomBytes = 16
	adminPasswordFile    = "initial_admin_password"
	legacyAdminSlug      = "superadmin"
	legacyAdminPassword  = "admin123456"
)

// EnsureAdmin 保证管理员账号与其订阅存在且凭证安全；可重复调用（幂等）。
func EnsureAdmin(svc *UserService, store UserStore, dataDir string) error {
	admin, err := store.GetUserByUsername(adminUsername)
	if err != nil || admin == nil {
		if admin, err = createAdmin(svc, store, dataDir); err != nil {
			return err
		}
	} else {
		if !admin.IsStaff {
			if err := store.SetStaff(admin.ID, true); err != nil {
				return fmt.Errorf("mark admin as staff: %w", err)
			}
		}
		if admin.PasswordHash == "" || CheckPassword(legacyAdminPassword, admin.PasswordHash) {
			pwd, err := initialAdminPassword(dataDir)
			if err != nil {
				return err
			}
			if err := store.SetPassword(admin.ID, HashPassword(pwd)); err != nil {
				return fmt.Errorf("set admin password: %w", err)
			}
		}
	}

	slug := admin.SubSlug
	if !isStrongAdminSlug(slug) {
		if slug, err = newAdminSlug(); err != nil {
			return err
		}
		if err := store.UpdateSubSlug(admin.ID, slug); err != nil {
			return fmt.Errorf("rotate admin slug: %w", err)
		}
	}
	return ensureAdminSubscription(store, admin, slug)
}

func createAdmin(svc *UserService, store UserStore, dataDir string) (*User, error) {
	pwd, err := initialAdminPassword(dataDir)
	if err != nil {
		return nil, err
	}
	admin, err := svc.Register(CreateUserParams{Username: adminUsername, Password: pwd, IsStaff: true})
	if err != nil {
		return nil, fmt.Errorf("create admin: %w", err)
	}
	if err := store.SetStaff(admin.ID, true); err != nil {
		return nil, fmt.Errorf("mark admin as staff: %w", err)
	}
	return admin, nil
}

// ensureAdminSubscription 没有订阅时创建；已有订阅中凡 slug 不合格的逐个轮换（slug 在订阅表内唯一）。
func ensureAdminSubscription(store UserStore, admin *User, slug string) error {
	subs, err := store.ListSubscriptions(admin.ID)
	if err != nil {
		return fmt.Errorf("list admin subscriptions: %w", err)
	}
	if len(subs) == 0 {
		now := time.Now()
		token, err := randomHex(16)
		if err != nil {
			return err
		}
		seed, err := randomHex(24)
		if err != nil {
			return err
		}
		return store.CreateSubscription(&Subscription{
			SubID:         "sub_admin_" + token[:12],
			UserID:        admin.ID,
			UserUUID:      admin.UUID,
			SubSlug:       slug,
			SubToken:      token,
			SubTicketSeed: "sec_" + seed,
			PlanName:      "管理员",
			AssignedNodes: []string{},
			SwitchStatus:  "on",
			Status:        true,
			CreatedAt:     now,
			UpdatedAt:     now,
		})
	}
	for i, s := range subs {
		if isStrongAdminSlug(s.SubSlug) {
			continue
		}
		next := slug
		if i > 0 { // 第二个起各自独立，避免订阅表唯一约束冲突
			if next, err = newAdminSlug(); err != nil {
				return err
			}
		}
		if err := store.UpdateSubscriptionSlug(s.SubID, next); err != nil {
			return fmt.Errorf("rotate admin subscription slug: %w", err)
		}
	}
	return nil
}

// initialAdminPassword 返回 ADMIN_INIT_PASSWORD；未设置时生成随机密码并原子写入 0600 文件。
// 先写文件、后改账号，保证不会出现“密码已改但无人知道”的状态。
func initialAdminPassword(dataDir string) (string, error) {
	if pwd := strings.TrimSpace(os.Getenv("ADMIN_INIT_PASSWORD")); pwd != "" {
		if err := ValidatePassword(pwd); err != nil {
			return "", fmt.Errorf("ADMIN_INIT_PASSWORD: %w", err)
		}
		if pwd == legacyAdminPassword {
			return "", errors.New("ADMIN_INIT_PASSWORD must not be the legacy default password")
		}
		return pwd, nil
	}
	var pwd string
	for {
		h, err := randomHex(16)
		if err != nil {
			return "", err
		}
		if ValidatePassword(h) == nil { // 十六进制几乎总含字母和数字；极少数不满足时重抽
			pwd = h
			break
		}
	}
	path := filepath.Join(dataDir, adminPasswordFile)
	tmp, err := os.CreateTemp(dataDir, adminPasswordFile+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("write initial admin password: %w", err)
	}
	_, werr := tmp.WriteString(pwd + "\n")
	if werr == nil {
		werr = tmp.Chmod(0o600)
	}
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), path)
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("write initial admin password: %w", werr)
	}
	return pwd, nil
}

func isStrongAdminSlug(slug string) bool {
	rest, ok := strings.CutPrefix(slug, adminSlugPrefix)
	if !ok || len(rest) != 2*adminSlugRandomBytes {
		return false
	}
	_, err := hex.DecodeString(rest)
	return err == nil
}

func newAdminSlug() (string, error) {
	h, err := randomHex(adminSlugRandomBytes)
	if err != nil {
		return "", err
	}
	return adminSlugPrefix + h, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}
