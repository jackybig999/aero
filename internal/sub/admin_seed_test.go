package sub

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 两种存储都要验证：MemoryUserStore 与真实 SQLite（AeroDB）。
func adminSeedStores(t *testing.T) map[string]UserStore {
	t.Helper()
	db, err := NewAeroDB(filepath.Join(t.TempDir(), "aero.db"), nil)
	if err != nil {
		t.Fatalf("NewAeroDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return map[string]UserStore{"memory": NewMemoryUserStore(), "sqlite": db}
}

func readAdminPasswordFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, adminPasswordFile)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("initial password file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("initial password file mode = %v, want 0600", fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// 新部署：随机密码只写入 0600 文件；slug 高熵；订阅不限量、不限期；固定名称取不到订阅。
func TestEnsureAdminFreshInstall(t *testing.T) {
	t.Setenv("ADMIN_INIT_PASSWORD", "")
	for name, store := range adminSeedStores(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := EnsureAdmin(NewUserService(store, "hmac-test"), store, dir); err != nil {
				t.Fatalf("EnsureAdmin: %v", err)
			}
			admin, err := store.GetUserByUsername("admin")
			if err != nil || admin == nil || !admin.IsStaff {
				t.Fatalf("admin = %+v, err = %v", admin, err)
			}
			pwd := readAdminPasswordFile(t, dir)
			if pwd == legacyAdminPassword || !CheckPassword(pwd, admin.PasswordHash) {
				t.Fatal("admin password does not match the generated initial password")
			}
			if !isStrongAdminSlug(admin.SubSlug) {
				t.Fatalf("admin slug %q is not a strong admin slug", admin.SubSlug)
			}
			subs, err := store.ListSubscriptions(admin.ID)
			if err != nil || len(subs) != 1 {
				t.Fatalf("subscriptions = %d, err = %v", len(subs), err)
			}
			s := subs[0]
			if s.SubSlug != admin.SubSlug || s.LimitBytes != 0 || !s.ExpireAt.IsZero() || !s.Status {
				t.Fatalf("admin subscription = %+v, want own slug, unlimited, no expiry, active", s)
			}
			if got, _ := store.GetSubscriptionBySlug(legacyAdminSlug); got != nil {
				t.Fatal("subscription reachable via legacy slug")
			}

			mux := http.NewServeMux()
			NewSubBuilder(store, nil, nil, nil).RegisterRoutes(mux)
			for path, want := range map[string]int{"/sub/superadmin": 404, "/sub/admin": 404, "/sub/" + admin.SubSlug: 200} {
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
				if rec.Code != want {
					t.Errorf("GET %s = %d, want %d", path, rec.Code, want)
				}
			}
		})
	}
}

// 再次运行幂等：已修改的密码、已轮换的 slug 与订阅都不变。
func TestEnsureAdminIsIdempotent(t *testing.T) {
	t.Setenv("ADMIN_INIT_PASSWORD", "")
	for name, store := range adminSeedStores(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			svc := NewUserService(store, "hmac-test")
			if err := EnsureAdmin(svc, store, dir); err != nil {
				t.Fatal(err)
			}
			admin, _ := store.GetUserByUsername("admin")
			if err := store.SetPassword(admin.ID, HashPassword("CustomAdminPass2026")); err != nil {
				t.Fatal(err)
			}
			if err := EnsureAdmin(svc, store, dir); err != nil {
				t.Fatal(err)
			}
			after, _ := store.GetUserByUsername("admin")
			if !CheckPassword("CustomAdminPass2026", after.PasswordHash) {
				t.Fatal("custom admin password was overwritten")
			}
			if after.SubSlug != admin.SubSlug {
				t.Fatalf("slug changed on re-run: %q -> %q", admin.SubSlug, after.SubSlug)
			}
			if subs, _ := store.ListSubscriptions(admin.ID); len(subs) != 1 || subs[0].SubSlug != admin.SubSlug {
				t.Fatalf("subscriptions changed on re-run: %+v", subs)
			}
		})
	}
}

// 旧版部署升级：slug "superadmin"、默认密码 admin123456 必须被轮换。
func TestEnsureAdminRotatesLegacyState(t *testing.T) {
	t.Setenv("ADMIN_INIT_PASSWORD", "")
	for name, store := range adminSeedStores(t) {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			id, err := store.CreateUser(&User{UUID: "u_legacy", Username: "admin", PasswordHash: HashPassword(legacyAdminPassword),
				SubSlug: legacyAdminSlug, SubToken: "tok", Status: true, IsStaff: true, CreatedAt: time.Now(), UpdatedAt: time.Now()})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			if err := store.CreateSubscription(&Subscription{SubID: "sub_admin_legacy", UserID: id, UserUUID: "u_legacy",
				SubSlug: legacyAdminSlug, SubToken: "tok", SubTicketSeed: "sec_x", PlanName: "管理员专享订阅",
				LimitBytes: 10 << 40, ExpireAt: now.AddDate(10, 0, 0), SwitchStatus: "on", Status: true,
				CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}

			if err := EnsureAdmin(NewUserService(store, "hmac-test"), store, dir); err != nil {
				t.Fatalf("EnsureAdmin: %v", err)
			}
			admin, _ := store.GetUserByUsername("admin")
			if CheckPassword(legacyAdminPassword, admin.PasswordHash) {
				t.Fatal("legacy default password still valid")
			}
			if !CheckPassword(readAdminPasswordFile(t, dir), admin.PasswordHash) {
				t.Fatal("rotated password not written to the initial password file")
			}
			if !isStrongAdminSlug(admin.SubSlug) {
				t.Fatalf("admin slug not rotated: %q", admin.SubSlug)
			}
			if got, _ := store.GetSubscriptionBySlug(legacyAdminSlug); got != nil {
				t.Fatal("legacy subscription slug still resolvable")
			}
			if got, _ := store.GetSubscriptionBySlug(admin.SubSlug); got == nil || got.SubID != "sub_admin_legacy" {
				t.Fatalf("legacy subscription not moved to the new slug: %+v", got)
			}
		})
	}
}

// ADMIN_INIT_PASSWORD 生效时不写密码文件；设置为旧默认密码时拒绝启动。
func TestEnsureAdminInitPasswordFromEnv(t *testing.T) {
	store := NewMemoryUserStore()
	dir := t.TempDir()
	t.Setenv("ADMIN_INIT_PASSWORD", legacyAdminPassword)
	if err := EnsureAdmin(NewUserService(store, "hmac-test"), store, dir); err == nil {
		t.Fatal("legacy default password accepted from ADMIN_INIT_PASSWORD")
	}
	t.Setenv("ADMIN_INIT_PASSWORD", "OperatorChosen2026")
	if err := EnsureAdmin(NewUserService(store, "hmac-test"), store, dir); err != nil {
		t.Fatal(err)
	}
	admin, _ := store.GetUserByUsername("admin")
	if !CheckPassword("OperatorChosen2026", admin.PasswordHash) {
		t.Fatal("ADMIN_INIT_PASSWORD not applied")
	}
	if _, err := os.Stat(filepath.Join(dir, adminPasswordFile)); !os.IsNotExist(err) {
		t.Fatalf("password file written although ADMIN_INIT_PASSWORD was set (err=%v)", err)
	}
}
