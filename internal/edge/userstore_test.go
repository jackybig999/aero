package edge

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func newTestUserStore(t *testing.T) (*UserStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "edge.db")
	s, err := OpenUserStore(path)
	if err != nil {
		t.Fatalf("OpenUserStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func sampleUser(n string) LocalUser {
	return LocalUser{
		UID: "u_local_" + n + "_0001", Username: "user" + n, Slug: "user" + n + "ab12cd",
		Tier: "local", Classes: []string{"default", "ai"}, MaxDevices: 3,
		QuotaBytes: 50 << 30, BWBps: 0, ExpireAt: time.Now().Add(24 * time.Hour).Unix(), Status: UserActive,
	}
}

func TestUserStoreCRUDRoundTrip(t *testing.T) {
	s, _ := newTestUserStore(t)
	u := sampleUser("a")
	if err := s.Create(u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, ok, err := s.Get(u.Slug)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.CreatedAt == 0 || got.UpdatedAt == 0 {
		t.Fatal("timestamps not set")
	}
	got.CreatedAt, got.UpdatedAt = 0, 0
	if !reflect.DeepEqual(got, u) {
		t.Fatalf("Get = %+v, want %+v", got, u)
	}
	if byUID, ok, _ := s.GetByUID(u.UID); !ok || byUID.Slug != u.Slug {
		t.Fatal("GetByUID did not find the user")
	}
	list, err := s.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %d users, err %v", len(list), err)
	}
	if err := s.Delete(u.Slug); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := s.Get(u.Slug); ok {
		t.Fatal("user still present after Delete")
	}
	if err := s.Delete(u.Slug); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("second Delete err = %v, want ErrUserNotFound", err)
	}
}

func TestUserStoreUniqueness(t *testing.T) {
	s, _ := newTestUserStore(t)
	u := sampleUser("a")
	if err := s.Create(u); err != nil {
		t.Fatal(err)
	}
	dupSlug := sampleUser("b")
	dupSlug.Slug = u.Slug
	dupName := sampleUser("c")
	dupName.Username = u.Username
	for name, d := range map[string]LocalUser{"slug": dupSlug, "username": dupName} {
		if err := s.Create(d); !errors.Is(err, ErrUserExists) {
			t.Errorf("duplicate %s: err = %v, want ErrUserExists", name, err)
		}
	}
}

func TestUserStoreRejectsInvalidInput(t *testing.T) {
	s, _ := newTestUserStore(t)
	bad := map[string]func(*LocalUser){
		"empty uid":      func(u *LocalUser) { u.UID = "" },
		"bad username":   func(u *LocalUser) { u.Username = "a b" },
		"bad slug":       func(u *LocalUser) { u.Slug = "../etc" },
		"unknown class":  func(u *LocalUser) { u.Classes = []string{"vip"} },
		"no class":       func(u *LocalUser) { u.Classes = nil },
		"zero devices":   func(u *LocalUser) { u.MaxDevices = 0 },
		"negative quota": func(u *LocalUser) { u.QuotaBytes = -1 },
		"unknown status": func(u *LocalUser) { u.Status = "weird" },
	}
	for name, mutate := range bad {
		u := sampleUser("x")
		mutate(&u)
		if err := s.Create(u); err == nil {
			t.Errorf("%s: Create accepted invalid user", name)
		}
	}
}

// 计量累加在并发下必须精确（单写连接，L0 §7.5 原子增减）。
func TestUserStoreConcurrentUsageIsExact(t *testing.T) {
	s, _ := newTestUserStore(t)
	u := sampleUser("a")
	if err := s.Create(u); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := s.AddUsage(u.UID, 1000); err != nil {
					t.Errorf("AddUsage: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	got, _, _ := s.Get(u.Slug)
	if got.UsedBytes != 20*50*1000 {
		t.Fatalf("UsedBytes = %d, want %d", got.UsedBytes, 20*50*1000)
	}
	if err := s.AddUsage("u_unknown_000001", 1); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("AddUsage for unknown uid: err = %v, want ErrUserNotFound", err)
	}
}

func TestUserStorePersistsAndAppliesPragmas(t *testing.T) {
	s, path := newTestUserStore(t)
	if err := s.Create(sampleUser("a")); err != nil {
		t.Fatal(err)
	}
	for _, db := range []string{"write", "read"} {
		h := s.write
		if db == "read" {
			h = s.read
		}
		var fk int
		var mode string
		if err := h.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
			t.Errorf("%s handle foreign_keys = %d (err %v), want 1", db, fk, err)
		}
		if err := h.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
			t.Errorf("%s handle journal_mode = %q (err %v), want wal", db, mode, err)
		}
	}
	_ = s.Close()
	if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
		t.Fatalf("database file not created at %s: %v", path, err)
	}

	s2, err := OpenUserStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if _, ok, _ := s2.Get(sampleUser("a").Slug); !ok {
		t.Fatal("user lost after reopen")
	}
}
