package edge

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeTokensFile(t *testing.T, dir string, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "tokens.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write tokens.json: %v", err)
	}
}

const tokensFileAB = `{"version":1,"tokens":[
 {"token":"tok_a","label":"a","created_at":"2026-01-02T03:04:05Z","expires_at":"2099-01-01T00:00:00Z"},
 {"token":"tok_b","label":"b","created_at":"2026-01-02T03:04:05Z","expires_at":"2099-01-01T00:00:00Z"}]}`

// 文件损坏时 Reload 必须报错并保留原有 token，不得清空导致全部用户掉线。
func TestTokenStoreReloadKeepsTokensWhenFileIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	writeTokensFile(t, dir, tokensFileAB)
	v := NewValidator()
	ts, err := OpenTokenStore(dir, v)
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}

	writeTokensFile(t, dir, `{"version":1,"tokens":[`)
	if _, err := ts.Reload(); err == nil {
		t.Fatal("Reload of a corrupt file returned nil error")
	}
	if !v.Validate("tok_a") || !v.Validate("tok_b") {
		t.Fatal("tokens were dropped after a failed reload")
	}
}

// Reload 用新文件内容原子替换：被移除的 token 失效，保留的 token 不出现失效窗口。
func TestTokenStoreReloadIsAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	writeTokensFile(t, dir, tokensFileAB)
	v := NewValidator()
	ts, err := OpenTokenStore(dir, v)
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}

	var sawInvalid atomic.Bool
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if !v.Validate("tok_a") {
					sawInvalid.Store(true)
				}
			}
		}
	}()
	for i := 0; i < 200; i++ {
		if _, err := ts.Reload(); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("Reload: %v", err)
		}
	}
	close(stop)
	wg.Wait()
	if sawInvalid.Load() {
		t.Fatal("tok_a was observed invalid during reload (clear-then-load window)")
	}

	writeTokensFile(t, dir, `{"version":1,"tokens":[{"token":"tok_a","label":"a","expires_at":"2099-01-01T00:00:00Z"}]}`)
	n, err := ts.Reload()
	if err != nil || n != 1 {
		t.Fatalf("Reload = (%d, %v), want (1, nil)", n, err)
	}
	if v.Validate("tok_b") {
		t.Fatal("tok_b removed from file is still valid")
	}
}

// 重载保留文件中的 CreatedAt，而不是改成重载时刻。
func TestTokenStoreReloadPreservesCreatedAt(t *testing.T) {
	dir := t.TempDir()
	writeTokensFile(t, dir, tokensFileAB)
	v := NewValidator()
	ts, err := OpenTokenStore(dir, v)
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	if _, err := ts.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, info := range v.ListTokens() {
		if !info.CreatedAt.Equal(want) {
			t.Fatalf("token %s CreatedAt = %v, want %v", info.Label, info.CreatedAt, want)
		}
	}
}
