package connlimit

import (
	"sync"
	"testing"
)

func TestTryAcquireRelease(t *testing.T) {
	l := New(2, 2)
	if !l.TryAcquire("a") || !l.TryAcquire("a") {
		t.Fatal("expected two acquires for token a")
	}
	if l.TryAcquire("a") {
		t.Fatal("per-token limit should block third")
	}
	if l.Active() != 2 {
		t.Fatalf("active=%d want 2", l.Active())
	}
	l.Release("a")
	if !l.TryAcquire("a") {
		t.Fatal("after release should allow")
	}
	l.Release("a")
	l.Release("a")
	if l.Active() != 0 {
		t.Fatalf("active=%d want 0", l.Active())
	}
}

func TestGlobalLimit(t *testing.T) {
	l := New(2, 100)
	if !l.TryAcquire("a") || !l.TryAcquire("b") {
		t.Fatal("two tokens should fill global")
	}
	if l.TryAcquire("c") {
		t.Fatal("global full should reject")
	}
	l.Release("a")
	if !l.TryAcquire("c") {
		t.Fatal("after release should allow other token")
	}
}

func TestConcurrent(t *testing.T) {
	l := New(100, 50)
	var wg sync.WaitGroup
	var okN int64
	var mu sync.Mutex
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.TryAcquire("u") {
				mu.Lock()
				okN++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if okN != 50 {
		t.Fatalf("okN=%d want 50 (per-token)", okN)
	}
	if l.Active() != 50 {
		t.Fatalf("active=%d want 50", l.Active())
	}
}
