package bwlimit

import (
	"testing"
	"time"
)

func TestUnlimited(t *testing.T) {
	l := New(0)
	start := time.Now()
	l.Take("u", 1<<20)
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("unlimited should not sleep")
	}
}

func TestRateSlows(t *testing.T) {
	l := New(10_000) // 10KB/s
	// 吃掉 burst
	l.Take("u", 20_000)
	start := time.Now()
	l.Take("u", 10_000) // 约需 1s
	elapsed := time.Since(start)
	if elapsed < 400*time.Millisecond {
		t.Fatalf("expected throttle, elapsed=%v", elapsed)
	}
}
