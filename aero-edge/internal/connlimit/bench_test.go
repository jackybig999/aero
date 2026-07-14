package connlimit

import (
	"sync"
	"testing"
)

func BenchmarkTryAcquireRelease(b *testing.B) {
	l := New(1_000_000, 1_000_000)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if l.TryAcquire("bench") {
				l.Release("bench")
			}
		}
	})
}

func TestHighConcurrencyBalance(t *testing.T) {
	const workers = 64
	const each = 200
	l := New(workers*each, each)
	var wg sync.WaitGroup
	var got int64
	var mu sync.Mutex
	for w := 0; w < workers; w++ {
		wg.Add(1)
		tok := string(rune('a'+w%26)) + string(rune('0'+w/26))
		go func(token string) {
			defer wg.Done()
			local := 0
			for i := 0; i < each; i++ {
				if l.TryAcquire(token) {
					local++
				}
			}
			mu.Lock()
			got += int64(local)
			mu.Unlock()
		}(tok)
	}
	wg.Wait()
	// each token max = each, so total should be workers*each if global allows
	want := int64(workers * each)
	if got != want {
		t.Fatalf("acquired=%d want=%d active=%d", got, want, l.Active())
	}
	if l.Active() != want {
		t.Fatalf("active=%d want %d", l.Active(), want)
	}
	// release all
	for w := 0; w < workers; w++ {
		tok := string(rune('a'+w%26)) + string(rune('0'+w/26))
		for i := 0; i < each; i++ {
			l.Release(tok)
		}
	}
	if l.Active() != 0 {
		t.Fatalf("after release active=%d", l.Active())
	}
}
