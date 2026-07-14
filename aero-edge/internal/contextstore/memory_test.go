package contextstore

import (
	"testing"
	"time"
)

func TestMemorySaveGet(t *testing.T) {
	s := NewMemory(2)
	if err := s.Save(StreamContext{ContextID: "a", LastSequence: 1}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("a")
	if err != nil || got == nil || got.LastSequence != 1 {
		t.Fatalf("get: %+v err=%v", got, err)
	}
	_ = s.Save(StreamContext{ContextID: "b"})
	_ = s.Save(StreamContext{ContextID: "c"}) // evicts oldest
	if s.Count() > 2 {
		t.Fatalf("count=%d want <=2", s.Count())
	}
}

func TestMemoryCleanup(t *testing.T) {
	s := NewMemory(10)
	_ = s.Save(StreamContext{ContextID: "old", UpdatedAt: time.Now().Add(-time.Hour)})
	// force old timestamp after save overwrites UpdatedAt — use cleanup with 0 by sleeping
	// Save always sets UpdatedAt=now; delete via Cleanup short TTL after manual age:
	s.mu.Lock()
	if c := s.items["old"]; c != nil {
		c.UpdatedAt = time.Now().Add(-time.Hour)
	}
	s.mu.Unlock()
	n, err := s.Cleanup(time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("cleanup n=%d err=%v", n, err)
	}
}
