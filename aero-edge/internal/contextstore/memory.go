package contextstore

import (
	"sync"
	"time"
)

// MemoryStore 内存 LRU 风格上下文（默认热路径，无磁盘 I/O，适合多用户）。
type MemoryStore struct {
	mu      sync.RWMutex
	max     int
	items   map[string]*StreamContext
	order   []string // 粗略 FIFO 淘汰
}

// NewMemory 创建内存存储；max≤0 则 4096。
func NewMemory(max int) *MemoryStore {
	if max <= 0 {
		max = 4096
	}
	return &MemoryStore{
		max:   max,
		items: make(map[string]*StreamContext),
	}
}

// Save 保存上下文。
func (s *MemoryStore) Save(ctx StreamContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if ctx.CreatedAt.IsZero() {
		ctx.CreatedAt = now
	}
	ctx.UpdatedAt = now
	if _, ok := s.items[ctx.ContextID]; !ok {
		s.order = append(s.order, ctx.ContextID)
	}
	cp := ctx
	s.items[ctx.ContextID] = &cp
	for len(s.items) > s.max && len(s.order) > 0 {
		old := s.order[0]
		s.order = s.order[1:]
		delete(s.items, old)
	}
	return nil
}

// Get 查询。
func (s *MemoryStore) Get(contextID string) (*StreamContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.items[contextID]
	if !ok {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

// Delete 删除。
func (s *MemoryStore) Delete(contextID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, contextID)
	return nil
}

// Cleanup 按 TTL 清理。
func (s *MemoryStore) Cleanup(ttl time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-ttl)
	n := 0
	for id, c := range s.items {
		if c.UpdatedAt.Before(cutoff) {
			delete(s.items, id)
			n++
		}
	}
	// 重建 order
	s.order = s.order[:0]
	for id := range s.items {
		s.order = append(s.order, id)
	}
	return n, nil
}

// Count 数量。
func (s *MemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

// Close 无操作。
func (s *MemoryStore) Close() error { return nil }
