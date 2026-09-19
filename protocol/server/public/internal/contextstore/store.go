// Package contextstore：AI 流断线续传上下文。
// 默认使用纯内存 MemoryStore（零磁盘 I/O 开销，高并发低延迟）。
package contextstore

import (
	"time"
)

// StreamContext AI 流上下文记录
type StreamContext struct {
	ContextID        string
	SessionID        string
	StreamID         uint32
	TargetHost       string
	TargetPort       uint32
	LastSequence     uint64
	BytesTransferred uint64
	ModelName        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Backend 统一接口（纯内存读写锁实现）
type Backend interface {
	Save(ctx StreamContext) error
	Get(contextID string) (*StreamContext, error)
	Delete(contextID string) error
	Cleanup(ttl time.Duration) (int, error)
	Count() int
	Close() error
}

// Store 兼容旧 API 的包装（委托 Backend）
type Store struct {
	Backend
}

// New 创建内存存储（保持旧签名兼容）
func New(_ string) (*Store, error) {
	return NewDefault(), nil
}

// NewDefault 生产默认：纯内存，避免每连接写盘拖垮 VPS。
func NewDefault() *Store {
	return &Store{Backend: NewMemory(4096)}
}
