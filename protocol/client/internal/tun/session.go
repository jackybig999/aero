// 五元组会话管理
//
// 会话表 key = {srcIP, dstIP, srcPort, dstPort, proto}
// TCP: SYN 触发创建，双向 goroutine 转发
// UDP: 首个包触发创建，60 秒无流量过期
package tun

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// SessionKey 五元组
type SessionKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

func (k SessionKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d/%d", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Proto)
}

// Session 单个会话
type Session struct {
	Key          SessionKey
	CreatedAt    time.Time
	LastActivity time.Time
	Conn         net.Conn      // 到目标的系统连接
	TCP          *TCPState     // TCP 状态（仅 TCP 会话非 nil）
	Done         chan struct{} // 关闭信号
}

// SessionTable 会话表（线程安全）
type SessionTable struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
}

// NewSessionTable 创建会话表
func NewSessionTable(ttl time.Duration) *SessionTable {
	return &SessionTable{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
}

// Get 根据 key 获取会话
func (t *SessionTable) Get(key SessionKey) *Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	k := key.String()
	if s, ok := t.sessions[k]; ok {
		s.LastActivity = time.Now()
		return s
	}
	return nil
}

// Put 添加会话
func (t *SessionTable) Put(key SessionKey, conn net.Conn) *Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := key.String()
	s := &Session{
		Key:          key,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		Conn:         conn,
		Done:         make(chan struct{}),
	}
	t.sessions[k] = s
	return s
}

// Remove 移除会话
func (t *SessionTable) Remove(key SessionKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, key.String())
}

// CleanupExpired 清理过期会话，返回被清理的数量
func (t *SessionTable) CleanupExpired() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	now := time.Now()
	for k, s := range t.sessions {
		if now.Sub(s.LastActivity) > t.ttl {
			close(s.Done)
			if s.Conn != nil {
				s.Conn.Close()
			}
			delete(t.sessions, k)
			count++
		}
	}
	return count
}

// Count 返回当前会话数
func (t *SessionTable) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}
