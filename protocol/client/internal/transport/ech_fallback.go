// ECH 降级策略
//
// 三层回退：
//   1. 真 ECH (HPKE 加密 inner CH)
//   2. 伪 ECH (TLS SNI = public_name, HTTP/2 :authority = 真实目标)
//   3. 明文 TLS (标准 TLS，无伪装)
package transport

import (
	"log"
)

// ECHLevel ECH 级别
type ECHLevel int

const (
	LevelReal    ECHLevel = iota // 真 ECH
	LevelPseudo                  // 伪 ECH
	LevelPlain                   // 明文 TLS
)

func (l ECHLevel) String() string {
	switch l {
	case LevelReal:
		return "real_ech"
	case LevelPseudo:
		return "pseudo_ech"
	case LevelPlain:
		return "plain_tls"
	default:
		return "unknown"
	}
}

// FallbackStrategy ECH 降级策略
type FallbackStrategy struct {
	current    ECHLevel
	attempted  map[ECHLevel]bool
}

// NewFallbackStrategy 创建降级策略
func NewFallbackStrategy() *FallbackStrategy {
	return &FallbackStrategy{
		current:   LevelReal, // 优先尝试真 ECH
		attempted: make(map[ECHLevel]bool),
	}
}

// Next 返回下一个应尝试的 ECH 级别
func (s *FallbackStrategy) Next() *ECHLevel {
	s.attempted[s.current] = true

	switch s.current {
	case LevelReal:
		s.current = LevelPseudo
		log.Printf("[ECH] Real ECH unavailable, falling back to pseudo ECH")
		return &s.current
	case LevelPseudo:
		s.current = LevelPlain
		log.Printf("[ECH] Pseudo ECH unavailable, falling back to plain TLS")
		return &s.current
	case LevelPlain:
		log.Printf("[ECH] All ECH methods failed, giving up")
		return nil
	}
	return nil
}

// Current 返回当前级别
func (s *FallbackStrategy) Current() ECHLevel {
	return s.current
}

// Attempted 返回已尝试的级别
func (s *FallbackStrategy) Attempted() []ECHLevel {
	levels := make([]ECHLevel, 0, len(s.attempted))
	for l := range s.attempted {
		levels = append(levels, l)
	}
	return levels
}

// Reset 重置策略
func (s *FallbackStrategy) Reset() {
	s.current = LevelReal
	s.attempted = make(map[ECHLevel]bool)
}
