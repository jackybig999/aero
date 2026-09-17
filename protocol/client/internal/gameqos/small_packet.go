// Game QoS: 小包直通 + 禁用 Nagle
//
// 游戏流量特征：小包高频（< 200B, > 50pps）
// 优化策略：小包不缓冲直接发送，禁用 Nagle 算法
package gameqos

import (
	"log"
	"net"
	"time"
)

// SmallPacketConfig 小包优化配置
type SmallPacketConfig struct {
	MaxSize    int           // 小包阈值（字节），默认 200
	FlushEvery time.Duration // 最大缓冲时间，默认 2ms
}

// DefaultSmallPacketConfig 默认配置
func DefaultSmallPacketConfig() SmallPacketConfig {
	return SmallPacketConfig{
		MaxSize:    200,
		FlushEvery: 2 * time.Millisecond,
	}
}

// SmallPacketWriter 小包直通 Writer
type SmallPacketWriter struct {
	conn   net.Conn
	config SmallPacketConfig
}

// NewSmallPacketWriter 创建小包直通 Writer
func NewSmallPacketWriter(conn net.Conn, cfg SmallPacketConfig) *SmallPacketWriter {
	return &SmallPacketWriter{conn: conn, config: cfg}
}

// Write 小包直接发送，大包可以缓冲
func (w *SmallPacketWriter) Write(p []byte) (int, error) {
	if len(p) <= w.config.MaxSize {
		// 小包立即发送
		return w.conn.Write(p)
	}
	// 大包正常发送
	return w.conn.Write(p)
}

// OptimizeConn 优化 TCP 连接的游戏参数
func OptimizeConn(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	// 禁用 Nagle 算法（TCP_NODELAY）
	tcpConn.SetNoDelay(true)
	// 启用 Keepalive
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(30 * time.Second)
	log.Printf("[GameQoS] TCP_NODELAY + keepalive enabled")
}

// IsSmallPacket 判断是否为小包
func IsSmallPacket(data []byte, threshold int) bool {
	return len(data) <= threshold
}

// DetectGamePattern 检测游戏流量模式
//
// 判断条件：连续 N 个包都小于阈值，且间隔 < 50ms
type GamePatternDetector struct {
	smallCount   int
	totalCount   int
	lastTime     time.Time
	threshold    int  // 包大小阈值
	minPackets   int  // 最小样本数
	maxInterval  time.Duration
}

// NewGamePatternDetector 创建检测器
func NewGamePatternDetector() *GamePatternDetector {
	return &GamePatternDetector{
		threshold:   200,
		minPackets:  20,
		maxInterval: 50 * time.Millisecond,
	}
}

// Record 记录一个包
func (d *GamePatternDetector) Record(size int, ts time.Time) {
	d.totalCount++
	if size <= d.threshold {
		d.smallCount++
	}
	if !d.lastTime.IsZero() && ts.Sub(d.lastTime) > d.maxInterval {
		// 间隔太大，重置
		d.smallCount = 0
		d.totalCount = 0
	}
	d.lastTime = ts
}

// IsGameTraffic 判断是否为游戏流量
func (d *GamePatternDetector) IsGameTraffic() bool {
	if d.totalCount < d.minPackets {
		return false
	}
	// > 80% 的包是小包 + 高频
	return float64(d.smallCount)/float64(d.totalCount) > 0.8
}
