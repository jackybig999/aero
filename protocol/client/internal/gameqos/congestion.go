// Game QoS: 游戏专用拥塞控制参数
//
// 目标：低延迟优先于高吞吐
// 策略：小拥塞窗口、快速重传、延迟敏感 AIMD
package gameqos

import "time"

// GameCongestionConfig 游戏拥塞控制配置
type GameCongestionConfig struct {
	InitialWindow   int           // 初始拥塞窗口（包），默认 10
	MinWindow       int           // 最小窗口，默认 4
	MaxWindow       int           // 最大窗口，默认 64
	SlowStartThresh int           // 慢启动阈值，默认 20
	RTTSmooth       time.Duration // RTT 平滑值
	RTTVar          time.Duration // RTT 方差
}

// DefaultGameCongestion 默认游戏拥塞参数
func DefaultGameCongestion() GameCongestionConfig {
	return GameCongestionConfig{
		InitialWindow:   10,
		MinWindow:       4,
		MaxWindow:       64,
		SlowStartThresh: 20,
	}
}

// CongestionController 拥塞控制器
type CongestionController struct {
	cfg          GameCongestionConfig
	cwnd         int     // 拥塞窗口（包）
	ssthresh     int     // 慢启动阈值
	rtt          time.Duration
	inSlowStart  bool
	lossCount    int
}

// NewCongestionController 创建拥塞控制器
func NewCongestionController(cfg GameCongestionConfig) *CongestionController {
	return &CongestionController{
		cfg:         cfg,
		cwnd:        cfg.InitialWindow,
		ssthresh:    cfg.SlowStartThresh,
		inSlowStart: true,
	}
}

// OnAck 收到 ACK 时调用
func (c *CongestionController) OnAck() {
	if c.inSlowStart {
		// 慢启动：每 ACK 窗口翻倍
		c.cwnd *= 2
		if c.cwnd >= c.ssthresh {
			c.inSlowStart = false
		}
	} else {
		// 拥塞避免：每 RTT 窗口 +1（简化：每 ACK +1/cwnd）
		if c.cwnd < c.cfg.MaxWindow {
			c.cwnd++
		}
	}
}

// OnLoss 丢包时调用
func (c *CongestionController) OnLoss() {
	c.lossCount++
	// 快速恢复：窗口减半（不小于最小窗口）
	c.ssthresh = c.cwnd / 2
	if c.ssthresh < c.cfg.MinWindow {
		c.ssthresh = c.cfg.MinWindow
	}
	c.cwnd = c.ssthresh
	c.inSlowStart = false
}

// UpdateRTT 更新 RTT 测量
func (c *CongestionController) UpdateRTT(rtt time.Duration) {
	if c.rtt == 0 {
		c.rtt = rtt
	} else {
		// 指数加权移动平均
		c.rtt = (c.rtt*7 + rtt) / 8
	}
}

// Window 返回当前拥塞窗口
func (c *CongestionController) Window() int {
	return c.cwnd
}

// LimitBytes 返回当前可发送字节数（按 MTU=1420 估算）
func (c *CongestionController) LimitBytes() int {
	return c.cwnd * 1420
}
