// AERO fork (ADR-0019): 对随机丢包不敏感的发送方的测试。

package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

func newTestLossTolerantSender() *testCubicSender {
	s := newTestCubicSender(true) // CUBIC 增长曲线
	s.sender.lossTolerant = true
	return s
}

// growTo 在没有丢包的情况下把窗口涨到至少 packets 个包（慢启动，每个确认加一个包）。
func (s *testCubicSender) growTo(t *testing.T, packets int) {
	t.Helper()
	for range 2000 {
		if s.sender.GetCongestionWindow() >= protocol.ByteCount(packets)*maxDatagramSize {
			return
		}
		n := s.SendAvailableSendWindow()
		s.AckNPackets(n)
	}
	t.Fatalf("窗口没能涨到 %d 个包: %d", packets, s.sender.GetCongestionWindow()/maxDatagramSize)
}

func TestLossStatsRatio(t *testing.T) {
	var s lossStats
	require.Zero(t, s.ratio())
	s.onLost() // 样本不足：按 lossMinSamples 计，一次丢包不会变成 100%
	require.InDelta(t, 1.0/lossMinSamples, s.ratio(), 1e-9)
	for range 99 {
		s.onAcked()
	}
	require.InDelta(t, 1.0/100, s.ratio(), 1e-9)
	// 窗口满了以后衰减，计数不会无限增长
	for range 10000 {
		s.onAcked()
	}
	require.Less(t, s.acked+s.lost, float64(lossWindowSamples)+1)
	require.Less(t, s.ratio(), 0.001)
}

func TestRTTInflated(t *testing.T) {
	var rtt utils.RTTStats
	require.False(t, rttInflated(&rtt), "没有样本时不判为膨胀")
	rtt.UpdateRTT(190*time.Millisecond, 0)
	require.False(t, rttInflated(&rtt))
	// 抖动 10ms：余量 max(190/4=47ms, 25ms) 之内，不算膨胀
	rtt.UpdateRTT(200*time.Millisecond, 0)
	require.False(t, rttInflated(&rtt))
	// 持续高 RTT（排队）：平滑 RTT 越过余量
	for range 40 {
		rtt.UpdateRTT(300*time.Millisecond, 0)
	}
	require.True(t, rttInflated(&rtt))
}

// 核心：1% 的随机丢包、RTT 稳定时，窗口不会被压低（上游的 Reno 每次丢包都乘 0.7）。
func TestLossTolerantIgnoresRandomLoss(t *testing.T) {
	lossy := newTestLossTolerantSender()
	reno := newTestCubicSender(false) // 上游行为
	lossy.growTo(t, 150)
	reno.growTo(t, 150)
	before := lossy.sender.GetCongestionWindow()

	for round := range 200 {
		for _, s := range []*testCubicSender{lossy, reno} {
			n := s.SendAvailableSendWindow()
			if round%3 == 0 && n > 0 { // 约 1%：每三轮丢一个包
				s.LoseNPackets(1)
				n--
			}
			s.AckNPackets(n)
		}
	}
	require.GreaterOrEqual(t, lossy.sender.GetCongestionWindow(), before, "随机丢包不应降窗口")
	require.False(t, lossy.sender.InRecovery())
	require.Less(t, reno.sender.GetCongestionWindow(), lossy.sender.GetCongestionWindow()/2, "对照：上游行为窗口被压得很低")
	// 统计仍然记录丢包
	require.NotZero(t, lossy.sender.connStats.PacketsLost.Load())
}

// RTT 膨胀（瓶颈在排队）时，丢包仍然要降窗口：真拥塞时必须退让。
func TestLossTolerantBacksOffWhenQueueBuilds(t *testing.T) {
	s := newTestLossTolerantSender()
	s.growTo(t, 150)
	s.rttStats.UpdateRTT(60*time.Millisecond, 0) // 最小 RTT
	for range 60 {
		s.rttStats.UpdateRTT(200*time.Millisecond, 0) // 排队：平滑 RTT 远高于最小 RTT
	}
	require.True(t, rttInflated(s.rttStats))
	before := s.sender.GetCongestionWindow()
	n := s.SendAvailableSendWindow()
	s.LoseNPackets(1)
	s.AckNPackets(n - 1)
	require.Less(t, s.sender.GetCongestionWindow(), before, "排队时丢包应降窗口")
}

// 丢包率高（超过阈值）时，即使 RTT 没膨胀也降窗口。
func TestLossTolerantBacksOffOnHighLossRate(t *testing.T) {
	s := newTestLossTolerantSender()
	s.growTo(t, 150)
	before := s.sender.GetCongestionWindow()
	// 一批里丢 20%：丢包率远高于 lossTolerantRatio
	n := s.SendAvailableSendWindow()
	lost := n / 5
	s.LoseNPackets(lost)
	s.AckNPackets(n - lost)
	require.Less(t, s.sender.GetCongestionWindow(), before, "高丢包率应降窗口")
}

// 默认（lossTolerant=false）行为与上游完全一致：随机丢包照样降窗口。
func TestLossTolerantDisabledKeepsUpstreamBehavior(t *testing.T) {
	s := newTestCubicSender(false)
	s.growTo(t, 150)
	before := s.sender.GetCongestionWindow()
	n := s.SendAvailableSendWindow()
	s.LoseNPackets(1)
	s.AckNPackets(n - 1)
	require.Less(t, s.sender.GetCongestionWindow(), before)
	require.False(t, s.sender.lossTolerant)
}

func TestNewLossTolerantSenderUsesCubicGrowth(t *testing.T) {
	var clock mockClock
	rtt := utils.RTTStats{}
	c := NewLossTolerantSender(&clock, &rtt, &utils.ConnectionStats{}, protocol.InitialPacketSize, nil)
	require.True(t, c.lossTolerant)
	require.False(t, c.reno, "增长曲线用 CUBIC，不是 Reno")
}
