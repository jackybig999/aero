// AERO fork (ADR-0019): 对随机丢包不敏感的发送方。
// 许可证与上游相同（MIT，见仓库根目录 LICENSE）。

package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/utils"
)

// 背景：上游只有基于丢包的拥塞控制（这里实际用的是 NewReno，见 sent_packet_handler.go 里的 `true, // use Reno`），
// 把每次丢包都当作链路拥塞并把窗口乘以 0.7。在往返约 190ms、随机丢包 ≥0.1% 的跨境链路上窗口涨不起来，
// 吞吐只有 1~5 Mbit/s。“lossy” 模式（quic.Config.CongestionControl = "lossy"）做两件事：
//  1. 增长曲线改用 CUBIC：按时间增长，与往返时延无关；Reno 每个往返只加一个包，190ms 下恢复需要几百个往返。
//  2. 丢包事件不一定降窗口：最近的丢包率低于 lossTolerantRatio 且平滑 RTT 没有明显高于最小 RTT（没有在排队）时，
//     把它当作随机丢包，不降窗口；否则按原行为降窗口。这样真拥塞（排队增长或丢包率高）时仍会退让。
const (
	// lossWindowSamples 是丢包率统计窗口的大小（包结果数）；满了以后两个计数同时减半，相当于指数衰减。
	lossWindowSamples = 128
	// lossMinSamples：样本不足时，把缺的当作“已确认”，避免连接刚开始的一次丢包被算成 100%。
	lossMinSamples = 32
	// lossTolerantRatio：低于这个丢包率（且没有排队）时，把丢包当作随机丢包。数值为估算，由 netem 矩阵标定。
	lossTolerantRatio = 0.05
	// rttInflationMin：判定“RTT 膨胀（在排队）”的最小余量；余量取 max(minRTT/4, rttInflationMin)。
	rttInflationMin = 25 * time.Millisecond
)

// lossStats 统计最近一段时间的包结果（已确认/丢失），旧的结果指数衰减。
type lossStats struct {
	acked, lost float64
}

func (s *lossStats) decay() {
	if s.acked+s.lost >= lossWindowSamples {
		s.acked /= 2
		s.lost /= 2
	}
}

func (s *lossStats) onAcked() {
	s.acked++
	s.decay()
}

func (s *lossStats) onLost() {
	s.lost++
	s.decay()
}

// ratio 返回最近的丢包率；样本不足 lossMinSamples 时按 lossMinSamples 计。
func (s *lossStats) ratio() float64 {
	n := s.acked + s.lost
	if n < lossMinSamples {
		n = lossMinSamples
	}
	return s.lost / n
}

// rttInflated 判断平滑 RTT 是否明显高于最小 RTT（说明瓶颈处在排队）。没有 RTT 样本时返回 false。
func rttInflated(rtt *utils.RTTStats) bool {
	minRTT, srtt := rtt.MinRTT(), rtt.SmoothedRTT()
	if minRTT <= 0 || srtt <= 0 {
		return false
	}
	margin := max(minRTT/4, rttInflationMin)
	return srtt > minRTT+margin
}
