package edge

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// GlobalTunnelDevice is the minimal server-side TUN contract. Opening and
// platform-specific configuration are intentionally outside this reader.
type GlobalTunnelDevice interface {
	Read([]byte) (int, error)
	Close() error
}

type globalTunnelDeviceWriter interface {
	Write([]byte) (int, error)
}

func packetSource(packet []byte) (netip.Addr, error) {
	if len(packet) < 20 {
		return netip.Addr{}, errors.New("IP packet is shorter than the minimum header")
	}
	switch packet[0] >> 4 {
	case 4:
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return netip.Addr{}, errors.New("invalid IPv4 header length")
		}
		var source [4]byte
		copy(source[:], packet[12:16])
		return netip.AddrFrom4(source), nil
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, errors.New("IPv6 packet is shorter than the minimum header")
		}
		var source [16]byte
		copy(source[:], packet[8:24])
		return netip.AddrFrom16(source), nil
	default:
		return netip.Addr{}, errors.New("unsupported IP packet version")
	}
}

var tunnelBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 65535)
		return &buf
	},
}

// GlobalTunnelReader owns exactly one read loop and dispatches packets to the
// connection selected by GlobalTunnelRouter. It never creates per-session NAT.
type GlobalTunnelReader struct {
	device        GlobalTunnelDevice
	router        *GlobalTunnelRouter
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	startOnce     sync.Once
	closeOnce     sync.Once
	closeErr      error
	bindingMu     sync.Mutex
	bindingCancel map[uint64]context.CancelFunc
	bindingWG     sync.WaitGroup

	// 每个会话一条有界下行队列与独立发送协程：读循环只入队、从不阻塞，
	// 一个拥塞客户端（SendDatagram 阻塞）不会影响其他用户（审查 P0-6）。
	downMu    sync.Mutex
	downlinks map[uint64]*tunnelDownlink
	downWG    sync.WaitGroup
}

// downlinkQueueLen 是单个会话的下行队列长度，用于吸收突发（1Gbps 约 9 万包/秒，
// 1ms 调度延迟约 90 包）；满了即丢包（等同路由器尾部丢弃）。
const downlinkQueueLen = 512

// downlinkBudgetBytes 是全部会话排队中报文的总内存上限（L0 §9.2）；超出即丢包，
// 大量客户端同时拥塞时内存仍有确定上界。
const downlinkBudgetBytes = 64 << 20

var downlinkQueuedBytes atomic.Int64

type downlinkPacket struct {
	buf *[]byte
	n   int
}

type tunnelDownlink struct {
	binding   GlobalTunnelBinding
	conn      IPPacketConn
	ch        chan downlinkPacket
	done      chan struct{}
	closeOnce sync.Once
}

// downlinkBufPool 存放单个下行报文副本；TUN MTU 为 1360，2048 足够，更大的报文单独分配。
var downlinkBufPool = sync.Pool{New: func() any {
	b := make([]byte, 2048)
	return &b
}}

func (d *tunnelDownlink) stop() {
	d.closeOnce.Do(func() {
		close(d.done)
		// 关闭连接以解除阻塞中的 SendDatagram，保证发送协程有退出路径。
		_ = d.conn.Close()
	})
}

func NewGlobalTunnelReader(parent context.Context, device GlobalTunnelDevice, router *GlobalTunnelRouter) (*GlobalTunnelReader, error) {
	if device == nil {
		return nil, errors.New("global tunnel reader requires a device")
	}
	if router == nil {
		return nil, errors.New("global tunnel reader requires a router")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &GlobalTunnelReader{device: device, router: router, ctx: ctx, cancel: cancel, bindingCancel: make(map[uint64]context.CancelFunc), downlinks: make(map[uint64]*tunnelDownlink)}, nil
}

// StartBinding starts the reverse direction for one registered CONNECT-IP
// binding. The packet source is checked before it is written to the shared
// device, preventing a session from injecting another client's address.
func (r *GlobalTunnelReader) StartBinding(parent context.Context, binding GlobalTunnelBinding) error {
	writer, ok := r.device.(globalTunnelDeviceWriter)
	if !ok {
		return errors.New("global tunnel device does not support packet writes")
	}
	if binding.Conn == nil || binding.Generation == 0 {
		return errors.New("global tunnel binding is incomplete")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	r.bindingMu.Lock()
	if r.ctx.Err() != nil {
		r.bindingMu.Unlock()
		cancel()
		return errors.New("global tunnel reader is closed")
	}
	r.bindingCancel[binding.Generation] = cancel
	r.bindingMu.Unlock()
	r.bindingWG.Add(1)
	go func() {
		defer r.bindingWG.Done()
		defer cancel()
		defer func() {
			r.bindingMu.Lock()
			delete(r.bindingCancel, binding.Generation)
			r.bindingMu.Unlock()
			r.closeDownlink(binding.Generation)
		}()
		workerDone := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = binding.Conn.Close()
			case <-workerDone:
			}
		}()
		defer close(workerDone)
		bufPtr := tunnelBufPool.Get().(*[]byte)
		defer tunnelBufPool.Put(bufPtr)
		buffer := *bufPtr
		for {
			n, err := binding.Conn.ReadPacket(buffer)
			if n > 0 {
				packet := buffer[:n]
				if source, parseErr := packetSource(packet); parseErr == nil && r.router.IsCurrent(binding) && r.router.ValidateSource(binding, source) == nil {
					// 统一目的地址 ACL：私网、元数据、本机、其他用户地址池、出站 SMTP 一律丢弃。
					// 不记录目的地址（PROJECT_RULES：edge 不记录用户访问的目的地址）。
					if !clientPacketAllowed(packet) {
						continue
					}
					if len(packet) > 1360 && packet[0]>>4 == 6 {
						gwIPv6 := net.ParseIP("fd88::1")
						ptbPkt := buildICMPv6PacketTooBig(packet, gwIPv6, 1360)
						if len(ptbPkt) > 0 {
							_, _ = binding.Conn.WritePacket(ptbPkt)
						}
						continue
					}
					if _, writeErr := writer.Write(packet); writeErr != nil {
						return
					}
					binding.usage.Add(int64(n), 0)
				}
			}
			if err != nil || ctx.Err() != nil {
				return
			}
		}
	}()
	return nil
}

func (r *GlobalTunnelReader) Start() {
	r.startOnce.Do(func() {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.run()
		}()
	})
}

func (r *GlobalTunnelReader) run() {
	bufPtr := tunnelBufPool.Get().(*[]byte)
	defer tunnelBufPool.Put(bufPtr)
	buffer := *bufPtr
	for {
		if r.ctx.Err() != nil {
			return
		}
		n, err := r.device.Read(buffer)
		if n > 0 {
			packet := buffer[:n]
			binding, _, routeErr := r.router.RoutePacket(packet)
			if routeErr != nil {
				continue
			}
			r.enqueueDownlink(binding, packet)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) && r.ctx.Err() == nil {
				log.Printf("[TUN] shared reader read failed: %v", err)
			}
			return
		}
	}
}

func (r *GlobalTunnelReader) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.cancel()
		r.bindingMu.Lock()
		for _, cancel := range r.bindingCancel {
			cancel()
		}
		r.bindingMu.Unlock()
		r.closeErr = r.device.Close()
		r.downMu.Lock()
		for gen, d := range r.downlinks {
			d.stop()
			delete(r.downlinks, gen)
		}
		r.downMu.Unlock()
	})
	r.wg.Wait()
	r.bindingWG.Wait()
	r.downWG.Wait()
	return r.closeErr
}

// packetDestination 解析客户端报文的目的地址、传输层协议与目的端口。
// IPv6 会跳过常见扩展头（逐跳、路由、分片、目的选项），防止借扩展头绕过端口策略。
// 非首分片或无端口协议时 port 为 0。ok 为 false 表示报文无法解析，调用方必须丢弃。
func packetDestination(packet []byte) (dst netip.Addr, proto uint8, port uint16, ok bool) {
	if len(packet) < 20 {
		return netip.Addr{}, 0, 0, false
	}
	var l4 int
	switch packet[0] >> 4 {
	case 4:
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return netip.Addr{}, 0, 0, false
		}
		dst = netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
		proto = packet[9]
		if binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 { // 非首分片
			return dst, proto, 0, true
		}
		l4 = ihl
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, 0, 0, false
		}
		var d [16]byte
		copy(d[:], packet[24:40])
		dst = netip.AddrFrom16(d)
		next := packet[6]
		off := 40
		for i := 0; i < 8; i++ { // 扩展头数量上限，防止构造的长链消耗 CPU
			switch next {
			case 0, 43, 60: // 逐跳、路由、目的选项
				if len(packet) < off+8 {
					return netip.Addr{}, 0, 0, false
				}
				next = packet[off]
				off += (int(packet[off+1]) + 1) * 8
			case 44: // 分片
				if len(packet) < off+8 {
					return netip.Addr{}, 0, 0, false
				}
				fragOffset := binary.BigEndian.Uint16(packet[off+2:off+4]) >> 3
				next = packet[off]
				off += 8
				if fragOffset != 0 {
					return dst, next, 0, true
				}
			default:
				proto, l4 = next, off
				goto ports
			}
		}
		return netip.Addr{}, 0, 0, false // 扩展头过多
	default:
		return netip.Addr{}, 0, 0, false
	}
ports:
	if (proto == 6 || proto == 17) && len(packet) >= l4+4 {
		port = binary.BigEndian.Uint16(packet[l4+2 : l4+4])
	}
	return dst, proto, port, true
}

// clientPacketAllowed 判定客户端经 CONNECT-IP 发出的报文能否写入共享 TUN。
func clientPacketAllowed(packet []byte) bool {
	dst, proto, port, ok := packetDestination(packet)
	if !ok {
		return false
	}
	if blocked, _ := destinationBlocked(dst, edgeLocalAddrs()); blocked {
		return false
	}
	if blocked, _ := destinationPortBlocked(proto, port); blocked {
		return false
	}
	return true
}

// enqueueDownlink 把下行报文复制进会话队列；队列满或 reader 已关闭时丢弃。
func (r *GlobalTunnelReader) enqueueDownlink(binding GlobalTunnelBinding, packet []byte) {
	d := r.downlinkFor(binding)
	if d == nil {
		return
	}
	size := int64(len(packet))
	if len(packet) <= 2048 {
		size = 2048
	}
	if downlinkQueuedBytes.Add(size) > downlinkBudgetBytes {
		downlinkQueuedBytes.Add(-size)
		return // 全局预算耗尽：丢包
	}
	var buf *[]byte
	if len(packet) <= 2048 {
		buf = downlinkBufPool.Get().(*[]byte)
	} else {
		b := make([]byte, len(packet))
		buf = &b
	}
	n := copy(*buf, packet)
	select {
	case d.ch <- downlinkPacket{buf: buf, n: n}:
	default:
		putDownlinkBuf(buf) // 队列满：丢包，不阻塞读循环
	}
}

func putDownlinkBuf(buf *[]byte) {
	size := int64(cap(*buf))
	if size < 2048 {
		size = 2048
	}
	downlinkQueuedBytes.Add(-size)
	if cap(*buf) == 2048 {
		downlinkBufPool.Put(buf)
	}
}

// downlinkFor 返回会话的下行队列，不存在时创建并启动发送协程。
func (r *GlobalTunnelReader) downlinkFor(binding GlobalTunnelBinding) *tunnelDownlink {
	r.downMu.Lock()
	defer r.downMu.Unlock()
	if d, ok := r.downlinks[binding.Generation]; ok {
		return d
	}
	if r.ctx.Err() != nil {
		return nil
	}
	d := &tunnelDownlink{binding: binding, conn: binding.Conn, ch: make(chan downlinkPacket, downlinkQueueLen), done: make(chan struct{})}
	r.downlinks[binding.Generation] = d
	r.downWG.Add(1)
	go r.runDownlink(d)
	return d
}

// downlinkLivenessInterval：发送协程定期确认会话仍在路由表中，会话已注销即自行退出。
// 这样无论“会话清理”与“注销路由”谁先发生，都不会为已结束的会话遗留协程。
const downlinkLivenessInterval = time.Second

func (r *GlobalTunnelReader) runDownlink(d *tunnelDownlink) {
	defer r.downWG.Done()
	writer, canWrite := r.device.(globalTunnelDeviceWriter)
	liveness := time.NewTicker(downlinkLivenessInterval)
	defer liveness.Stop()
	for {
		select {
		case <-d.done:
			r.drainDownlink(d)
			return
		case <-liveness.C:
			if d.binding.Generation != 0 && !r.router.IsCurrent(d.binding) {
				r.removeDownlink(d)
				r.drainDownlink(d)
				return
			}
		case p := <-d.ch:
			icmpPkt, err := d.conn.WritePacket((*p.buf)[:p.n])
			if err == nil {
				d.binding.usage.Add(0, int64(p.n))
			}
			putDownlinkBuf(p.buf)
			if len(icmpPkt) > 0 && canWrite {
				_, _ = writer.Write(icmpPkt)
			}
			if err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("[TUN] downlink write packet failed: %v", err)
			}
		}
	}
}

// drainDownlink 归还队列中剩余报文的缓冲。
func (r *GlobalTunnelReader) drainDownlink(d *tunnelDownlink) {
	for {
		select {
		case p := <-d.ch:
			putDownlinkBuf(p.buf)
		default:
			return
		}
	}
}

// removeDownlink 由发送协程自身调用：仅当表中仍是同一个队列时移除，并停止它。
func (r *GlobalTunnelReader) removeDownlink(d *tunnelDownlink) {
	r.downMu.Lock()
	if cur, ok := r.downlinks[d.binding.Generation]; ok && cur == d {
		delete(r.downlinks, d.binding.Generation)
	}
	r.downMu.Unlock()
	d.stop()
}

// closeDownlink 停止并移除会话的下行队列（会话结束时调用）。
func (r *GlobalTunnelReader) closeDownlink(generation uint64) {
	r.downMu.Lock()
	d, ok := r.downlinks[generation]
	if ok {
		delete(r.downlinks, generation)
	}
	r.downMu.Unlock()
	if ok {
		d.stop()
	}
}
