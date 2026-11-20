package edge

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// 这两个值是变量只为测试能缩小；生产代码不修改。
var (
	// hopPoolMaxConns 是入口到出口的共享连接数上限（每个活跃用户一条）。
	// 满了且没有空闲连接可回收时，新请求退回“每请求一条独立连接”，不会失败。
	hopPoolMaxConns = 256
	// hopPoolIdleTTL 是共享连接没有任何流之后保留的时间；到期关闭，避免空闲用户长期占着连接。
	hopPoolIdleTTL = 60 * time.Second
)

// hopPooledConn 是入口到出口的一条 QUIC 连接；每个 TCP CONNECT 在其上只开一个 HTTP/3 流。
type hopPooledConn struct {
	q  *quic.Conn
	h3 *http3.ClientConn
}

func (c *hopPooledConn) alive() bool { return c.q.Context().Err() == nil }

// hopDialFlight 是一次进行中的拨号：同一用户的并发请求共用同一次握手，结果（含错误）一并共享，
// 出口不可达时不会让 N 个等待者各自串行重试 N 次。
type hopDialFlight struct {
	done chan struct{}
	conn *hopPooledConn
	err  error
}

// hopPoolEntry 是一个用户的共享连接。每个用户各用一条连接，一个用户的慢流只占自己的连接窗口，
// 不会拖住其他用户（QUIC 连接级流控是队头阻塞的来源）。
type hopPoolEntry struct {
	cur    *hopPooledConn
	flight *hopDialFlight
	active int         // 持有租约的请求数（含正在等待拨号的）；为 0 才允许回收
	idle   *time.Timer // active 降到 0 后启动，到期关闭连接
}

// hopLease 是对一个用户共享连接的占用；release 幂等，必须在流结束（或开流失败）时调用。
type hopLease struct {
	p    *hopConnPool
	key  string
	e    *hopPoolEntry
	conn *hopPooledConn
	once sync.Once
}

func (l *hopLease) release() {
	l.once.Do(func() { l.p.release(l.key, l.e) })
}

// hopConnPool 按用户键保存到出口的共享连接。
type hopConnPool struct {
	mu     sync.Mutex
	closed bool
	m      map[string]*hopPoolEntry
}

var (
	errHopPoolClosed = errors.New("server closed")
	errHopPoolFull   = errors.New("hop connection pool full")
)

// get 返回 key 对应用户的可用共享连接租约；没有时调用 dial 建立（同一用户同一时刻只拨一次）。
// 池满且无空闲连接可回收时返回 errHopPoolFull，由调用方改用独立连接。
// dial 自带超时，不受单个调用方 ctx 取消的影响；等待者按自己的 ctx 退出。
func (p *hopConnPool) get(ctx context.Context, key string, dial func() (*hopPooledConn, error)) (*hopLease, error) {
	// 持锁期间摘下的待关闭连接：CloseWithError 会发包并等连接循环退出，不能在 p.mu 内做（§11.2），
	// 否则所有用户的 get/release 都被它卡住。unlock 解锁后再关。
	var pending []*quic.Conn
	unlock := func() {
		p.mu.Unlock()
		closeConns(pending)
		pending = nil
	}

	p.mu.Lock()
	if p.closed {
		unlock()
		return nil, errHopPoolClosed
	}
	if p.m == nil {
		p.m = make(map[string]*hopPoolEntry)
	}
	e := p.m[key]
	if e == nil {
		if len(p.m) >= hopPoolMaxConns {
			c, ok := p.evictIdleLocked()
			if c != nil {
				pending = append(pending, c)
			}
			if !ok {
				unlock()
				return nil, errHopPoolFull
			}
		}
		e = &hopPoolEntry{}
		p.m[key] = e
	}
	// 先占租约再拨号/等待：保证拨号期间该条目不会被回收。
	e.active++
	if e.idle != nil {
		e.idle.Stop()
		e.idle = nil
	}
	fail := func(err error) (*hopLease, error) {
		p.release(key, e)
		return nil, err
	}

	if e.cur != nil && !e.cur.alive() {
		e.cur = nil
	}
	if e.cur != nil {
		l := &hopLease{p: p, key: key, e: e, conn: e.cur}
		unlock()
		return l, nil
	}
	if f := e.flight; f != nil {
		unlock()
		select {
		case <-f.done:
			if f.err != nil {
				return fail(f.err)
			}
			return &hopLease{p: p, key: key, e: e, conn: f.conn}, nil
		case <-ctx.Done():
			return fail(ctx.Err())
		}
	}
	f := &hopDialFlight{done: make(chan struct{})}
	e.flight = f
	unlock()

	c, err := dial()

	p.mu.Lock()
	e.flight = nil
	if err == nil && p.closed {
		pending = append(pending, c.q)
		c, err = nil, errHopPoolClosed
	}
	if err == nil {
		e.cur = c
	}
	f.conn, f.err = c, err
	unlock()
	close(f.done)
	if err != nil {
		return fail(err)
	}
	return &hopLease{p: p, key: key, e: e, conn: c}, nil
}

// release 归还一个租约；条目没有租约时：连接已失效就立即删除，否则启动空闲计时。
func (p *hopConnPool) release(key string, e *hopPoolEntry) {
	p.mu.Lock()
	e.active--
	if e.active > 0 {
		p.mu.Unlock()
		return
	}
	if p.closed || e.cur == nil || !e.cur.alive() {
		c := p.removeLocked(key, e)
		p.mu.Unlock()
		closeConns([]*quic.Conn{c})
		return
	}
	if e.idle == nil {
		// 回调要核对 e.idle 仍是自己：Stop 返回 false 时旧回调可能已在排队，
		// 若期间条目又被使用并装了新定时器，旧回调不能提前回收它。
		var t *time.Timer
		t = time.AfterFunc(hopPoolIdleTTL, func() {
			p.mu.Lock()
			if e.active != 0 || e.idle != t || p.m[key] != e {
				p.mu.Unlock()
				return
			}
			c := p.removeLocked(key, e)
			p.mu.Unlock()
			closeConns([]*quic.Conn{c})
		})
		e.idle = t // 回调需要 p.mu，必在本函数解锁后才读取 t
	}
	p.mu.Unlock()
}

// removeLocked 从池里删除条目并返回要关闭的连接（可能为 nil）；调用方在解锁后用 closeConns 关闭。
// 调用方持有 p.mu。
func (p *hopConnPool) removeLocked(key string, e *hopPoolEntry) *quic.Conn {
	if p.m[key] == e {
		delete(p.m, key)
	}
	if e.idle != nil {
		e.idle.Stop()
		e.idle = nil
	}
	var c *quic.Conn
	if e.cur != nil {
		c = e.cur.q
		e.cur = nil
	}
	return c
}

// evictIdleLocked 回收一个没有租约的条目：返回要关闭的连接（可能为 nil）与是否腾出了位置。
// 调用方持有 p.mu，并在解锁后关闭返回的连接。
func (p *hopConnPool) evictIdleLocked() (*quic.Conn, bool) {
	for k, e := range p.m {
		if e.active == 0 {
			return p.removeLocked(k, e), true
		}
	}
	return nil, false
}

// closeConns 关闭连接（忽略 nil）；不得在持有 p.mu 时调用。
func closeConns(cs []*quic.Conn) {
	for _, c := range cs {
		if c != nil {
			_ = c.CloseWithError(0, "idle")
		}
	}
}

// invalidate 把已损坏的连接移出池并关闭；已被替换的旧连接不影响新连接。
func (p *hopConnPool) invalidate(l *hopLease) {
	p.mu.Lock()
	if l.e.cur == l.conn {
		l.e.cur = nil
	}
	p.mu.Unlock()
	_ = l.conn.q.CloseWithError(0, "invalidated")
}

// close 关闭池与全部共享连接；之后 get 一律失败。
func (p *hopConnPool) close() {
	p.mu.Lock()
	p.closed = true
	conns := make([]*quic.Conn, 0, len(p.m))
	for k, e := range p.m {
		conns = append(conns, p.removeLocked(k, e))
	}
	p.mu.Unlock()
	closeConns(conns)
}

// size 返回当前条目数（测试用）。
func (p *hopConnPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}
