// AERO fork of github.com/quic-go/connect-ip-go v0.4.0 (MIT, see LICENSE).
// Tests for the capsule data mode added in datamode.go.

package connectip

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

// pipeStream is one end of an in-memory stream pair. Writes block until the peer reads
// (io.Pipe semantics), which makes back-pressure observable.
type pipeStream struct {
	mockStream
	r *io.PipeReader
	w *io.PipeWriter
}

func newPipeStreams() (a, b *pipeStream) {
	ar, bw := io.Pipe() // b writes, a reads
	br, aw := io.Pipe() // a writes, b reads
	return &pipeStream{r: ar, w: aw}, &pipeStream{r: br, w: bw}
}

func (p *pipeStream) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeStream) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeStream) Close() error                { return p.w.Close() }
func (p *pipeStream) CancelRead(quic.StreamErrorCode) {
	_ = p.r.CloseWithError(io.ErrClosedPipe)
}
func (p *pipeStream) CancelWrite(quic.StreamErrorCode) {
	_ = p.w.CloseWithError(io.ErrClosedPipe)
}
func (p *pipeStream) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() && !t.After(time.Now()) { // like a real stream: an expired deadline interrupts a blocked Write
		_ = p.w.CloseWithError(os.ErrDeadlineExceeded)
	}
	return nil
}

// eofStream feeds fixed bytes, then EOF.
type eofStream struct {
	mockStream
	r *bytes.Reader
}

func (s *eofStream) Read(b []byte) (int, error) { return s.r.Read(b) }

// holdStream feeds fixed bytes, then blocks (the peer keeps the stream open) until hold is closed.
type holdStream struct {
	mockStream
	r    *bytes.Reader
	hold chan struct{}
}

func (s *holdStream) Read(b []byte) (int, error) {
	n, err := s.r.Read(b)
	if err == io.EOF {
		<-s.hold
	}
	return n, err
}

func ipv4Packet(src, dst netip.Addr, seq uint32) []byte {
	pkt := make([]byte, 20+8+4)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint32(pkt[28:32], seq)
	return pkt
}

var (
	testClientAddr = netip.MustParseAddr("10.0.0.2")
	testServerAddr = netip.MustParseAddr("1.1.1.1")
	allV4Routes    = []IPRoute{{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")}}
)

// pairedCapsuleConns returns a (client, proxy) pair over an in-memory stream with the proxy
// having assigned 10.0.0.2/32 and advertised all IPv4 routes, like the AERO edge does.
func pairedConns(t *testing.T, clientMode, proxyMode DataMode) (client, proxy *Conn) {
	t.Helper()
	cs, ps := newPipeStreams()
	client = newProxiedConnMode(cs, nil, clientMode)
	proxy = newProxiedConnMode(ps, nil, proxyMode)
	t.Cleanup(func() { _ = client.Close(); _ = proxy.Close() })

	require.NoError(t, proxy.AssignAddresses([]netip.Prefix{netip.PrefixFrom(testClientAddr, 32)}))
	require.NoError(t, proxy.AdvertiseRoute(allV4Routes))
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := client.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	return client, proxy
}

func TestDataCapsuleEncoding(t *testing.T) {
	payload := append(quicvarint.Append(nil, 0), 0x45, 0x00, 0x01)
	frame := appendDataCapsule(nil, payload)

	ct, cr, err := http3.NewCapsuleParser(bytes.NewReader(frame)).Next()
	require.NoError(t, err)
	require.Equal(t, http3.CapsuleType(0), ct)
	require.EqualValues(t, len(payload), cr.Remaining())
	got, err := io.ReadAll(cr)
	require.NoError(t, err)
	require.Equal(t, payload, got)

	id, packet, err := splitDataPayload(got)
	require.NoError(t, err)
	require.EqualValues(t, 0, id)
	require.Equal(t, []byte{0x45, 0x00, 0x01}, packet)

	_, _, err = splitDataPayload(nil)
	require.Error(t, err)
}

func TestCapsuleModeRoundTrip(t *testing.T) {
	client, proxy := pairedConns(t, DataModeCapsule, DataModeCapsule)
	require.Equal(t, DataModeCapsule, client.DataMode())

	up := ipv4Packet(testClientAddr, testServerAddr, 1)
	icmp, err := client.WritePacket(up) // WritePacket decrements the TTL in place
	require.NoError(t, err)
	require.Nil(t, icmp)
	buf := make([]byte, 2000)
	n, err := proxy.ReadPacket(buf)
	require.NoError(t, err)
	require.Equal(t, up, buf[:n])

	down := ipv4Packet(testServerAddr, testClientAddr, 2)
	_, err = proxy.WritePacket(down)
	require.NoError(t, err)
	n, err = client.ReadPacket(buf)
	require.NoError(t, err)
	require.Equal(t, down, buf[:n])
}

// Reliable and ordered: nothing is lost even when the sender is far ahead of the receiver,
// and control capsules interleaved with data are still delivered.
func TestCapsuleModeBackpressureNoLossInOrder(t *testing.T) {
	client, proxy := pairedConns(t, DataModeCapsule, DataModeCapsule)
	const total = 1000

	var sent atomic.Int64
	done := make(chan error, 1)
	go func() {
		for i := range total {
			if _, err := client.WritePacket(ipv4Packet(testClientAddr, testServerAddr, uint32(i))); err != nil {
				done <- err
				return
			}
			sent.Add(1)
		}
		done <- nil
	}()

	// Nobody reads yet: the sender must stall (bounded queues), not drop and not close.
	require.Eventually(t, func() bool {
		a := sent.Load()
		time.Sleep(150 * time.Millisecond)
		return a > 0 && a == sent.Load()
	}, 5*time.Second, 10*time.Millisecond)
	require.Less(t, sent.Load(), int64(total), "sender should have been back-pressured")
	select {
	case <-client.closeChan:
		t.Fatal("conn must stay open while back-pressured")
	default:
	}
	// A control capsule still fits while the data queue is full.
	require.NoError(t, client.AdvertiseRoute(allV4Routes))

	buf := make([]byte, 2000)
	for i := range total {
		n, err := proxy.ReadPacket(buf)
		require.NoError(t, err)
		require.Equal(t, uint32(i), binary.BigEndian.Uint32(buf[28:32]), "packet %d out of order or lost (len %d)", i, n)
	}
	require.NoError(t, <-done)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	routes, err := proxy.Routes(ctx) // the control capsule sent in the middle arrived too
	require.NoError(t, err)
	require.Equal(t, allV4Routes, routes)
}

// Packets received before a clean close by the peer must still be delivered (reliable mode).
func TestCapsuleModeDeliversQueuedPacketsAfterPeerClose(t *testing.T) {
	client, proxy := pairedConns(t, DataModeCapsule, DataModeCapsule)
	const n = 10
	for i := range n {
		_, err := client.WritePacket(ipv4Packet(testClientAddr, testServerAddr, uint32(i)))
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool { return len(proxy.dataPackets) == n }, 3*time.Second, 5*time.Millisecond)
	require.NoError(t, client.Close()) // the proxy sees a clean end of stream

	select {
	case <-proxy.closeChan:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not observe the close")
	}
	buf := make([]byte, 2000)
	for i := range n {
		_, err := proxy.ReadPacket(buf)
		require.NoError(t, err, "packet %d lost after peer close", i)
		require.Equal(t, uint32(i), binary.BigEndian.Uint32(buf[28:32]))
	}
	_, err := proxy.ReadPacket(buf)
	require.ErrorIs(t, err, net.ErrClosed)
}

// Several goroutines writing while the queue is full must all be woken (no lost wakeup)
// and keep their own order.
func TestCapsuleModeConcurrentWriters(t *testing.T) {
	client, proxy := pairedConns(t, DataModeCapsule, DataModeCapsule)
	const writers, perWriter = 8, 150
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWriter {
				if _, err := client.WritePacket(ipv4Packet(testClientAddr, testServerAddr, uint32(w)<<16|uint32(i))); err != nil {
					t.Errorf("writer %d: %v", w, err)
					return
				}
			}
		}()
	}
	next := make([]uint32, writers)
	buf := make([]byte, 2000)
	for range writers * perWriter {
		_, err := proxy.ReadPacket(buf)
		require.NoError(t, err)
		seq := binary.BigEndian.Uint32(buf[28:32])
		w, i := seq>>16, seq&0xffff
		require.Equal(t, next[w], i, "writer %d out of order or lost", w)
		next[w]++
	}
	wg.Wait()
}

func TestCapsuleModeCloseUnblocksWriter(t *testing.T) {
	client, _ := pairedConns(t, DataModeCapsule, DataModeCapsule)
	errCh := make(chan error, 1)
	go func() {
		for i := 0; ; i++ {
			if _, err := client.WritePacket(ipv4Packet(testClientAddr, testServerAddr, uint32(i))); err != nil {
				errCh <- err
				return
			}
		}
	}()
	time.Sleep(300 * time.Millisecond) // let the writer block on the full queue
	go func() { _ = client.Close() }()
	select {
	case err := <-errCh:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(3 * time.Second):
		t.Fatal("blocked WritePacket was not released by Close")
	}
}

func TestDatagramModeDropsDataCapsule(t *testing.T) {
	client, proxy := pairedConns(t, DataModeCapsule, DataModeDatagram)
	_, err := client.WritePacket(ipv4Packet(testClientAddr, testServerAddr, 1))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return proxy.DroppedModeMismatch() == 1 }, 2*time.Second, 10*time.Millisecond)

	// The connection keeps working: control capsules after the dropped data capsule arrive.
	require.NoError(t, client.AdvertiseRoute(allV4Routes))
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	routes, err := proxy.Routes(ctx)
	require.NoError(t, err)
	require.Equal(t, allV4Routes, routes)
	require.Zero(t, client.DroppedModeMismatch())
}

func TestCapsuleModeIgnoresUnknownContextID(t *testing.T) {
	valid := ipv4Packet(testClientAddr, testServerAddr, 7)
	var data []byte
	data = appendDataCapsule(data, append(quicvarint.Append(nil, 1), 0xde, 0xad)) // Context ID 1: ignored
	data = appendDataCapsule(data, append(quicvarint.Append(nil, 0), valid...))

	hold := make(chan struct{})
	conn := newProxiedConnMode(&holdStream{r: bytes.NewReader(data), hold: hold}, nil, DataModeCapsule)
	t.Cleanup(func() { close(hold); _ = conn.Close() })
	require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.PrefixFrom(testClientAddr, 32)}))
	require.NoError(t, conn.AdvertiseRoute(allV4Routes))
	buf := make([]byte, 2000)
	n, err := conn.ReadPacket(buf)
	require.NoError(t, err)
	require.Equal(t, valid, buf[:n])
}

func TestCapsuleModeMalformedClosesConn(t *testing.T) {
	cases := map[string][]byte{
		"empty payload (no Context ID)": quicvarint.Append(quicvarint.Append(nil, 0), 0),
		"oversized capsule": append(quicvarint.Append(quicvarint.Append(nil, 0), maxDataCapsuleSize+1),
			bytes.Repeat([]byte{0}, 16)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			conn := newProxiedConnMode(&eofStream{r: bytes.NewReader(data)}, nil, DataModeCapsule)
			t.Cleanup(func() { _ = conn.Close() })
			errCh := make(chan error, 1)
			go func() { _, err := conn.ReadPacket(make([]byte, 2000)); errCh <- err }()
			select {
			case err := <-errCh:
				require.ErrorIs(t, err, net.ErrClosed)
			case <-time.After(2 * time.Second):
				t.Fatal("malformed capsule did not close the conn")
			}
		})
	}
}

func TestUnknownDataModeRejected(t *testing.T) {
	_, _, err := (&ClientConn{}).DialWithMode(nil, DataMode(9))
	require.ErrorContains(t, err, "unknown data mode")
	require.Equal(t, "capsule", DataModeCapsule.String())
	require.Equal(t, "datagram", DataModeDatagram.String())
	require.Equal(t, "DataMode(9)", DataMode(9).String())
}

func FuzzCapsuleStream(f *testing.F) {
	pkt := ipv4Packet(testClientAddr, testServerAddr, 1)
	f.Add(appendDataCapsule(nil, append(quicvarint.Append(nil, 0), pkt...)))
	f.Add(appendDataCapsule(nil, append(quicvarint.Append(nil, 1), pkt...)))
	f.Add(appendDataCapsule(nil, nil))
	f.Add(quicvarint.Append(quicvarint.Append(nil, 0), 1<<20))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		conn := newProxiedConnMode(&eofStream{r: bytes.NewReader(data)}, nil, DataModeCapsule)
		defer conn.Close()
		_ = conn.AssignAddresses([]netip.Prefix{netip.PrefixFrom(testServerAddr, 32)})
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 70000)
			for {
				if _, err := conn.ReadPacket(buf); err != nil {
					return
				}
			}
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("ReadPacket did not terminate after the stream ended")
		}
	})
}

// End to end over a real HTTP/3 connection (QUIC DATAGRAM negotiated), both ends in capsule mode.
func TestCapsuleModeOverRealHTTP3(t *testing.T) {
	for _, mode := range []DataMode{DataModeCapsule, DataModeDatagram} {
		t.Run(mode.String(), func(t *testing.T) {
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			t.Cleanup(func() { udp.Close() })
			template := uritemplate.MustNew(fmt.Sprintf("https://%s/connect-ip", udp.LocalAddr()))

			var wg sync.WaitGroup
			proxyConn := make(chan *Conn, 1)
			mux := http.NewServeMux()
			mux.HandleFunc("/connect-ip", func(w http.ResponseWriter, r *http.Request) {
				preq, err := ParseProxyRequest(r, template)
				require.NoError(t, err)
				c, err := (&Proxy{}).ProxyWithMode(w, preq, mode)
				require.NoError(t, err)
				proxyConn <- c
				<-r.Context().Done()
			})
			srv := http3.Server{Handler: mux, EnableDatagrams: true, TLSConfig: tlsConf}
			wg.Add(1)
			go func() { defer wg.Done(); _ = srv.Serve(udp) }()
			t.Cleanup(func() { _ = srv.Close(); wg.Wait() })

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			qconn, err := quic.DialAddr(ctx, udp.LocalAddr().String(), &tls.Config{
				ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3},
			}, &quic.Config{EnableDatagrams: true})
			require.NoError(t, err)
			t.Cleanup(func() { _ = qconn.CloseWithError(0, "") })
			cc, err := (&Transport{}).NewClientConn(qconn)
			require.NoError(t, err)
			req, err := NewRequest(ctx, template)
			require.NoError(t, err)
			client, rsp, err := cc.DialWithMode(req, mode)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, rsp.StatusCode)
			t.Cleanup(func() { _ = client.Close() })
			proxy := <-proxyConn
			t.Cleanup(func() { _ = proxy.Close() })

			require.NoError(t, proxy.AssignAddresses([]netip.Prefix{netip.PrefixFrom(testClientAddr, 32)}))
			require.NoError(t, proxy.AdvertiseRoute(allV4Routes))
			_, err = client.ReceiveAddressAssignment(ctx)
			require.NoError(t, err)

			up := ipv4Packet(testClientAddr, testServerAddr, 42)
			_, err = client.WritePacket(up)
			require.NoError(t, err)
			buf := make([]byte, 2000)
			n, err := proxy.ReadPacket(buf)
			require.NoError(t, err)
			require.Equal(t, up, buf[:n])

			down := ipv4Packet(testServerAddr, testClientAddr, 43)
			_, err = proxy.WritePacket(down)
			require.NoError(t, err)
			n, err = client.ReadPacket(buf)
			require.NoError(t, err)
			require.Equal(t, down, buf[:n])
		})
	}
}
