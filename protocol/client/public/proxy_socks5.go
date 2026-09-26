package public

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/aero-protocol/aero-ech/internal/tun"
)

// isSTUNPacket 检测是否为 WebRTC STUN 探针数据包（RFC 5389 / RFC 8489）
// 格式：0-1 字节为消息类型，4-7 字节为 Magic Cookie 0x2112A442
func isSTUNPacket(payload []byte) bool {
	if len(payload) < 20 {
		return false
	}
	return payload[4] == 0x21 && payload[5] == 0x12 && payload[6] == 0xa4 && payload[7] == 0x42
}

// -----------------------------------------------------------------------------
// Source: socks5.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

const (
	socksCmdConnect = 0x01
	socksCmdUDP     = 0x03
)

// handleSocks5Buffered: SOCKS5 after mixed peek (reader already has buffered bytes).
func handleSocks5Buffered(client net.Conn, br *bufio.Reader) {
	cmd, target, err := handshakeSocks5Reader(br, client)
	if err != nil {
		log.Printf("socks5 handshake failed: %v", err)
		return
	}
	if cmd == socksCmdUDP {
		serveSocksUDP(client, target)
		return
	}
	log.Printf("[SOCKS5] CONNECT %s", target)
	bc := &bufConn{Conn: client, r: br}
	serveTarget(bc, target, func(ok bool) {
		if ok {
			log.Printf("[SOCKS5] CONNECT ok %s", target)
			_ = replySocks5Bind(client, 0x00, net.IPv4(127, 0, 0, 1), 0)
		} else {
			log.Printf("[SOCKS5] CONNECT fail %s", target)
			_ = replySocks5(client, 0x01)
		}
	})
}

// handleClient keeps a pure-SOCKS entry for tests; production uses mixed.
func handleClient(client net.Conn) {
	defer client.Close()
	br := bufio.NewReader(client)
	handleSocks5Buffered(client, br)
}

func handshakeSocks5Reader(reader *bufio.Reader, conn net.Conn) (cmd byte, target string, err error) {
	greeting := make([]byte, 2)
	if _, err = io.ReadFull(reader, greeting); err != nil {
		return 0, "", err
	}
	if greeting[0] != 0x05 {
		return 0, "", fmt.Errorf("not SOCKS5")
	}
	nmethods := int(greeting[1])
	methods := make([]byte, nmethods)
	if nmethods > 0 {
		if _, err = io.ReadFull(reader, methods); err != nil {
			return 0, "", err
		}
	}

	// Clash/sing-box mixed: always NO-AUTH. Reply before logging so
	// fingerprint testers (Roxy SocksClient) are not racing the log write.
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return 0, "", err
	}
	if n := reader.Buffered(); n > 0 {
		if n > 16 {
			n = 16
		}
		if p, pe := reader.Peek(n); pe == nil {
			log.Printf("[SOCKS5] from=%s methods=%v peek=%x", conn.RemoteAddr(), methods, p)
		}
	} else {
		log.Printf("[SOCKS5] from=%s methods=%v", conn.RemoteAddr(), methods)
	}
	if reader.Buffered() > 0 {
		if p, pe := reader.Peek(1); pe == nil && p[0] == 0x01 {
			if err = readSocksUserPass(reader, conn); err != nil {
				return 0, "", err
			}
		}
	}

	header := make([]byte, 4)
	if _, err = io.ReadFull(reader, header); err != nil {
		return 0, "", err
	}
	if header[0] != 0x05 {
		return 0, "", fmt.Errorf("bad request ver %d", header[0])
	}
	cmd = header[1]
	if cmd != socksCmdConnect && cmd != socksCmdUDP {
		_ = replySocks5(conn, 0x07)
		return cmd, "", fmt.Errorf("unsupported command %d", cmd)
	}

	target, err = readSocksAddr(reader, header[3])
	if err != nil {
		return 0, "", err
	}
	return cmd, target, nil
}

func readSocksAddr(reader *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", err
		}
		portb := make([]byte, 2)
		if _, err := io.ReadFull(reader, portb); err != nil {
			return "", err
		}
		p := binary.BigEndian.Uint16(portb)
		return fmt.Sprintf("%s:%d", net.IP(addr).String(), p), nil
	case 0x03:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(reader, lenByte); err != nil {
			return "", err
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(reader, domain); err != nil {
			return "", err
		}
		portb := make([]byte, 2)
		if _, err := io.ReadFull(reader, portb); err != nil {
			return "", err
		}
		p := binary.BigEndian.Uint16(portb)
		return fmt.Sprintf("%s:%d", string(domain), p), nil
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", err
		}
		portb := make([]byte, 2)
		if _, err := io.ReadFull(reader, portb); err != nil {
			return "", err
		}
		p := binary.BigEndian.Uint16(portb)
		return fmt.Sprintf("[%s]:%d", net.IP(addr).String(), p), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

func readSocksUserPass(reader *bufio.Reader, conn net.Conn) error {
	ver := make([]byte, 2)
	if _, err := io.ReadFull(reader, ver); err != nil {
		return err
	}
	ulen := int(ver[1])
	if ulen < 0 || ulen > 255 {
		return fmt.Errorf("bad ulen")
	}
	user := make([]byte, ulen)
	if ulen > 0 {
		if _, err := io.ReadFull(reader, user); err != nil {
			return err
		}
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(reader, plenBuf); err != nil {
		return err
	}
	pass := make([]byte, int(plenBuf[0]))
	if len(pass) > 0 {
		if _, err := io.ReadFull(reader, pass); err != nil {
			return err
		}
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func handshakeSocks5(conn net.Conn) (string, error) {
	cmd, target, err := handshakeSocks5Reader(bufio.NewReader(conn), conn)
	if err != nil {
		return "", err
	}
	if cmd != socksCmdConnect {
		return "", fmt.Errorf("unsupported command %d", cmd)
	}
	return target, nil
}

type prefillConn struct {
	net.Conn
	r io.Reader
}

func (c *prefillConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func startPrefetch(c net.Conn) net.Conn {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		_, _ = io.Copy(pw, c)
	}()
	return &prefillConn{Conn: c, r: pr}
}

func replySocks5(conn net.Conn, code byte) error {
	return replySocks5Bind(conn, code, net.IPv4zero, 0)
}

func replySocks5Bind(conn net.Conn, code byte, ip net.IP, port uint16) error {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero.To4()
	}
	buf := []byte{0x05, code, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], 0, 0}
	binary.BigEndian.PutUint16(buf[8:], port)
	_, err := conn.Write(buf)
	return err
}

func handleSocks4Buffered(client net.Conn, br *bufio.Reader) {
	hdr := make([]byte, 8) // VN CD PORT[2] IP[4] — VN already in buffer
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if hdr[0] != 0x04 || hdr[1] != 0x01 {
		replySocks4(client, 0x5b)
		return
	}
	port := binary.BigEndian.Uint16(hdr[2:4])
	ip := net.IP(hdr[4:8])
	// userid until NUL
	if _, err := br.ReadBytes(0); err != nil {
		replySocks4(client, 0x5b)
		return
	}
	var target string
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
		dom, err := br.ReadBytes(0)
		if err != nil || len(dom) < 2 {
			replySocks4(client, 0x5b)
			return
		}
		target = fmt.Sprintf("%s:%d", string(dom[:len(dom)-1]), port)
	} else {
		target = fmt.Sprintf("%s:%d", ip.String(), port)
	}
	if err := replySocks4(client, 0x5a); err != nil {
		return
	}
	bc := &bufConn{Conn: client, r: br}
	serveTarget(bc, target, func(ok bool) {
		if !ok {
			log.Printf("socks4 tunnel fail %s", target)
		}
	})
}

func replySocks4(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{0x00, code, 0, 0, 0, 0, 0, 0})
	return err
}

// -----------------------------------------------------------------------------
// Source: socks5_udp.go
// -----------------------------------------------------------------------------
// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

type udpTunnelEntry struct {
	conn       net.Conn
	lastActive time.Time
}

// serveSocksUDP: SOCKS5 UDP ASSOCIATE. TCP control stays open until the
// client drops it; datagrams are relayed through existing openAEROUDP.
func serveSocksUDP(control net.Conn, _ string) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		log.Printf("[SOCKS-UDP] listen: %v", err)
		_ = replySocks5(control, 0x01)
		return
	}
	defer pc.Close()

	uaddr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = replySocks5(control, 0x01)
		return
	}
	if err := replySocks5Bind(control, 0x00, net.IPv4(127, 0, 0, 1), uint16(uaddr.Port)); err != nil {
		return
	}
	log.Printf("[SOCKS-UDP] associate 127.0.0.1:%d", uaddr.Port)

	var (
		mu       sync.Mutex
		tunnels  = map[string]*udpTunnelEntry{}
		clientUA net.Addr
	)
	closeTunnels := func() {
		mu.Lock()
		defer mu.Unlock()
		for k, e := range tunnels {
			_ = e.conn.Close()
			delete(tunnels, k)
		}
	}
	defer closeTunnels()

	stopCleaner := make(chan struct{})
	defer close(stopCleaner)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCleaner:
				return
			case <-ticker.C:
				mu.Lock()
				now := time.Now()
				for k, e := range tunnels {
					if now.Sub(e.lastActive) > 2*time.Minute {
						_ = e.conn.Close()
						delete(tunnels, k)
					}
				}
				mu.Unlock()
			}
		}
	}()

	go func() {
		buf := make([]byte, 1)
		_, _ = control.Read(buf)
		_ = pc.SetDeadline(time.Now())
	}()

	buf := make([]byte, 64*1024)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		dest, payload, err := parseSocksUDP(buf[:n])
		if err != nil {
			continue
		}
		// Fake-IP (198.18.0.0/15) 内存 0ms 反查还原
		if h, p, e := net.SplitHostPort(dest); e == nil {
			if ip := net.ParseIP(h); ip != nil {
				if v4 := ip.To4(); v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
					if domain, ok := tun.DefaultFakeIPTable.Lookup(ip); ok {
						dest = net.JoinHostPort(domain, p)
					}
				}
			}
		}

		isSTUN := isSTUNPacket(payload)
		mu.Lock()
		clientUA = from
		entry, ok := tunnels[dest]
		if !ok {
			tun, err := openAEROUDP(dest)
			if err != nil {
				mu.Unlock()
				if isSTUN {
					log.Printf("[WEBRTC-ARMOR] STUN packet to %s blackholed (tunnel unavailable, leak prevented)", dest)
				} else {
					log.Printf("[SOCKS-UDP] dial %s: %v", dest, err)
				}
				continue
			}
			entry = &udpTunnelEntry{conn: tun, lastActive: time.Now()}
			tunnels[dest] = entry
			go relayUDPToClient(pc, tun, dest, &clientUA, &mu, entry, tunnels)
		} else {
			entry.lastActive = time.Now()
		}
		mu.Unlock()
		if _, err := entry.conn.Write(payload); err != nil {
			mu.Lock()
			_ = entry.conn.Close()
			delete(tunnels, dest)
			mu.Unlock()
		}
	}
}

func relayUDPToClient(pc net.PacketConn, tun net.Conn, dest string, clientUA *net.Addr, mu *sync.Mutex, entry *udpTunnelEntry, tunnels map[string]*udpTunnelEntry) {
	defer func() {
		_ = tun.Close()
		mu.Lock()
		if cur, ok := tunnels[dest]; ok && cur == entry {
			delete(tunnels, dest)
		}
		mu.Unlock()
	}()
	buf := make([]byte, 64*1024)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			return
		}
		pkt, err := encodeSocksUDP(dest, buf[:n])
		if err != nil {
			return
		}
		mu.Lock()
		entry.lastActive = time.Now()
		to := *clientUA
		mu.Unlock()
		if to == nil {
			return
		}
		_, _ = pc.WriteTo(pkt, to)
	}
}

func parseSocksUDP(b []byte) (dest string, payload []byte, err error) {
	if len(b) < 7 {
		return "", nil, io.ErrUnexpectedEOF
	}
	if b[0] != 0 || b[1] != 0 {
		return "", nil, fmt.Errorf("bad rsv")
	}
	if b[2] != 0 {
		return "", nil, fmt.Errorf("frag")
	}
	atyp := b[3]
	off := 4
	switch atyp {
	case 0x01:
		if len(b) < off+4+2 {
			return "", nil, io.ErrUnexpectedEOF
		}
		ip := net.IP(b[off : off+4])
		off += 4
		p := binary.BigEndian.Uint16(b[off : off+2])
		off += 2
		return fmt.Sprintf("%s:%d", ip.String(), p), b[off:], nil
	case 0x03:
		if len(b) < off+1 {
			return "", nil, io.ErrUnexpectedEOF
		}
		n := int(b[off])
		off++
		if len(b) < off+n+2 {
			return "", nil, io.ErrUnexpectedEOF
		}
		host := string(b[off : off+n])
		off += n
		p := binary.BigEndian.Uint16(b[off : off+2])
		off += 2
		return fmt.Sprintf("%s:%d", host, p), b[off:], nil
	case 0x04:
		if len(b) < off+16+2 {
			return "", nil, io.ErrUnexpectedEOF
		}
		ip := net.IP(b[off : off+16])
		off += 16
		p := binary.BigEndian.Uint16(b[off : off+2])
		off += 2
		return fmt.Sprintf("[%s]:%d", ip.String(), p), b[off:], nil
	default:
		return "", nil, fmt.Errorf("atyp %d", atyp)
	}
}

func encodeSocksUDP(dest string, payload []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	ip := net.ParseIP(host)
	var mid []byte
	if ip4 := ip.To4(); ip4 != nil {
		mid = append([]byte{0x01}, ip4...)
	} else if ip != nil {
		mid = append([]byte{0x04}, ip.To16()...)
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("host too long")
		}
		mid = append([]byte{0x03, byte(len(host))}, []byte(host)...)
	}
	out := make([]byte, 0, 3+len(mid)+2+len(payload))
	out = append(out, 0, 0, 0)
	out = append(out, mid...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	out = append(out, pb[:]...)
	out = append(out, payload...)
	return out, nil
}
