// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// Package h2pool multiplexes many CONNECT streams over several shared
// TLS+HTTP/2 ClientConns (golang.org/x/net/http2).
//
// Design goals for browser / AI / multi-app VPN:
//   - Many concurrent streams (Chrome opens dozens of CONNECTs)
//   - Several parallel ClientConns to avoid single-conn HOL / stream limits
//   - Standard library HPACK/flow-control (no hand-rolled framer)
package h2pool

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// DialTLS establishes TCP+TLS to Edge (handshake done, ALPN h2).
type DialTLS func() (net.Conn, error)

// Pool keeps multiple live http2.ClientConn per edge for browser-scale concurrency.
type Pool struct {
	mu       sync.Mutex
	conns    map[string][]*managedConn // edgeAddr -> list
	dialing  map[string]*sync.Mutex
	maxConns int
	maxIdle  time.Duration
	rr       map[string]*uint64 // round-robin counters
}

type managedConn struct {
	cc       *http2.ClientConn
	raw      net.Conn
	lastUsed atomic.Int64
	inflight atomic.Int32
	id       int
}

// Default: up to 6 H2 conns per edge (Chrome often opens 20–50 CONNECTs).
var Default = New(6, 3*time.Minute)

// Reset closes every pooled ClientConn. Call on connect/disconnect so a
// second session never reuses a dead H2 session.
func (p *Pool) Reset() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, list := range p.conns {
		for _, mc := range list {
			if mc == nil {
				continue
			}
			_ = mc.cc.Close()
			_ = mc.raw.Close()
		}
		p.conns[addr] = nil
	}
	p.conns = make(map[string][]*managedConn)
	log.Printf("[H2POOL] reset")
}

// New creates a pool.
func New(maxConns int, idleTTL time.Duration) *Pool {
	if maxConns <= 0 {
		maxConns = 4
	}
	if idleTTL <= 0 {
		idleTTL = 3 * time.Minute
	}
	return &Pool{
		conns:    make(map[string][]*managedConn),
		dialing:  make(map[string]*sync.Mutex),
		maxConns: maxConns,
		maxIdle:  idleTTL,
		rr:       make(map[string]*uint64),
	}
}

// Open opens a CONNECT tunnel to target via edgeAddr.
func (p *Pool) Open(edgeAddr, target, token string, dialTLS DialTLS) (net.Conn, error) {
	if edgeAddr == "" || target == "" {
		return nil, fmt.Errorf("empty edge or target")
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		mc, err := p.pickOrDial(edgeAddr, dialTLS)
		if err != nil {
			return nil, err
		}
		c, err := roundTripCONNECT(mc, edgeAddr, target, token, nil)
		if err != nil {
			last = err
			mc.inflight.Add(-1)
			if isConnDead(err) {
				p.drop(edgeAddr, mc)
				continue
			}
			// soft fail: try another conn
			if attempt < 2 {
				continue
			}
			return nil, err
		}
		return c, nil
	}
	if last == nil {
		last = fmt.Errorf("connect failed")
	}
	return nil, last
}

// OpenPreface writes preface on the CONNECT body while waiting for HTTP 200
// so AERO ConnectRequest overlaps the H2 round-trip (one less RTT).
func (p *Pool) OpenPreface(edgeAddr, target, token string, dialTLS DialTLS, preface []byte) (net.Conn, error) {
	if len(preface) == 0 {
		return p.Open(edgeAddr, target, token, dialTLS)
	}
	if edgeAddr == "" || target == "" {
		return nil, fmt.Errorf("empty edge or target")
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		mc, err := p.pickOrDial(edgeAddr, dialTLS)
		if err != nil {
			return nil, err
		}
		c, err := roundTripCONNECT(mc, edgeAddr, target, token, preface)
		if err != nil {
			last = err
			mc.inflight.Add(-1)
			if isConnDead(err) {
				p.drop(edgeAddr, mc)
				continue
			}
			if attempt < 2 {
				continue
			}
			return nil, err
		}
		return c, nil
	}
	if last == nil {
		last = fmt.Errorf("connect failed")
	}
	return nil, last
}

func isConnDead(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	keys := []string{
		"http2: client conn is closed",
		"http2: client conn not usable",
		"client conn not usable",
		"connection refused",
		"broken pipe",
		"EOF",
		"use of closed network connection",
		"GOAWAY",
		"stream closed",
		"PROTOCOL_ERROR",
	}
	for _, k := range keys {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func (p *Pool) pickOrDial(edgeAddr string, dialTLS DialTLS) (*managedConn, error) {
	p.mu.Lock()
	list := p.conns[edgeAddr]
	// prune dead
	alive := list[:0]
	for _, mc := range list {
		if mc != nil && mc.cc.CanTakeNewRequest() {
			alive = append(alive, mc)
		} else if mc != nil {
			_ = mc.cc.Close()
			_ = mc.raw.Close()
		}
	}
	p.conns[edgeAddr] = alive
	list = alive

	// Prefer conn with room and lowest inflight
	var best *managedConn
	for _, mc := range list {
		if !mc.cc.CanTakeNewRequest() {
			continue
		}
		if best == nil || mc.inflight.Load() < best.inflight.Load() {
			best = mc
		}
	}
	// If we have capacity and all conns are busy, dial another
	needDial := best == nil || (len(list) < p.maxConns && best.inflight.Load() >= 24)
	if best != nil && !needDial {
		best.inflight.Add(1)
		best.lastUsed.Store(time.Now().UnixNano())
		p.mu.Unlock()
		return best, nil
	}
	if best != nil && needDial {
		// keep best as fallback; dial under lock release
	}
	dm, ok := p.dialing[edgeAddr]
	if !ok {
		dm = &sync.Mutex{}
		p.dialing[edgeAddr] = dm
	}
	p.mu.Unlock()

	if !needDial && best != nil {
		return best, nil
	}

	dm.Lock()
	defer dm.Unlock()

	// re-check
	p.mu.Lock()
	list = p.conns[edgeAddr]
	best = nil
	for _, mc := range list {
		if mc != nil && mc.cc.CanTakeNewRequest() {
			if best == nil || mc.inflight.Load() < best.inflight.Load() {
				best = mc
			}
		}
	}
	if best != nil && len(list) >= p.maxConns {
		best.inflight.Add(1)
		best.lastUsed.Store(time.Now().UnixNano())
		p.mu.Unlock()
		return best, nil
	}
	if best != nil && best.inflight.Load() < 16 {
		best.inflight.Add(1)
		best.lastUsed.Store(time.Now().UnixNano())
		p.mu.Unlock()
		return best, nil
	}
	n := len(list)
	p.mu.Unlock()

	if dialTLS == nil {
		return nil, fmt.Errorf("no dialTLS")
	}
	raw, err := dialTLS()
	if err != nil {
		// fallback to existing
		if best != nil {
			best.inflight.Add(1)
			return best, nil
		}
		return nil, err
	}
	t1 := &http.Transport{}
	tr, err := http2.ConfigureTransports(t1)
	if err != nil {
		tr = &http2.Transport{AllowHTTP: false}
	}
	cc, err := tr.NewClientConn(raw)
	if err != nil {
		_ = raw.Close()
		if best != nil {
			best.inflight.Add(1)
			return best, nil
		}
		return nil, fmt.Errorf("h2 client conn: %w", err)
	}
	mc := &managedConn{cc: cc, raw: raw, id: n}
	mc.lastUsed.Store(time.Now().UnixNano())
	mc.inflight.Add(1)

	p.mu.Lock()
	p.conns[edgeAddr] = append(p.conns[edgeAddr], mc)
	p.mu.Unlock()
	log.Printf("[H2POOL] new http2.ClientConn #%d -> %s (pool=%d)", n, edgeAddr, n+1)
	return mc, nil
}

func (p *Pool) drop(edgeAddr string, mc *managedConn) {
	if mc == nil {
		return
	}
	p.mu.Lock()
	list := p.conns[edgeAddr]
	out := list[:0]
	for _, x := range list {
		if x != mc {
			out = append(out, x)
		}
	}
	p.conns[edgeAddr] = out
	p.mu.Unlock()
	_ = mc.cc.Close()
	_ = mc.raw.Close()
}

func roundTripCONNECT(mc *managedConn, edgeAddr, target, token string, preface []byte) (net.Conn, error) {
	pr, pw := io.Pipe()

	req := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   edgeAddr,
			Opaque: target,
		},
		Host: target,
		Header: http.Header{
			"Proxy-Authorization": []string{"Bearer " + token},
		},
		Body:          pr,
		ContentLength: -1,
	}

	type result struct {
		resp *http.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := mc.cc.RoundTrip(req)
		ch <- result{resp, err}
	}()
	if len(preface) > 0 {
		go func() {
			_, _ = pw.Write(preface)
		}()
	}

	var res result
	select {
	case res = <-ch:
	case <-time.After(15 * time.Second):
		_ = pw.Close()
		_ = pr.Close()
		return nil, fmt.Errorf("CONNECT timeout")
	}

	if res.err != nil {
		_ = pw.Close()
		return nil, res.err
	}
	resp := res.resp
	if resp.StatusCode != http.StatusOK {
		_ = pw.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("CONNECT status=%d", resp.StatusCode)
	}

	mc.lastUsed.Store(time.Now().UnixNano())
	tc := &tunnelConn{
		r:      resp.Body,
		w:      pw,
		local:  mc.raw.LocalAddr(),
		remote: mc.raw.RemoteAddr(),
		onClose: func() {
			mc.inflight.Add(-1)
		},
	}
	return tc, nil
}

type tunnelConn struct {
	r         io.ReadCloser
	w         *io.PipeWriter
	local     net.Addr
	remote    net.Addr
	mu        sync.Mutex
	closed    bool
	readTimer *time.Timer
	onClose   func()
}

func (c *tunnelConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Write is serialized: heartbeat and TcpFrame share this pipe.
// io.PipeWriter is not safe for concurrent Write; interleaving corrupts AERO frames
// and shows up as "probe works, Chrome/multi-tab dies".
func (c *tunnelConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	return c.w.Write(p)
}

func (c *tunnelConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	_ = c.w.Close()
	_ = c.r.Close()
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

func (c *tunnelConn) LocalAddr() net.Addr { return c.local }
func (c *tunnelConn) RemoteAddr() net.Addr { return c.remote }

func (c *tunnelConn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

func (c *tunnelConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	if c.closed || t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		_ = c.r.Close()
		return nil
	}
	c.readTimer = time.AfterFunc(d, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.closed {
			_ = c.r.Close()
		}
	})
	return nil
}

func (c *tunnelConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*tunnelConn)(nil)
