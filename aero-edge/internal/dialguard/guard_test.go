package dialguard

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestIsBlockedTarget(t *testing.T) {
	cases := []struct {
		in      string
		blocked bool
	}{
		{"127.0.0.1:55556", true},
		{"localhost:80", true},
		{"10.0.0.1:443", true},
		{"192.168.1.1:443", true},
		{"8.8.8.8:443", false},
		{"www.google.com:443", false},
		{"[::1]:443", true},
	}
	for _, c := range cases {
		b, _ := IsBlockedTarget(c.in)
		if b != c.blocked {
			t.Fatalf("%s: blocked=%v want %v", c.in, b, c.blocked)
		}
	}
}

func TestDialQueue(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	g := New(2)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := g.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
			if err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			c.Close()
		}()
	}
	wg.Wait()
}
