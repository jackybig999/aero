package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowBurst(t *testing.T) {
	l := New(2)
	if !l.Allow("1.1.1.1") || !l.Allow("1.1.1.1") {
		t.Fatal("burst of 2 should pass")
	}
	if l.Allow("1.1.1.1") {
		t.Fatal("third should be rate limited")
	}
	if !l.Allow("2.2.2.2") {
		t.Fatal("other IP should pass")
	}
}

func TestBanAfterFails(t *testing.T) {
	l := New(100)
	l.banAfter = 3
	for i := 0; i < 2; i++ {
		if l.RecordFail("9.9.9.9") {
			t.Fatal("should not ban yet")
		}
	}
	if !l.RecordFail("9.9.9.9") {
		t.Fatal("third fail should ban")
	}
	if !l.IsBanned("9.9.9.9") {
		t.Fatal("expected banned")
	}
	if l.Allow("9.9.9.9") {
		t.Fatal("banned IP must not allow")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodConnect, "https://x/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	if ip := ClientIP(r); ip != "10.0.0.1" {
		t.Fatalf("got %q", ip)
	}
	r.Header.Set("X-Forwarded-For", "8.8.8.8, 1.1.1.1")
	if ip := ClientIP(r); ip != "8.8.8.8" {
		t.Fatalf("xff got %q", ip)
	}
}
