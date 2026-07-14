package cover

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHomeLooksLikeSite(t *testing.T) {
	s := New(Config{SiteName: "TestCDN"})
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://x/", nil))
	if rr.Code != 200 {
		t.Fatal(rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "TestCDN") || !strings.Contains(body, "<!DOCTYPE html>") {
		t.Fatal(body[:min(200, len(body))])
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatal(ct)
	}
}

func Test404HTML(t *testing.T) {
	s := New(Config{})
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/no/such", nil))
	if rr.Code != 404 {
		t.Fatal(rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "404") {
		t.Fatal(rr.Body.String())
	}
}

func TestRobots(t *testing.T) {
	s := New(Config{})
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/robots.txt", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "User-agent") {
		t.Fatal(rr.Body.String())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
