package service

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func probeHTTPImpl(rawURL string, timeout time.Duration) (ok bool, code int, errMsg string, n int) {
	if strings.TrimSpace(rawURL) == "" {
		return false, 0, "empty url", 0
	}
	cli := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := cli.Get(rawURL)
	if err != nil {
		return false, 0, trim(err.Error(), 120), 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && len(b) > 0 {
		return true, resp.StatusCode, "", len(b)
	}
	return false, resp.StatusCode, fmt.Sprintf("http %d", resp.StatusCode), len(b)
}
