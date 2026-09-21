package apimatrix

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"aisys/connect/os/internal/audit"
)

type Tester struct {
	vault     *APIVault
	proxyAddr string
}

func NewTester(vault *APIVault, proxyAddr string) *Tester {
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:55555"
	}
	return &Tester{
		vault:     vault,
		proxyAddr: proxyAddr,
	}
}

func (t *Tester) TestProvider(id string) (string, int64, error) {
	all := t.vault.GetAll()
	var target *APIProviderConfig
	for _, p := range all {
		if p.ID == id {
			target = p
			break
		}
	}

	if target == nil {
		return "error", 0, fmt.Errorf("unknown provider: %s", id)
	}

	if target.APIKey == "" {
		t.vault.UpdateStatus(id, "untested", 0, time.Now().Format("15:04:05"))
		return "untested", 0, fmt.Errorf("未配置 API Key")
	}

	// Create HTTP client using proxy
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}

	if t.proxyAddr != "" {
		if proxyURL, err := url.Parse("http://" + t.proxyAddr); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
	}

	start := time.Now()
	testURL := target.BaseURL
	if testURL == "" {
		testURL = target.DefaultURL
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return "error", 0, err
	}

	req.Header.Set("User-Agent", "AERO-OS-KeyMatrix/2.0")
	if id == "anthropic" {
		req.Header.Set("x-api-key", target.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	} else if id == "gemini" {
		// query params or key
	} else {
		req.Header.Set("Authorization", "Bearer "+target.APIKey)
	}

	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()

	status := "valid"
	if err != nil {
		status = "error"
		audit.GlobalLogger.Log("WARN", "APIMATRIX", fmt.Sprintf("[%s] 连通性测试异常 (%dms): %v", target.Name, latency, err))
	} else {
		defer resp.Body.Close()
		// If status is 401 / 403, key is invalid
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			status = "invalid"
		} else {
			status = "valid"
		}
		audit.GlobalLogger.Log("INFO", "APIMATRIX", fmt.Sprintf("[%s] 连通性检测完成: status=%s, code=%d, 时延=%dms", target.Name, status, resp.StatusCode, latency))
	}

	nowStr := time.Now().Format("15:04:05")
	t.vault.UpdateStatus(id, status, latency, nowStr)
	return status, latency, err
}
