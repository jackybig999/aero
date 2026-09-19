// Package cloudflare implements lightweight Cloudflare DNS API automation.
// Enforces pure DNS resolution (proxied: false) to protect AERO H2 CONNECT tunnels.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	APIToken   string
	ZoneID     string
	RootDomain string
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

func NewFromEnv() *Client {
	return New(Config{
		APIToken:   strings.TrimSpace(os.Getenv("CF_API_TOKEN")),
		ZoneID:     strings.TrimSpace(os.Getenv("CF_ZONE_ID")),
		RootDomain: strings.TrimSpace(os.Getenv("CF_ROOT_DOMAIN")),
	})
}

func New(cfg Config) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) Enabled() bool {
	return c.cfg.APIToken != "" && c.cfg.ZoneID != ""
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

type cfListResponse struct {
	Success  bool          `json:"success"`
	Errors   []cfError     `json:"errors"`
	Messages []string      `json:"messages"`
	Result   []cfDNSRecord `json:"result"`
}

type cfSingleResponse struct {
	Success bool        `json:"success"`
	Errors  []cfError   `json:"errors"`
	Result  cfDNSRecord `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// SyncGrayCloudARecord creates or updates an A record on Cloudflare.
// CRITICAL: proxied is hardcoded to false (Gray Cloud / DNS-Only) to preserve AERO H2 tunnel integrity.
func (c *Client) SyncGrayCloudARecord(ctx context.Context, domain, targetIP string) (recordID string, err error) {
	if !c.Enabled() {
		return "", fmt.Errorf("Cloudflare API 未配置 (缺少 CF_API_TOKEN 或 CF_ZONE_ID)")
	}
	domain = strings.TrimSpace(domain)
	targetIP = strings.TrimSpace(targetIP)
	if domain == "" || targetIP == "" {
		return "", fmt.Errorf("domain and targetIP required")
	}

	// 1. 查询是否已有该域名的 A 记录
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=A&name=%s", c.cfg.ZoneID, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cf query dns failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var listResp cfListResponse
	if err := json.Unmarshal(body, &listResp); err != nil {
		return "", fmt.Errorf("cf parse response failed: %w", err)
	}
	if !listResp.Success {
		errMsg := "unknown cf error"
		if len(listResp.Errors) > 0 {
			errMsg = listResp.Errors[0].Message
		}
		return "", fmt.Errorf("cf api error: %s", errMsg)
	}

	payload := map[string]any{
		"type":    "A",
		"name":    domain,
		"content": targetIP,
		"ttl":     1,     // Auto TTL
		"proxied": false, // 铁律：强制灰云朵 DNS-Only！
	}
	payloadBytes, _ := json.Marshal(payload)

	// 2. 若已有记录且内容/proxied 不符合，执行更新
	if len(listResp.Result) > 0 {
		existing := listResp.Result[0]
		if existing.Content == targetIP && !existing.Proxied {
			// 已经完全匹配且为灰云
			return existing.ID, nil
		}
		updateURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", c.cfg.ZoneID, existing.ID)
		putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, updateURL, bytes.NewReader(payloadBytes))
		if err != nil {
			return "", err
		}
		putReq.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
		putReq.Header.Set("Content-Type", "application/json")
		putResp, err := c.httpClient.Do(putReq)
		if err != nil {
			return "", fmt.Errorf("cf update dns failed: %w", err)
		}
		defer putResp.Body.Close()
		putBody, _ := io.ReadAll(putResp.Body)
		var singleResp cfSingleResponse
		_ = json.Unmarshal(putBody, &singleResp)
		if !singleResp.Success {
			errMsg := "update failed"
			if len(singleResp.Errors) > 0 {
				errMsg = singleResp.Errors[0].Message
			}
			return "", fmt.Errorf("cf update error: %s", errMsg)
		}
		return singleResp.Result.ID, nil
	}

	// 3. 不存在，执行创建
	createURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", c.cfg.ZoneID)
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, createURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return "", err
	}
	postReq.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	postReq.Header.Set("Content-Type", "application/json")
	postResp, err := c.httpClient.Do(postReq)
	if err != nil {
		return "", fmt.Errorf("cf create dns failed: %w", err)
	}
	defer postResp.Body.Close()
	postBody, _ := io.ReadAll(postResp.Body)
	var singleResp cfSingleResponse
	_ = json.Unmarshal(postBody, &singleResp)
	if !singleResp.Success {
		errMsg := "create failed"
		if len(singleResp.Errors) > 0 {
			errMsg = singleResp.Errors[0].Message
		}
		return "", fmt.Errorf("cf create error: %s", errMsg)
	}
	return singleResp.Result.ID, nil
}
