package edgeclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to aero-edge Admin API (api_level=1).
type Client struct {
	baseURL  string
	adminKey string
	http     *http.Client
}

func New(host, adminKey string) *Client {
	base := strings.TrimRight(host, "/")
	if !strings.HasPrefix(base, "http") {
		base = "https://" + base
	}
	return &Client{
		baseURL:  base,
		adminKey: adminKey,
		http: &http.Client{
			// Keep short: mid falls back to SSH when public Admin is blocked/TLS-broken.
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // self-signed edges common
			},
		},
	}
}

func (c *Client) do(method, path string, body any) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.adminKey != "" {
		req.Header.Set("X-Aero-Admin-Key", c.adminKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

func (c *Client) Status() (map[string]any, error) {
	raw, code, err := c.do(http.MethodGet, "/admin/status", nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("edge HTTP %d: %s", code, trim(string(raw), 120))
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Client) ListTokens() ([]map[string]any, error) {
	raw, code, err := c.do(http.MethodGet, "/admin/tokens", nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("edge HTTP %d: %s", code, trim(string(raw), 120))
	}
	var wrap struct {
		Tokens []map[string]any `json:"tokens"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, err
	}
	return wrap.Tokens, nil
}

func (c *Client) AddToken(token, label string, ttlHours int) (map[string]any, error) {
	body := map[string]any{"token": token, "label": label, "ttl_hours": ttlHours}
	raw, code, err := c.do(http.MethodPost, "/admin/tokens", body)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("edge HTTP %d: %s", code, trim(string(raw), 120))
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m, nil
}

func (c *Client) DelToken(token string) error {
	path := "/admin/tokens?token=" + url.QueryEscape(token)
	raw, code, err := c.do(http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("edge HTTP %d: %s", code, trim(string(raw), 120))
	}
	return nil
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
