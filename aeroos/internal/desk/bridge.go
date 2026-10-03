package desk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const (
	DefaultAPIEndpoint = "http://127.0.0.1:19877"
	DefaultMixedProxy  = "127.0.0.1:55555"
)

// NetStatus represents the live network state returned from Client API
type NetStatus struct {
	Connected   bool   `json:"connected"`
	Mode        string `json:"mode"`
	Listen      string `json:"listen"`
	Node        string `json:"node"`
	RTTMs       uint32 `json:"rtt_ms"`
	SubURL      string `json:"sub_url"`
	SubURLMask  string `json:"sub_url_mask"`
	LastError   string `json:"last_error"`
	ProbeOK     *bool  `json:"probe_ok,omitempty"`
	ProbeMS     int64  `json:"probe_ms,omitempty"`
	ProbeDetail string `json:"probe_detail,omitempty"`
	Protocol    string `json:"protocol"`
	ISP         string `json:"isp"`
	SNI         string `json:"sni"`
}

// ClientBridge manages HTTP communication with local aero-client daemon
type ClientBridge struct {
	endpoint string
	client   *http.Client
}

// NewClientBridge creates a bridge connected to Client REST API
func NewClientBridge(endpoint string) *ClientBridge {
	if endpoint == "" {
		endpoint = DefaultAPIEndpoint
	}
	return &ClientBridge{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Ping checks if client API is reachable
func (b *ClientBridge) Ping() bool {
	resp, err := b.client.Get(b.endpoint + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// GetStatus queries current network and connection state
func (b *ClientBridge) GetStatus(probe bool) (*NetStatus, error) {
	url := b.endpoint + "/api/v1/status"
	if probe {
		url += "?probe=1"
	}
	resp, err := b.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("client api unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status query failed (%d): %s", resp.StatusCode, string(body))
	}

	var st NetStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, fmt.Errorf("decode status failed: %w", err)
	}
	return &st, nil
}

// Connect triggers network proxy/VPN connection
func (b *ClientBridge) Connect() error {
	resp, err := b.client.Post(b.endpoint+"/api/v1/connect", "application/json", nil)
	if err != nil {
		return fmt.Errorf("connect request failed: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// Disconnect releases proxy/VPN session
func (b *ClientBridge) Disconnect() error {
	resp, err := b.client.Post(b.endpoint+"/api/v1/disconnect", "application/json", nil)
	if err != nil {
		return fmt.Errorf("disconnect request failed: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// SetMode sets proxy mode ("sysproxy" or "tun")
func (b *ClientBridge) SetMode(mode string) error {
	payload, _ := json.Marshal(map[string]string{"mode": mode})
	resp, err := b.client.Post(b.endpoint+"/api/v1/mode", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("set mode request failed: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// ImportSub imports a subscription URL into the client
func (b *ClientBridge) ImportSub(subURL string) error {
	payload, _ := json.Marshal(map[string]string{"sub": subURL})
	resp, err := b.client.Post(b.endpoint+"/api/v1/import", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("import subscription failed: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// Probe runs live latency probe
func (b *ClientBridge) Probe() (map[string]interface{}, error) {
	resp, err := b.client.Get(b.endpoint + "/api/v1/probe")
	if err != nil {
		return nil, fmt.Errorf("probe request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// ClientDaemon 管理本地客户端后台守护进程
type ClientDaemon struct {
	bridge      *ClientBridge
	cmd         *exec.Cmd
	startedByMe bool
	mu          sync.Mutex
}

func NewClientDaemon(bridge *ClientBridge) *ClientDaemon {
	return &ClientDaemon{
		bridge: bridge,
	}
}

// EnsureRunning checks if client is online, launching aero-client if offline
func (d *ClientDaemon) EnsureRunning() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.bridge.Ping() {
		log.Printf("[NETCORE] Client already active on 127.0.0.1:19877")
		return nil
	}

	binPath := d.findClientBinary()
	if binPath == "" {
		log.Printf("[NETCORE] aero-client not found, expecting external client")
		return nil
	}

	log.Printf("[NETCORE] Starting background client daemon: %s", binPath)
	cmd := exec.Command(binPath)
	hideProcessWindow(cmd)

	if err := cmd.Start(); err != nil {
		log.Printf("[NETCORE] Failed to launch client daemon: %v", err)
		return err
	}

	d.cmd = cmd
	d.startedByMe = true

	for i := 0; i < 25; i++ {
		time.Sleep(200 * time.Millisecond)
		if d.bridge.Ping() {
			log.Printf("[NETCORE] Client daemon is ready on 127.0.0.1:19877")
			return nil
		}
	}
	log.Printf("[NETCORE] Client daemon launched (pid=%d), waiting for initialization...", cmd.Process.Pid)
	return nil
}

// Stop cleanly terminates the daemon if it was started by AERO OS
func (d *ClientDaemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.startedByMe && d.cmd != nil && d.cmd.Process != nil {
		_ = d.bridge.Disconnect()
		_ = d.cmd.Process.Kill()
		log.Printf("[NETCORE] Stopped client daemon pid=%d", d.cmd.Process.Pid)
		d.cmd = nil
		d.startedByMe = false
	}
}

func (d *ClientDaemon) findClientBinary() string {
	if env := os.Getenv("AERO_CLIENT_BIN"); env != "" {
		if fi, err := os.Stat(env); err == nil && !fi.IsDir() {
			return env
		}
	}

	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "aero-client.exe"),
			filepath.Join(dir, "aero-client-cli.exe"),
			filepath.Join(dir, "aero-client"),
			filepath.Join(dir, "..", "dist", "win", "aero-client.exe"),
			filepath.Join(dir, "..", "..", "dist", "win", "aero-client.exe"),
		)
	}

	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "aero-client.exe"),
			filepath.Join(cwd, "aero-client"),
			filepath.Join(cwd, "dist", "win", "aero-client.exe"),
		)
	}

	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			abs, err := filepath.Abs(p)
			if err == nil {
				return abs
			}
			return p
		}
	}
	return ""
}
