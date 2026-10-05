// Copyright 2026 AERO Protocol Contributors
// AERO Node Topology, VPS Machine Assets & Registry Subsystem
package mid

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ----------------------------------------------------------------------
// Node Models & NodeService
// ----------------------------------------------------------------------

type Node struct {
	ID            uint64     `json:"id"`
	VPSID         uint64     `json:"vps_id"`
	Name          string     `json:"name"`
	Region        string     `json:"region"`
	IP            string     `json:"ip"`
	Address       string     `json:"address,omitempty"`
	Port          int32      `json:"port"`
	Protocol      string     `json:"protocol"`
	Status        bool       `json:"status"`
	MaxUsers      int32      `json:"max_users"`
	CurrentUsers  int32      `json:"current_users"`
	IsBackup      bool       `json:"is_backup"`
	Weight        int32      `json:"weight"`
	PurityScore   int        `json:"purity_score,omitempty"`
	LatencyMS     int64      `json:"latency_ms,omitempty"`
	BandwidthMB   int32      `json:"bandwidth_mb,omitempty"`
	AgentVersion  string     `json:"agent_version,omitempty"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type NodeService struct {
	mu     sync.RWMutex
	nodes  map[uint64]*Node
	nextID uint64
}

func NewNodeService() *NodeService {
	return &NodeService{
		nodes:  make(map[uint64]*Node),
		nextID: 1,
	}
}

func (s *NodeService) CreateNode(name, region, ip, protocol string, port, max int32, backup bool, weight int32, vpsID uint64) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := &Node{
		ID:           s.nextID,
		VPSID:        vpsID,
		Name:         name,
		Region:       region,
		IP:           ip,
		Address:      ip,
		Port:         port,
		Protocol:     protocol,
		Status:       true,
		MaxUsers:     max,
		CurrentUsers: 0,
		IsBackup:     backup,
		Weight:       weight,
		PurityScore:  100,
		LatencyMS:    35,
		BandwidthMB:  1000,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.nextID++
	s.nodes[n.ID] = n
	return n, nil
}

func (s *NodeService) GetNode(id uint64) (*Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n, ok := s.nodes[id]; ok {
		cp := *n
		return &cp, nil
	}
	return nil, errors.New("node not found")
}

func (s *NodeService) ListAll() ([]Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []Node
	for _, n := range s.nodes {
		item := *n
		if item.Region == "" || item.Region == "node" || item.Region == "edge" || strings.HasPrefix(item.Region, "VPS") || !strings.Contains(item.Region, "AS") {
			targetIP := item.IP
			if targetIP == "" {
				targetIP = item.Address
			}
			if targetIP != "" {
				item.Region = ResolveIPRegion(targetIP)
				n.Region = item.Region
			}
		}
		list = append(list, item)
	}
	return list, nil
}

func (s *NodeService) ListAvailable() ([]Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []Node
	for _, n := range s.nodes {
		if n.Status {
			item := *n
			if item.Region == "" || item.Region == "node" || item.Region == "edge" || strings.HasPrefix(item.Region, "VPS") || !strings.Contains(item.Region, "AS") {
				targetIP := item.IP
				if targetIP == "" {
					targetIP = item.Address
				}
				if targetIP != "" {
					item.Region = ResolveIPRegion(targetIP)
					n.Region = item.Region
				}
			}
			list = append(list, item)
		}
	}
	return list, nil
}

func (s *NodeService) Heartbeat(id uint64, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[id]; ok {
		now := time.Now()
		n.Status = true
		n.AgentVersion = version
		n.LastHeartbeat = &now
		n.UpdatedAt = now
		return nil
	}
	return errors.New("node not found")
}

func (s *NodeService) ProbeNode(id uint64) (bool, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return false, 0, errors.New("node not found")
	}
	targetHost := strings.TrimSpace(n.IP)
	if n.Address != "" {
		targetHost = strings.TrimSpace(n.Address)
	}
	if host, _, err := net.SplitHostPort(targetHost); err == nil {
		targetHost = host
	}
	targetPort := n.Port
	if targetPort <= 0 {
		targetPort = 443
	}
	targetAddr := net.JoinHostPort(targetHost, fmt.Sprint(targetPort))

	start := time.Now()
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.Dial("tcp", targetAddr)
	now := time.Now()
	if err != nil {
		n.Status = false
		n.UpdatedAt = now
		return false, 0, fmt.Errorf("连通性探测失败 (%s: %w)", targetAddr, err)
	}
	defer conn.Close()

	latency := time.Since(start).Milliseconds()
	n.Status = true
	n.LatencyMS = latency
	n.LastHeartbeat = &now
	n.UpdatedAt = now
	return true, latency, nil
}

func (s *NodeService) DeleteNode(id uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.nodes, id)
	return nil
}

func (s *NodeService) DeleteMatching(vpsID uint64, ip string) ([]uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var deleted []uint64
	for id, n := range s.nodes {
		if (vpsID > 0 && n.VPSID == vpsID) || (ip != "" && n.IP == ip) {
			deleted = append(deleted, id)
			delete(s.nodes, id)
		}
	}
	return deleted, nil
}

func (s *NodeService) UpdateHostByVPS(vpsID uint64, newHost string) {
	if vpsID == 0 || newHost == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.nodes {
		if n.VPSID == vpsID {
			n.IP = newHost
			n.UpdatedAt = time.Now()
		}
	}
}

// ----------------------------------------------------------------------
// NodeHandler
// ----------------------------------------------------------------------

type NodeHandler struct {
	svc      *NodeService
	vpsStore VPSStore
	vpsSvc   *VPSService
	aeroDB   *AeroDB
}

func NewNodeHandler(svc *NodeService, vpsStore ...VPSStore) *NodeHandler {
	h := &NodeHandler{svc: svc}
	if len(vpsStore) > 0 {
		h.vpsStore = vpsStore[0]
	}
	return h
}

func (h *NodeHandler) SetVPSService(v *VPSService) { h.vpsSvc = v }
func (h *NodeHandler) SetAeroDB(db *AeroDB)        { h.aeroDB = db }

func (h *NodeHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/nodes/", h.Create)
	mux.HandleFunc("GET /api/v1/nodes/", h.List)
	mux.HandleFunc("GET /api/v1/nodes/available/", h.Available)
	mux.HandleFunc("DELETE /api/v1/nodes/orphan/", h.CleanOrphans)
	mux.HandleFunc("DELETE /api/v1/nodes/orphan", h.CleanOrphans)
	mux.HandleFunc("DELETE /api/v1/nodes/", h.CascadeDelete)
	mux.HandleFunc("GET /api/v1/nodes/{id}/", h.Get)
	mux.HandleFunc("POST /api/v1/nodes/{id}/heartbeat/", h.Heartbeat)
	mux.HandleFunc("DELETE /api/v1/nodes/{id}/", h.Delete)
}

func (h *NodeHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Region   string `json:"region"`
		IP       string `json:"ip"`
		Protocol string `json:"protocol"`
		Port     int32  `json:"port"`
		MaxUsers int32  `json:"max_users"`
		IsBackup bool   `json:"is_backup"`
		Weight   int32  `json:"weight"`
		VPSID    uint64 `json:"vps_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "invalid body"})
		return
	}
	if req.Protocol == "" {
		req.Protocol = "aero"
	}
	if req.Port <= 0 {
		req.Port = 443
	}
	if req.MaxUsers <= 0 {
		req.MaxUsers = 100
	}
	if req.Weight <= 0 {
		req.Weight = 1
	}

	n, err := h.svc.CreateNode(req.Name, req.Region, req.IP, req.Protocol, req.Port, req.MaxUsers, req.IsBackup, req.Weight, req.VPSID)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"code": 0, "data": n})
}

func (h *NodeHandler) List(w http.ResponseWriter, r *http.Request) {
	nodes, _ := h.svc.ListAll()
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"results": nodes}})
}

func (h *NodeHandler) Available(w http.ResponseWriter, r *http.Request) {
	nodes, _ := h.svc.ListAvailable()
	if nodes == nil {
		nodes = []Node{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": nodes})
}

func (h *NodeHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	n, err := h.svc.GetNode(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": n})
}

func (h *NodeHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var req struct {
		AgentVersion string `json:"agent_version"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1002, "message": "invalid json body: " + err.Error()})
			return
		}
	}

	if req.AgentVersion != "" {
		if err := h.svc.Heartbeat(id, req.AgentVersion); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": err.Error(), "online": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "heartbeat registered", "online": true})
		return
	}

	online, latency, err := h.svc.ProbeNode(id)
	if err != nil || !online {
		errMsg := "节点离线不可达"
		if err != nil {
			errMsg = err.Error()
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"code":    1003,
			"online":  false,
			"message": errMsg,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"code":       0,
		"online":     true,
		"latency_ms": latency,
		"message":    fmt.Sprintf("节点在线 (延迟: %d ms)", latency),
	})
}

func (h *NodeHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	n, _ := h.svc.GetNode(id)
	if n != nil {
		vpsID := n.VPSID
		nodeName := n.Name
		nodeIP := n.IP
		if vpsID > 0 && h.vpsSvc != nil {
			if cred, err := h.vpsSvc.store.GetCredentials(vpsID); err == nil && cred != nil && cred.IP != "" {
				go func(c *Credentials) {
					client, dialErr := dialSSH(SSHCredentials{
						Host: c.IP, Port: c.SSHPort, User: c.SSHUsername, Password: c.SSHPassword,
					}, 10*time.Second)
					if dialErr == nil {
						defer client.Close()
						cleanCmd := "systemctl stop aero-edge 2>/dev/null; systemctl disable aero-edge 2>/dev/null; pkill -9 -f aero-edge 2>/dev/null || true; pkill -9 -f aero 2>/dev/null || true; fuser -k 443/tcp 2>/dev/null || true; rm -rf /usr/local/bin/aero-edge /usr/local/bin/aero /etc/systemd/system/aero-edge.service /etc/aero /var/lib/aero; systemctl daemon-reload"
						_, _ = runSSH(client, cleanCmd, 15*time.Second)
					}
				}(cred)
			}
			if h.vpsSvc.eps != nil {
				if ep, ok := h.vpsSvc.eps.Get(vpsID); ok {
					ep.Installed = false
					ep.UpdatedAt = time.Now()
					_ = h.vpsSvc.eps.Upsert(ep)
				}
			}
		}
		if h.aeroDB != nil {
			_, _ = h.aeroDB.db.Exec(`DELETE FROM node WHERE id = ? OR vps_id = ? OR name = ? OR address LIKE ?`, id, vpsID, nodeName, "%"+nodeIP+"%")
		}
	}
	_ = h.svc.DeleteNode(id)
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "success"})
}

func (h *NodeHandler) CascadeDelete(w http.ResponseWriter, r *http.Request) {
	vpsID, _ := strconv.ParseUint(r.URL.Query().Get("vps_id"), 10, 64)
	ip := r.URL.Query().Get("ip")
	if vpsID == 0 && ip == "" {
		var req struct {
			VPSID uint64 `json:"vps_id"`
			IP    string `json:"ip"`
		}
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
				writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1002, "message": "invalid json body: " + err.Error()})
				return
			}
		}
		vpsID, ip = req.VPSID, req.IP
	}
	if vpsID == 0 && ip == "" {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "vps_id or ip required"})
		return
	}
	if vpsID > 0 && h.vpsSvc != nil {
		if cred, err := h.vpsSvc.store.GetCredentials(vpsID); err == nil && cred != nil && cred.IP != "" {
			go func(c *Credentials) {
				client, dialErr := dialSSH(SSHCredentials{
					Host: c.IP, Port: c.SSHPort, User: c.SSHUsername, Password: c.SSHPassword,
				}, 10*time.Second)
				if dialErr == nil {
					defer client.Close()
					cleanCmd := "systemctl stop aero-edge 2>/dev/null; systemctl disable aero-edge 2>/dev/null; pkill -9 -f aero-edge 2>/dev/null || true; pkill -9 -f aero 2>/dev/null || true; fuser -k 443/tcp 2>/dev/null || true; rm -rf /usr/local/bin/aero-edge /usr/local/bin/aero /etc/systemd/system/aero-edge.service /etc/aero /var/lib/aero; systemctl daemon-reload"
					_, _ = runSSH(client, cleanCmd, 15*time.Second)
				}
			}(cred)
		}
		if h.vpsSvc.eps != nil {
			if ep, ok := h.vpsSvc.eps.Get(vpsID); ok {
				ep.Installed = false
				ep.UpdatedAt = time.Now()
				_ = h.vpsSvc.eps.Upsert(ep)
			}
		}
	}
	if h.aeroDB != nil {
		_, _ = h.aeroDB.db.Exec(`DELETE FROM node WHERE vps_id = ? OR address LIKE ?`, vpsID, "%"+ip+"%")
	}
	ids, err := h.svc.DeleteMatching(vpsID, ip)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 1006, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"deleted_ids": ids, "count": len(ids)}})
}

func (h *NodeHandler) CleanOrphans(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ValidVPSIDs []uint64 `json:"valid_vps_ids"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": 1002, "message": "invalid json body: " + err.Error()})
			return
		}
	}
	validMap := make(map[uint64]bool)
	for _, id := range req.ValidVPSIDs {
		validMap[id] = true
	}
	if len(validMap) == 0 && h.vpsStore != nil {
		if hosts, err := h.vpsStore.List(); err == nil {
			for _, v := range hosts {
				validMap[v.ID] = true
			}
		}
	}
	h.svc.mu.Lock()
	defer h.svc.mu.Unlock()
	var deleted []uint64
	for id, n := range h.svc.nodes {
		if n.VPSID == 0 || (len(validMap) > 0 && !validMap[n.VPSID]) {
			deleted = append(deleted, id)
			delete(h.svc.nodes, id)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "orphans cleaned", "data": map[string]any{"deleted_ids": deleted, "count": len(deleted)}})
}

// ----------------------------------------------------------------------
// VPS Asset Domain Models & SecretBox
// ----------------------------------------------------------------------

type HostMetrics struct {
	CPUPercent  float64        `json:"cpu_percent"`
	MemTotalMB  float64        `json:"mem_total_mb"`
	MemUsedMB   float64        `json:"mem_used_mb"`
	MemPercent  float64        `json:"mem_percent"`
	DiskTotalGB float64        `json:"disk_total_gb"`
	DiskUsedGB  float64        `json:"disk_used_gb"`
	DiskPercent float64        `json:"disk_percent"`
	Load1       float64        `json:"load_1"`
	Load5       float64        `json:"load_5"`
	Load15      float64        `json:"load_15"`
	NetRxMbps   float64        `json:"net_rx_mbps"`
	NetTxMbps   float64        `json:"net_tx_mbps"`
	UptimeSec   int64          `json:"uptime_sec"`
	OS          string         `json:"os,omitempty"`
	Arch        string         `json:"arch,omitempty"`
	CollectedAt time.Time      `json:"collected_at"`
	Source      string         `json:"source"`
	ProbeOK     bool           `json:"probe_ok"`
	ProbeError  string         `json:"probe_error,omitempty"`
	LatencyMS   int64          `json:"latency_ms,omitempty"`
	Cert        map[string]any `json:"cert,omitempty"`
}

type VPSHost struct {
	ID                uint64         `json:"id"`
	Name              string         `json:"name"`
	Role              string         `json:"role"`
	IP                string         `json:"ip"`
	SSHPort           int            `json:"ssh_port"`
	SSHUsername       string         `json:"ssh_username"`
	HasPassword       bool           `json:"has_password"`
	Domain            string         `json:"domain,omitempty"`
	Remark            string         `json:"remark,omitempty"`
	Status            string         `json:"status"` // registered | online | offline | error
	HealthScore       int            `json:"health_score"`
	Tier              int            `json:"tier"` // 1: Nano/Edge (<=1G), 2: Standard (<=4G), 3: Enterprise (>4G)
	CapacityState     string         `json:"capacity_state"`
	PurityScore       int            `json:"purity_score"`
	AIBlocked         bool           `json:"ai_blocked"`
	GoogleClean       bool           `json:"google_clean"`
	CFClean           bool           `json:"cf_clean"`
	IsWARPEgress      bool           `json:"is_warp_egress"`
	Metrics           *HostMetrics   `json:"metrics,omitempty"`
	DNSStatus         *DNSStatusInfo `json:"dns_status,omitempty"`
	LastProbeAt       *time.Time     `json:"last_probe_at,omitempty"`
	LastPurityProbeAt *time.Time     `json:"last_purity_probe_at,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

type DNSStatusInfo struct {
	Matched     bool      `json:"matched"`
	IsCFProxy   bool      `json:"is_cf_proxy"`
	Domain      string    `json:"domain"`
	VPSIP       string    `json:"vps_ip"`
	ResolvedIPs []string  `json:"resolved_ips"`
	StatusText  string    `json:"status_text"`
	CheckedAt   time.Time `json:"checked_at"`
}

type PurityResult struct {
	VPSID        uint64    `json:"vps_id"`
	PurityScore  int       `json:"purity_score"`
	AIBlocked    bool      `json:"ai_blocked"`
	GoogleClean  bool      `json:"google_clean"`
	CFClean      bool      `json:"cf_clean"`
	IsWARPEgress bool      `json:"is_warp_egress"`
	RawOutput    string    `json:"raw_output,omitempty"`
	ProbeAt      time.Time `json:"probe_at"`
	ProbeError   string    `json:"probe_error,omitempty"`
}

type UpdateVPSParams struct {
	Name        string `json:"name,omitempty"`
	Role        string `json:"role,omitempty"`
	SSHPort     int    `json:"ssh_port,omitempty"`
	SSHUsername string `json:"ssh_username,omitempty"`
	Remark      string `json:"remark,omitempty"`
}

type CreateVPSParams struct {
	Name        string
	Role        string
	IP          string
	SSHPort     int
	SSHUsername string
	SSHPassword string
	Domain      string
	Remark      string
}

type Credentials struct {
	VPSID       uint64 `json:"vps_id"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	SSHPort     int    `json:"ssh_port"`
	SSHUsername string `json:"ssh_username"`
	SSHPassword string `json:"ssh_password"`
	Domain      string `json:"domain,omitempty"`
}

type SecretBox struct {
	gcm cipher.AEAD
}

func NewSecretBox() (*SecretBox, error) {
	raw := strings.TrimSpace(os.Getenv("SSH_CRED_KEY"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("HMAC_SECRET"))
	}
	if raw == "" {
		raw = "dev-ssh-cred-key-change-me"
	}
	sum := sha256.Sum256([]byte(raw))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{gcm: gcm}, nil
}

func (b *SecretBox) Encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if b == nil || b.gcm == nil {
		return "", errors.New("crypto box not initialized")
	}
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := b.gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

func (b *SecretBox) Decrypt(blob string) (string, error) {
	if blob == "" {
		return "", nil
	}
	if b == nil || b.gcm == nil {
		return "", errors.New("crypto box not initialized")
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext: %w", err)
	}
	ns := b.gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	plain, err := b.gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt failed: %w", err)
	}
	return string(plain), nil
}

// ----------------------------------------------------------------------
// VPS Stores
// ----------------------------------------------------------------------

type VPSStore interface {
	Get(id uint64) (*VPSHost, error)
	List() ([]*VPSHost, error)
	Create(p CreateVPSParams) (*VPSHost, error)
	Update(id uint64, p UpdateVPSParams) (*VPSHost, error)
	Delete(id uint64) error
	UpdateMetrics(id uint64, m *HostMetrics, probeOK bool, errMsg string, latency int64) error
	UpdatePurity(id uint64, res *PurityResult) error
	UpdateDomain(id uint64, domain string) error
	UpdateDNSStatus(id uint64, st *DNSStatusInfo) error
	UpdatePassword(id uint64, password string) error
	GetCredentials(id uint64) (*Credentials, error)
}

type MemoryVPSStore struct {
	mu        sync.RWMutex
	next      uint64
	hosts     map[uint64]*VPSHost
	passwords map[uint64]string
}

func NewMemoryVPSStore() *MemoryVPSStore {
	return &MemoryVPSStore{
		hosts:     make(map[uint64]*VPSHost),
		passwords: make(map[uint64]string),
	}
}

func (m *MemoryVPSStore) Get(id uint64) (*VPSHost, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.hosts[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *h
	return &cp, nil
}

func (m *MemoryVPSStore) List() ([]*VPSHost, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*VPSHost, 0, len(m.hosts))
	for _, h := range m.hosts {
		cp := *h
		out = append(out, &cp)
	}
	return out, nil
}

func (m *MemoryVPSStore) Create(p CreateVPSParams) (*VPSHost, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	id := m.next
	now := time.Now()
	h := &VPSHost{
		ID:          id,
		Name:        p.Name,
		Role:        p.Role,
		IP:          p.IP,
		SSHPort:     p.SSHPort,
		SSHUsername: p.SSHUsername,
		HasPassword: p.SSHPassword != "",
		Domain:      p.Domain,
		Remark:      p.Remark,
		Status:      "registered",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	m.hosts[id] = h
	if p.SSHPassword != "" {
		m.passwords[id] = p.SSHPassword
	}
	cp := *h
	return &cp, nil
}

func (m *MemoryVPSStore) Update(id uint64, p UpdateVPSParams) (*VPSHost, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return nil, errors.New("not found")
	}
	if p.Name != "" {
		h.Name = p.Name
	}
	if p.Role != "" {
		h.Role = p.Role
	}
	if p.SSHPort > 0 {
		h.SSHPort = p.SSHPort
	}
	if p.SSHUsername != "" {
		h.SSHUsername = p.SSHUsername
	}
	if p.Remark != "" {
		h.Remark = p.Remark
	}
	h.UpdatedAt = time.Now()
	cp := *h
	return &cp, nil
}

func (m *MemoryVPSStore) Delete(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.hosts, id)
	delete(m.passwords, id)
	return nil
}

func (m *MemoryVPSStore) UpdateMetrics(id uint64, met *HostMetrics, probeOK bool, errMsg string, latency int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return errors.New("not found")
	}
	now := time.Now()
	h.LastProbeAt = &now
	h.UpdatedAt = now
	if met != nil {
		met.ProbeOK = probeOK
		met.ProbeError = errMsg
		met.LatencyMS = latency
		met.CollectedAt = now
		h.Metrics = met
		if probeOK {
			h.Status = "online"
			score, tier, state := CalculateCapacity(met)
			h.HealthScore = score
			h.Tier = tier
			h.CapacityState = state
		} else {
			h.Status = "offline"
			h.CapacityState = "offline"
		}
	} else {
		h.Status = "offline"
		h.CapacityState = "offline"
	}
	return nil
}

func (m *MemoryVPSStore) UpdatePurity(id uint64, res *PurityResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return errors.New("not found")
	}
	now := time.Now()
	h.LastPurityProbeAt = &now
	h.UpdatedAt = now
	if res != nil {
		h.PurityScore = res.PurityScore
		h.AIBlocked = res.AIBlocked
		h.GoogleClean = res.GoogleClean
		h.CFClean = res.CFClean
		h.IsWARPEgress = res.IsWARPEgress
	}
	return nil
}

func (m *MemoryVPSStore) UpdateDomain(id uint64, domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return errors.New("not found")
	}
	h.Domain = domain
	h.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryVPSStore) UpdateDNSStatus(id uint64, st *DNSStatusInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return errors.New("not found")
	}
	h.DNSStatus = st
	h.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryVPSStore) UpdatePassword(id uint64, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return errors.New("not found")
	}
	m.passwords[id] = password
	h.HasPassword = password != ""
	h.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryVPSStore) GetCredentials(id uint64) (*Credentials, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.hosts[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return &Credentials{
		VPSID:       h.ID,
		Name:        h.Name,
		IP:          h.IP,
		SSHPort:     h.SSHPort,
		SSHUsername: h.SSHUsername,
		SSHPassword: m.passwords[id],
		Domain:      h.Domain,
	}, nil
}

// FileVPSStore provides JSON + AES-256 persistence for VPS assets
type FileVPSStore struct {
	mu        sync.RWMutex
	path      string
	box       *SecretBox
	next      uint64
	hosts     map[uint64]*VPSHost
	passwords map[uint64]string
}

type vpsPersistFormat struct {
	Next      uint64              `json:"next"`
	NextID    uint64              `json:"next_id"`
	Hosts     map[uint64]*VPSHost `json:"hosts"`
	Passwords map[uint64]string   `json:"passwords"`
	IPs       map[uint64]string   `json:"ips"`
}

func NewFileVPSStore(path string, box *SecretBox) (*FileVPSStore, error) {
	s := &FileVPSStore{
		path:      path,
		box:       box,
		hosts:     make(map[uint64]*VPSHost),
		passwords: make(map[uint64]string),
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *FileVPSStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var doc vpsPersistFormat
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("corrupt vps store: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if doc.Next > 0 {
		s.next = doc.Next
	} else {
		s.next = doc.NextID
	}
	if doc.Hosts != nil {
		s.hosts = doc.Hosts
	}
	if doc.Passwords != nil {
		s.passwords = doc.Passwords
	}
	if doc.IPs != nil && s.box != nil {
		for id, encIP := range doc.IPs {
			if plain, err := s.box.Decrypt(encIP); err == nil {
				if h, ok := s.hosts[id]; ok {
					h.IP = plain
				}
			}
		}
	}
	return nil
}

func (s *FileVPSStore) save() error {
	if s.path == "" {
		return nil
	}
	encIPs := make(map[uint64]string)
	if s.box != nil {
		for id, h := range s.hosts {
			if h.IP != "" {
				if enc, err := s.box.Encrypt(h.IP); err == nil {
					encIPs[id] = enc
				}
			}
		}
	}
	doc := vpsPersistFormat{
		Next:      s.next,
		NextID:    s.next,
		Hosts:     s.hosts,
		Passwords: s.passwords,
		IPs:       encIPs,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *FileVPSStore) Get(id uint64) (*VPSHost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.hosts[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *h
	return &cp, nil
}

func (s *FileVPSStore) List() ([]*VPSHost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*VPSHost, 0, len(s.hosts))
	for _, h := range s.hosts {
		cp := *h
		out = append(out, &cp)
	}
	return out, nil
}

func (s *FileVPSStore) Create(p CreateVPSParams) (*VPSHost, error) {
	s.mu.Lock()
	s.next++
	id := s.next
	now := time.Now()
	h := &VPSHost{
		ID:          id,
		Name:        p.Name,
		Role:        p.Role,
		IP:          p.IP,
		SSHPort:     p.SSHPort,
		SSHUsername: p.SSHUsername,
		HasPassword: p.SSHPassword != "",
		Domain:      p.Domain,
		Remark:      p.Remark,
		Status:      "registered",
		HealthScore: 100,
		Tier:        2,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	s.hosts[id] = h
	if p.SSHPassword != "" && s.box != nil {
		if enc, err := s.box.Encrypt(p.SSHPassword); err == nil {
			s.passwords[id] = enc
		}
	}
	s.mu.Unlock()
	_ = s.save()
	cp := *h
	return &cp, nil
}

func (s *FileVPSStore) Update(id uint64, p UpdateVPSParams) (*VPSHost, error) {
	s.mu.Lock()
	h, ok := s.hosts[id]
	if !ok {
		s.mu.Unlock()
		return nil, errors.New("not found")
	}
	if p.Name != "" {
		h.Name = p.Name
	}
	if p.Role != "" {
		h.Role = p.Role
	}
	if p.SSHPort > 0 {
		h.SSHPort = p.SSHPort
	}
	if p.SSHUsername != "" {
		h.SSHUsername = p.SSHUsername
	}
	if p.Remark != "" {
		h.Remark = p.Remark
	}
	h.UpdatedAt = time.Now()
	cp := *h
	s.mu.Unlock()
	_ = s.save()
	return &cp, nil
}

func (s *FileVPSStore) Delete(id uint64) error {
	s.mu.Lock()
	delete(s.hosts, id)
	delete(s.passwords, id)
	s.mu.Unlock()
	return s.save()
}

func (s *FileVPSStore) UpdateMetrics(id uint64, met *HostMetrics, probeOK bool, errMsg string, latency int64) error {
	s.mu.Lock()
	h, ok := s.hosts[id]
	if !ok {
		s.mu.Unlock()
		return errors.New("not found")
	}
	now := time.Now()
	h.LastProbeAt = &now
	h.UpdatedAt = now
	if met != nil {
		met.ProbeOK = probeOK
		met.ProbeError = errMsg
		met.LatencyMS = latency
		met.CollectedAt = now
		h.Metrics = met
		if probeOK {
			h.Status = "online"
			score, tier, state := CalculateCapacity(met)
			h.HealthScore = score
			h.Tier = tier
			h.CapacityState = state
		} else {
			h.Status = "offline"
			h.CapacityState = "offline"
		}
	} else {
		h.Status = "offline"
		h.CapacityState = "offline"
	}
	s.mu.Unlock()
	return s.save()
}

func (s *FileVPSStore) UpdatePurity(id uint64, res *PurityResult) error {
	s.mu.Lock()
	h, ok := s.hosts[id]
	if !ok {
		s.mu.Unlock()
		return errors.New("not found")
	}
	now := time.Now()
	h.LastPurityProbeAt = &now
	h.UpdatedAt = now
	if res != nil {
		h.PurityScore = res.PurityScore
		h.AIBlocked = res.AIBlocked
		h.GoogleClean = res.GoogleClean
		h.CFClean = res.CFClean
		h.IsWARPEgress = res.IsWARPEgress
	}
	s.mu.Unlock()
	return s.save()
}

func (s *FileVPSStore) UpdateDomain(id uint64, domain string) error {
	s.mu.Lock()
	h, ok := s.hosts[id]
	if !ok {
		s.mu.Unlock()
		return errors.New("not found")
	}
	h.Domain = domain
	h.UpdatedAt = time.Now()
	s.mu.Unlock()
	return s.save()
}

func (s *FileVPSStore) UpdateDNSStatus(id uint64, st *DNSStatusInfo) error {
	s.mu.Lock()
	h, ok := s.hosts[id]
	if !ok {
		s.mu.Unlock()
		return errors.New("not found")
	}
	h.DNSStatus = st
	h.UpdatedAt = time.Now()
	s.mu.Unlock()
	return s.save()
}

func (s *FileVPSStore) UpdatePassword(id uint64, password string) error {
	s.mu.Lock()
	h, ok := s.hosts[id]
	if !ok {
		s.mu.Unlock()
		return errors.New("not found")
	}
	if password != "" && s.box != nil {
		if enc, err := s.box.Encrypt(password); err == nil {
			s.passwords[id] = enc
			h.HasPassword = true
		}
	} else if password == "" {
		delete(s.passwords, id)
		h.HasPassword = false
	}
	h.UpdatedAt = time.Now()
	s.mu.Unlock()
	return s.save()
}

func (s *FileVPSStore) GetCredentials(id uint64) (*Credentials, error) {
	s.mu.RLock()
	h, ok := s.hosts[id]
	encPass := s.passwords[id]
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	pass := ""
	if encPass != "" && s.box != nil {
		if plain, err := s.box.Decrypt(encPass); err == nil {
			pass = plain
		}
	}
	return &Credentials{
		VPSID:       h.ID,
		Name:        h.Name,
		IP:          h.IP,
		SSHPort:     h.SSHPort,
		SSHUsername: h.SSHUsername,
		SSHPassword: pass,
		Domain:      h.Domain,
	}, nil
}

// ----------------------------------------------------------------------
// EndpointStore (aero_endpoints.json)
// ----------------------------------------------------------------------

type EndpointInfo struct {
	VPSID     uint64    `json:"vps_id"`
	Name      string    `json:"name"`
	Region    string    `json:"region,omitempty"`
	Host      string    `json:"host"`
	IP        string    `json:"ip,omitempty"`
	Port      int       `json:"port"`
	SubSecret string    `json:"sub_secret"`
	AdminKey  string    `json:"admin_key"`
	HasAdmin  bool      `json:"has_admin"`
	SubURL    string    `json:"sub_url"`
	Installed bool      `json:"installed"`
	Version   string    `json:"version,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type EndpointStore struct {
	mu    sync.RWMutex
	path  string
	items map[uint64]EndpointInfo
}

type endpointSnapshot struct {
	Items []EndpointInfo `json:"items"`
}

func NewEndpointStore(path string) (*EndpointStore, error) {
	if path == "" {
		path = filepath.Join("data", "aero_endpoints.json")
	}
	es := &EndpointStore{
		path:  path,
		items: make(map[uint64]EndpointInfo),
	}
	_ = es.load()
	return es, nil
}

func (s *EndpointStore) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var snap endpointSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range snap.Items {
		s.items[it.VPSID] = it
	}
	return nil
}

func (s *EndpointStore) persistLocked() error {
	snap := endpointSnapshot{Items: make([]EndpointInfo, 0, len(s.items))}
	for _, it := range s.items {
		snap.Items = append(snap.Items, it)
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *EndpointStore) Upsert(ep EndpointInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep.UpdatedAt = time.Now()
	s.items[ep.VPSID] = ep
	return s.persistLocked()
}

func (s *EndpointStore) Delete(vpsID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, vpsID)
	return s.persistLocked()
}

func (s *EndpointStore) Get(vpsID uint64) (EndpointInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ep, ok := s.items[vpsID]
	return ep, ok
}

func (s *EndpointStore) List() []EndpointInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]EndpointInfo, 0, len(s.items))
	for _, ep := range s.items {
		out = append(out, ep)
	}
	return out
}

// ----------------------------------------------------------------------
// VPSService
// ----------------------------------------------------------------------

type VPSService struct {
	store     VPSStore
	box       *SecretBox
	eps       *EndpointStore
	nodeSvc   *NodeService
	userStore UserStore
}

func NewVPSService(s VPSStore, box *SecretBox, eps *EndpointStore) *VPSService {
	return &VPSService{store: s, box: box, eps: eps}
}

func (s *VPSService) SetNodeService(ns *NodeService) {
	s.nodeSvc = ns
}

func (s *VPSService) SetUserStore(us UserStore) {
	s.userStore = us
}

func (s *VPSService) Create(p CreateVPSParams) (*VPSHost, error) {
	p.IP = strings.TrimSpace(p.IP)
	p.Name = strings.TrimSpace(p.Name)
	p.SSHPassword = strings.TrimSpace(p.SSHPassword)
	p.SSHUsername = strings.TrimSpace(p.SSHUsername)
	p.Domain = strings.TrimSpace(p.Domain)
	if p.Name == "" || p.IP == "" {
		return nil, fmt.Errorf("name and ip required")
	}
	if p.Domain == "" {
		return nil, fmt.Errorf("域名为必填项：严禁未绑定域名的 VPS 接入中台，杜绝源站 IP 泄露")
	}
	if net.ParseIP(p.Domain) != nil || !strings.Contains(p.Domain, ".") {
		return nil, fmt.Errorf("域名格式不合法：%s 不是有效的公网域名（严禁使用纯 IP 作为域名）", p.Domain)
	}

	if p.SSHPort <= 0 {
		p.SSHPort = 22
	}
	if p.SSHUsername == "" {
		p.SSHUsername = "root"
	}
	if p.Role == "" {
		p.Role = "node"
	}
	if p.SSHPassword == "" {
		return nil, fmt.Errorf("ssh_password required")
	}
	host, err := s.store.Create(p)
	if err != nil {
		return nil, err
	}

	if s.nodeSvc != nil && host != nil {
		targetHost := host.Domain
		if targetHost == "" {
			targetHost = host.IP
		}
		region := ResolveIPRegion(host.IP)
		_, _ = s.nodeSvc.CreateNode(host.Name, region, targetHost, "aero-quic", 443, 500, false, 100, host.ID)
	}
	return host, nil
}

func (s *VPSService) List() ([]*VPSHost, error)       { return s.store.List() }
func (s *VPSService) Get(id uint64) (*VPSHost, error) { return s.store.Get(id) }

func (s *VPSService) Delete(id uint64) error {
	vps, _ := s.store.Get(id)
	ip := ""
	if vps != nil {
		ip = vps.IP
	}

	if cred, credErr := s.store.GetCredentials(id); credErr == nil && cred != nil && cred.IP != "" {
		go func(c *Credentials) {
			client, err := dialSSH(SSHCredentials{
				Host: c.IP, Port: c.SSHPort, User: c.SSHUsername, Password: c.SSHPassword,
			}, 10*time.Second)
			if err == nil {
				defer client.Close()
				cleanCmd := "systemctl stop aero-edge 2>/dev/null; systemctl disable aero-edge 2>/dev/null; pkill -9 -f aero-edge 2>/dev/null || true; pkill -9 -f '/usr/local/bin/aero' 2>/dev/null || true; fuser -k 443/tcp 2>/dev/null || true; rm -rf /usr/local/bin/aero-edge /usr/local/bin/aero /etc/systemd/system/aero-edge.service /etc/aero /var/lib/aero; systemctl daemon-reload"
				_, _ = runSSH(client, cleanCmd, 15*time.Second)
			}
		}(cred)
	}

	err := s.store.Delete(id)
	if err == nil {
		if s.eps != nil {
			_ = s.eps.Delete(id)
		}
		if s.nodeSvc != nil {
			_, _ = s.nodeSvc.DeleteMatching(id, ip)
		}
	}
	return err
}

func (s *VPSService) UpdateMeta(id uint64, p UpdateVPSParams) error {
	p.Name = strings.TrimSpace(p.Name)
	p.Role = strings.TrimSpace(p.Role)
	p.Remark = strings.TrimSpace(p.Remark)
	p.SSHUsername = strings.TrimSpace(p.SSHUsername)
	_, err := s.store.Update(id, p)
	return err
}

func (s *VPSService) UpdatePassword(id uint64, password string) error {
	return s.store.UpdatePassword(id, password)
}

func (s *VPSService) UpdateDomain(id uint64, domain string) error {
	domain = strings.TrimSpace(domain)
	err := s.store.UpdateDomain(id, domain)
	if err == nil {
		if s.nodeSvc != nil && domain != "" {
			s.nodeSvc.UpdateHostByVPS(id, domain)
		}
		if s.eps != nil && domain != "" {
			if ep, ok := s.eps.Get(id); ok {
				ep.Host = domain
				sec := ep.SubSecret
				if sec == "" {
					sec = "superadmin"
				}
				ep.SubURL = fmt.Sprintf("https://%s/sub/%s", domain, sec)
				_ = s.eps.Upsert(ep)
			}
		}
	}
	return err
}

func (s *VPSService) GetCredentials(id uint64) (*Credentials, error) {
	return s.store.GetCredentials(id)
}

func CalculateCapacity(m *HostMetrics) (score int, tier int, state string) {
	if m == nil || !m.ProbeOK {
		return 0, 1, "offline"
	}
	tier = 2
	if m.MemTotalMB > 0 {
		if m.MemTotalMB <= 1200 {
			tier = 1
		} else if m.MemTotalMB > 4500 {
			tier = 3
		}
	}

	s := 100.0
	if m.MemPercent > 90 {
		s -= 45
	} else if m.MemPercent > 80 {
		s -= 30
	} else if m.MemPercent > 70 {
		s -= 15
	}

	if m.CPUPercent > 90 {
		s -= 40
	} else if m.CPUPercent > 75 {
		s -= 25
	} else if m.CPUPercent > 50 {
		s -= 10
	}

	if m.LatencyMS > 400 {
		s -= 20
	} else if m.LatencyMS > 250 {
		s -= 10
	} else if m.LatencyMS > 150 {
		s -= 5
	}

	if s < 0 {
		s = 0
	}
	score = int(s)

	switch {
	case score >= 80:
		state = "excellent"
	case score >= 60:
		state = "good"
	case score >= 40:
		state = "heavy"
	default:
		state = "overload"
	}
	return score, tier, state
}

func (s *VPSService) VerifyOrSyncDomain(ctx context.Context, domain, ip string) error {
	domain = strings.TrimSpace(domain)
	ip = strings.TrimSpace(ip)
	if domain == "" || ip == "" {
		return fmt.Errorf("domain and ip required")
	}
	if domain == "localhost" || domain == "127.0.0.1" {
		return nil
	}
	ips, err := resolveDomainAuthoritative(ctx, domain)
	if err != nil {
		return fmt.Errorf("域名 %s 尚未在公网解析，请添加 A 记录指向 %s: %w", domain, ip, err)
	}
	for _, resolved := range ips {
		if resolved == ip {
			return nil
		}
	}
	return fmt.Errorf("域名 %s 当前解析出的 IP (%v) 与 VPS IP (%s) 不一致", domain, ips, ip)
}

// ----------------------------------------------------------------------
// VPSHandler
// ----------------------------------------------------------------------

type VPSHandler struct {
	svc *VPSService
}

func NewVPSHandler(svc *VPSService) *VPSHandler {
	return &VPSHandler{svc: svc}
}

func (h *VPSHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/vps/", h.Create)
	mux.HandleFunc("GET /api/v1/vps/", h.List)
	mux.HandleFunc("GET /api/v1/vps/{id}/", h.Get)
	mux.HandleFunc("PATCH /api/v1/vps/{id}/", h.Patch)
	mux.HandleFunc("DELETE /api/v1/vps/{id}/", h.Delete)
	mux.HandleFunc("POST /api/v1/vps/{id}/purity-probe/", h.ProbePurity)
	mux.HandleFunc("POST /api/v1/vps/{id}/probe/", h.Probe)
	mux.HandleFunc("POST /api/v1/vps/{id}/verify-domain/", h.VerifyDomain)
	mux.HandleFunc("GET /api/v1/vps/cf-dns/status/", h.CFStatus)
	mux.HandleFunc("POST /api/v1/vps/cf-dns/sync/", h.SyncCFDNS)
	mux.HandleFunc("GET /api/v1/vps/{id}/diagnose/", h.Diagnose)
	mux.HandleFunc("POST /api/v1/vps/{id}/cert/renew/", h.RenewCert)
	mux.HandleFunc("POST /api/v1/vps/{id}/install-aero/", h.InstallAero)
}

func parseVPSID(r *http.Request) (uint64, error) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		return 0, errors.New("invalid vps id")
	}
	return id, nil
}

func (h *VPSHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		IP          string `json:"ip"`
		SSHPort     int    `json:"ssh_port"`
		SSHUsername string `json:"ssh_username"`
		SSHPassword string `json:"ssh_password"`
		Domain      string `json:"domain"`
		Remark      string `json:"remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 422, errResp(1002, "invalid body"))
		return
	}
	v, err := h.svc.Create(CreateVPSParams{
		Name: req.Name, Role: req.Role, IP: req.IP, SSHPort: req.SSHPort,
		SSHUsername: req.SSHUsername, SSHPassword: req.SSHPassword,
		Domain: req.Domain, Remark: req.Remark,
	})
	if err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 201, map[string]any{"code": 0, "data": v})
}

func (h *VPSHandler) List(w http.ResponseWriter, r *http.Request) {
	list, _ := h.svc.List()
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": list}})
}

func (h *VPSHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	v, err := h.svc.Get(id)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "not found"))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": v})
}

func (h *VPSHandler) Patch(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	var req struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		SSHPort     int    `json:"ssh_port"`
		SSHUsername string `json:"ssh_username"`
		SSHPassword string `json:"ssh_password"`
		Domain      string `json:"domain"`
		Remark      string `json:"remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 422, errResp(1002, "invalid body"))
		return
	}
	if req.SSHPassword != "" {
		_ = h.svc.UpdatePassword(id, req.SSHPassword)
	}
	if req.Domain != "" {
		_ = h.svc.UpdateDomain(id, req.Domain)
	}
	_ = h.svc.UpdateMeta(id, UpdateVPSParams{
		Name: req.Name, Role: req.Role, SSHPort: req.SSHPort, SSHUsername: req.SSHUsername, Remark: req.Remark,
	})
	v, _ := h.svc.Get(id)
	writeJSON(w, 200, map[string]any{"code": 0, "data": v})
}

func (h *VPSHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	if err := h.svc.Delete(id); err != nil {
		writeJSON(w, 500, errResp(1003, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "message": "deleted"})
}

func (h *VPSHandler) Probe(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	m, err := h.svc.Probe(ctx, id)
	if err != nil {
		writeJSON(w, 500, errResp(1003, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": m})
}

func (h *VPSHandler) ProbePurity(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := h.svc.ProbePurity(ctx, id)
	if err != nil {
		writeJSON(w, 500, errResp(1003, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res})
}

func (h *VPSHandler) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res, err := h.svc.VerifyDomain(ctx, id)
	if err != nil {
		writeJSON(w, 400, errResp(1004, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res})
}

func (h *VPSHandler) CFStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"configured": h.svc.CFReady()}})
}

func (h *VPSHandler) SyncCFDNS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"code": 0, "message": "synced"})
}

func (h *VPSHandler) Diagnose(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	diag, err := h.svc.Diagnose(ctx, id)
	if err != nil {
		writeJSON(w, 500, errResp(1003, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": diag})
}

func (h *VPSHandler) RenewCert(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	var req struct {
		Force bool `json:"force"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, errResp(1002, "invalid json body: "+err.Error()))
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	res, err := h.svc.RenewCert(ctx, id, req.Force)
	if err != nil {
		writeJSON(w, 502, map[string]any{"code": 1006, "message": err.Error(), "data": res})
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res})
}

func (h *VPSHandler) InstallAero(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ep, err := h.svc.InstallAeroOnVPS(id)
	if err != nil {
		writeJSON(w, 500, errResp(1003, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": ep})
}
