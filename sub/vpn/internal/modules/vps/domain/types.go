package domain

import "time"

// HostMetrics is a resource snapshot from SSH probe (cluster capacity only).
type HostMetrics struct {
	CPUPercent  float64   `json:"cpu_percent"`
	MemTotalMB  float64   `json:"mem_total_mb"`
	MemUsedMB   float64   `json:"mem_used_mb"`
	MemPercent  float64   `json:"mem_percent"`
	DiskTotalGB float64   `json:"disk_total_gb"`
	DiskUsedGB  float64   `json:"disk_used_gb"`
	DiskPercent float64   `json:"disk_percent"`
	Load1       float64   `json:"load_1"`
	Load5       float64   `json:"load_5"`
	Load15      float64   `json:"load_15"`
	NetRxMbps   float64   `json:"net_rx_mbps"`
	NetTxMbps   float64   `json:"net_tx_mbps"`
	UptimeSec   int64     `json:"uptime_sec"`
	OS          string    `json:"os,omitempty"`
	Arch        string    `json:"arch,omitempty"`
	CollectedAt time.Time `json:"collected_at"`
	Source      string    `json:"source"`
	ProbeOK     bool      `json:"probe_ok"`
	ProbeError  string    `json:"probe_error,omitempty"`
	LatencyMS   int64     `json:"latency_ms,omitempty"`
}

// VPSHost is a machine asset. No AERO install state here.
type VPSHost struct {
	ID          uint64       `json:"id"`
	Name        string       `json:"name"`
	Role        string       `json:"role"`
	IP          string       `json:"ip"`
	SSHPort     int          `json:"ssh_port"`
	SSHUsername string       `json:"ssh_username"`
	HasPassword bool         `json:"has_password"`
	Domain      string       `json:"domain,omitempty"`
	Remark      string       `json:"remark,omitempty"`
	Status            string       `json:"status"` // registered | online | offline | error
	HealthScore       int          `json:"health_score"`            // 0~100 综合健康与承载评分
	Tier              int          `json:"tier"`                    // 1: Nano/Edge (<=1G), 2: Standard (<=4G), 3: Enterprise (>4G)
	CapacityState     string       `json:"capacity_state"`          // excellent | good | heavy | overload | unknown
	PurityScore       int          `json:"purity_score"`            // 0~100 出口纯净度软评分 (Google 60 + CF 40)
	AIBlocked         bool         `json:"ai_blocked"`              // 遭遇 AI 封禁一票否决 (剥夺 Tier 1 资格)
	GoogleClean       bool         `json:"google_clean"`            // Google 搜索打靶正常 (无 429/验证码)
	CFClean           bool         `json:"cf_clean"`                // Cloudflare 探活正常 (无人机验证)
	IsWARPEgress      bool         `json:"is_warp_egress"`          // 是否启用了 WARP 出口清洗
	Metrics           *HostMetrics `json:"metrics,omitempty"`
	LastProbeAt       *time.Time   `json:"last_probe_at,omitempty"`
	LastPurityProbeAt *time.Time   `json:"last_purity_probe_at,omitempty"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

// PurityResult 目标 VPS 出口纯净度远程打靶快照
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

// UpdateVPSParams defines mutable metadata for VPS management Web.
type UpdateVPSParams struct {
	Name        string `json:"name,omitempty"`
	Role        string `json:"role,omitempty"`
	SSHPort     int    `json:"ssh_port,omitempty"`
	SSHUsername string `json:"ssh_username,omitempty"`
	Remark      string `json:"remark,omitempty"`
}

// CreateVPSParams registration input.
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

// Credentials is SSH material for trusted callers (iface.VPSProvider / optional internal HTTP).
type Credentials struct {
	VPSID       uint64 `json:"vps_id"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	SSHPort     int    `json:"ssh_port"`
	SSHUsername string `json:"ssh_username"`
	SSHPassword string `json:"ssh_password"`
	Domain      string `json:"domain,omitempty"`
}
