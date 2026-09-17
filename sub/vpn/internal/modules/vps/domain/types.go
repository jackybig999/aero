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
	Status      string       `json:"status"` // registered | online | offline | error
	Metrics     *HostMetrics `json:"metrics,omitempty"`
	LastProbeAt *time.Time   `json:"last_probe_at,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
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
