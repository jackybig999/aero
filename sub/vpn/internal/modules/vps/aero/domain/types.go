package domain

import "time"

// HostMetrics used by sshprobe package (metrics during install are optional).
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

// DeployStep is one phase of install/uninstall.
type DeployStep struct {
	Key     string     `json:"key"`
	Title   string     `json:"title"`
	Status  string     `json:"status"`
	Detail  string     `json:"detail,omitempty"`
	Started *time.Time `json:"started_at,omitempty"`
	Ended   *time.Time `json:"ended_at,omitempty"`
}

// DeployTask tracks AERO package jobs only.
type DeployTask struct {
	ID          uint64       `json:"id"`
	Kind        string       `json:"kind"` // install | uninstall
	VPSID       uint64       `json:"vps_id"`
	VPSName     string       `json:"vps_name,omitempty"`
	Status      string       `json:"status"`
	Stage       string       `json:"stage,omitempty"`
	Progress    int          `json:"progress"`
	AeroVersion string       `json:"aero_version,omitempty"`
	Steps       []DeployStep `json:"steps"`
	Logs        []string     `json:"logs"`
	Error       string       `json:"error,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	FinishedAt  *time.Time   `json:"finished_at,omitempty"`
}
