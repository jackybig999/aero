// Package iface is the only coupling point between VPS assets and AERO package jobs.
// Implemented by vps-manager/service; consumed by vps-manager/aero/service.
package iface

// Cred is SSH material for a VPS (never exposed on public JSON of AERO handlers).
type Cred struct {
	VPSID       uint64
	Name        string
	IP          string
	SSHPort     int
	SSHUsername string
	SSHPassword string
	Domain      string
}

// Option is a VPS picker row for AERO UI.
type Option struct {
	ID     uint64 `json:"id"`
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Domain string `json:"domain,omitempty"`
	Status string `json:"status"`
}

// VPSProvider is provided by the VPS module (in-process, not HTTP).
type VPSProvider interface {
	Credentials(vpsID uint64) (*Cred, error)
	ListOptions() ([]Option, error)
}
