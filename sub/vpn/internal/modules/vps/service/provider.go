package service

import (
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/iface"
)

// ProviderAdapter exposes the VPS module as iface.VPSProvider for AERO package jobs.
// Coupling is only this interface — aero never imports VPS domain types for SSH secrets.
type ProviderAdapter struct {
	svc *Service
}

func NewProvider(svc *Service) *ProviderAdapter {
	return &ProviderAdapter{svc: svc}
}

var _ iface.VPSProvider = (*ProviderAdapter)(nil)

func (a *ProviderAdapter) Credentials(vpsID uint64) (*iface.Cred, error) {
	c, err := a.svc.Credentials(vpsID)
	if err != nil {
		return nil, err
	}
	return &iface.Cred{
		VPSID: c.VPSID, Name: c.Name, IP: c.IP, SSHPort: c.SSHPort,
		SSHUsername: c.SSHUsername, SSHPassword: c.SSHPassword, Domain: c.Domain,
	}, nil
}

func (a *ProviderAdapter) ListOptions() ([]iface.Option, error) {
	list, err := a.svc.List()
	if err != nil {
		return nil, err
	}
	out := make([]iface.Option, 0, len(list))
	for _, h := range list {
		out = append(out, iface.Option{
			ID: h.ID, Name: h.Name, IP: h.IP, Domain: h.Domain, Status: h.Status,
		})
	}
	return out, nil
}
