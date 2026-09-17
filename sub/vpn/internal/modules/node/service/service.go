package service

import (
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/node/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/node/store"
)

type Service struct{ s store.Store }

func New(s store.Store) *Service { return &Service{s: s} }

func (svc *Service) CreateNode(name, region, ip, protocol string, port, max int32, backup bool, weight int32, vpsID uint64) (*domain.Node, error) {
	n := &domain.Node{
		Name: name, Region: region, IP: ip, Protocol: protocol,
		Port: port, MaxUsers: max, IsBackup: backup, Weight: weight,
		VPSID: vpsID, Status: true,
	}
	_, err := svc.s.Create(n)
	return n, err
}

func (svc *Service) GetNode(id uint64) (*domain.Node, error)  { return svc.s.Get(id) }
func (svc *Service) ListAll() ([]domain.Node, error)          { return svc.s.ListAll() }
func (svc *Service) ListAvailable() ([]domain.Node, error)    { return svc.s.ListAvailable() }
func (svc *Service) Heartbeat(id uint64, version string) error {
	return svc.s.UpdateStatus(id, true, version)
}
func (svc *Service) MarkOffline(id uint64) error { return svc.s.UpdateStatus(id, false, "") }
func (svc *Service) DeleteNode(id uint64) error  { return svc.s.Delete(id) }

// DeleteMatching removes all nodes for a VPS id and/or IP (cascade from VPS lifecycle).
func (svc *Service) DeleteMatching(vpsID uint64, ip string) ([]uint64, error) {
	return svc.s.DeleteMatching(vpsID, ip)
}
