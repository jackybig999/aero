package service

import (
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/billing/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/billing/store"
)

type Service struct{ s store.Store }

func New(s store.Store) *Service { return &Service{s: s} }

func (svc *Service) CreatePlan(name string, months int32, bytes, price int64) (*domain.Plan, error) {
	p := &domain.Plan{Name: name, DurationMonths: months, TrafficBytes: bytes, PriceCents: price}
	_, err := svc.s.CreatePlan(p)
	return p, err
}

func (svc *Service) GetPlan(id int32) (*domain.Plan, error)         { return svc.s.GetPlan(id) }
func (svc *Service) ListPlans(activeOnly bool) ([]domain.Plan, error) { return svc.s.ListPlans(activeOnly) }
func (svc *Service) UpdatePlan(id int32, price *int64, status *bool) error {
	return svc.s.UpdatePlan(id, price, status)
}
