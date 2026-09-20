// Copyright 2025 AERO Protocol Contributors
// Plan.md Phase 2: 平铺无子包运营中台 — 套餐与订阅计费引擎
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// BillingPlan defines a subscription plan.
type BillingPlan struct {
	ID             int32     `json:"id"`
	Name           string    `json:"name"`
	DurationMonths int32     `json:"duration_months"`
	TrafficBytes   int64     `json:"traffic_bytes"`
	PriceCents     int64     `json:"price_cents"`
	Status         bool      `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

type BillingService struct {
	mu     sync.RWMutex
	plans  map[int32]*BillingPlan
	nextID int32
}

func NewBillingService() *BillingService {
	svc := &BillingService{
		plans:  make(map[int32]*BillingPlan),
		nextID: 1,
	}
	now := time.Now()
	defaults := []BillingPlan{
		{ID: 1, Name: "月度套餐", DurationMonths: 1, TrafficBytes: 100 * 1024 * 1024 * 1024, PriceCents: 999, Status: true, CreatedAt: now},
		{ID: 2, Name: "季度套餐", DurationMonths: 3, TrafficBytes: 300 * 1024 * 1024 * 1024, PriceCents: 2499, Status: true, CreatedAt: now},
		{ID: 3, Name: "年度套餐", DurationMonths: 12, TrafficBytes: 1200 * 1024 * 1024 * 1024, PriceCents: 7999, Status: true, CreatedAt: now},
	}
	for _, p := range defaults {
		cp := p
		svc.plans[p.ID] = &cp
		if p.ID >= svc.nextID {
			svc.nextID = p.ID + 1
		}
	}
	return svc
}

func (s *BillingService) CreatePlan(name string, months int32, bytes, price int64) (*BillingPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &BillingPlan{
		ID:             s.nextID,
		Name:           name,
		DurationMonths: months,
		TrafficBytes:   bytes,
		PriceCents:     price,
		Status:         true,
		CreatedAt:      time.Now(),
	}
	s.nextID++
	s.plans[p.ID] = p
	return p, nil
}

func (s *BillingService) GetPlan(id int32) (*BillingPlan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.plans[id]; ok {
		cp := *p
		return &cp, nil
	}
	return nil, errors.New("plan not found")
}

func (s *BillingService) ListPlans(activeOnly bool) ([]BillingPlan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var res []BillingPlan
	for _, p := range s.plans {
		if !activeOnly || p.Status {
			res = append(res, *p)
		}
	}
	return res, nil
}

func (s *BillingService) UpdatePlan(id int32, price *int64, status *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.plans[id]
	if !ok {
		return errors.New("plan not found")
	}
	if price != nil {
		p.PriceCents = *price
	}
	if status != nil {
		p.Status = *status
	}
	return nil
}

type BillingHandler struct {
	svc *BillingService
}

func NewBillingHandler(svc *BillingService) *BillingHandler {
	return &BillingHandler{svc: svc}
}

func (h *BillingHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/plans/", h.List)
	mux.HandleFunc("POST /api/v1/plans/", h.Create)
	mux.HandleFunc("GET /api/v1/plans/{id}/", h.Get)
	mux.HandleFunc("PATCH /api/v1/plans/{id}/", h.Update)
}

func (h *BillingHandler) List(w http.ResponseWriter, r *http.Request) {
	plans, _ := h.svc.ListPlans(true)
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"results": plans}})
}

func (h *BillingHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		Months     int32  `json:"duration_months"`
		Traffic    int64  `json:"traffic_bytes"`
		PriceCents int64  `json:"price_cents"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "invalid body"})
		return
	}
	p, err := h.svc.CreatePlan(req.Name, req.Months, req.Traffic, req.PriceCents)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"code": 0, "data": p})
}

func (h *BillingHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	p, err := h.svc.GetPlan(int32(id))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": p})
}

func (h *BillingHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var req struct {
		Price  *int64 `json:"price_cents"`
		Status *bool  `json:"status"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	_ = h.svc.UpdatePlan(int32(id), req.Price, req.Status)
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "success"})
}
