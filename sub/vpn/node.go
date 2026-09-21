// Copyright 2025 AERO Protocol Contributors
// Plan.md Phase 2: 平铺无子包运营中台 — 节点分发与心跳健康巡检
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Node represents an active proxy or edge delivery node.
type Node struct {
	ID            uint64     `json:"id"`
	VPSID         uint64     `json:"vps_id"`
	Name          string     `json:"name"`
	Region        string     `json:"region"`
	IP            string     `json:"ip"`
	Port          int32      `json:"port"`
	Protocol      string     `json:"protocol"`
	Status        bool       `json:"status"`
	MaxUsers      int32      `json:"max_users"`
	CurrentUsers  int32      `json:"current_users"`
	IsBackup      bool       `json:"is_backup"`
	Weight        int32      `json:"weight"`
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
		Port:         port,
		Protocol:     protocol,
		Status:       true,
		MaxUsers:     max,
		CurrentUsers: 0,
		IsBackup:     backup,
		Weight:       weight,
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []Node
	for _, n := range s.nodes {
		list = append(list, *n)
	}
	return list, nil
}

func (s *NodeService) ListAvailable() ([]Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []Node
	for _, n := range s.nodes {
		if n.Status {
			list = append(list, *n)
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

type NodeHandler struct {
	svc *NodeService
}

func NewNodeHandler(svc *NodeService) *NodeHandler {
	return &NodeHandler{svc: svc}
}

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
	_ = json.NewDecoder(r.Body).Decode(&req)
	_ = h.svc.Heartbeat(id, req.AgentVersion)
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "success"})
}

func (h *NodeHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
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
		_ = json.NewDecoder(r.Body).Decode(&req)
		vpsID, ip = req.VPSID, req.IP
	}
	if vpsID == 0 && ip == "" {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "vps_id or ip required"})
		return
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
	_ = json.NewDecoder(r.Body).Decode(&req)
	validMap := make(map[uint64]bool)
	for _, id := range req.ValidVPSIDs {
		validMap[id] = true
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

