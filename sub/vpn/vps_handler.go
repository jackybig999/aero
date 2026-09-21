// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// VPSHandler exposes VPS management endpoints.
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
		if err := h.svc.UpdatePassword(id, req.SSHPassword); err != nil {
			writeJSON(w, 422, errResp(1002, err.Error()))
			return
		}
	}
	if req.Domain != "" {
		if err := h.svc.UpdateDomain(id, req.Domain); err != nil {
			writeJSON(w, 422, errResp(1002, err.Error()))
			return
		}
	}
	if req.Name != "" || req.Role != "" || req.SSHPort > 0 || req.SSHUsername != "" || req.Remark != "" {
		if err := h.svc.UpdateMeta(id, UpdateVPSParams{
			Name: req.Name, Role: req.Role, SSHPort: req.SSHPort,
			SSHUsername: req.SSHUsername, Remark: req.Remark,
		}); err != nil {
			writeJSON(w, 422, errResp(1002, err.Error()))
			return
		}
	}
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
		writeJSON(w, 404, errResp(1001, err.Error()))
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
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	met, err := h.svc.Probe(ctx, id)
	_, _ = h.svc.ProbePurity(ctx, id)
	v, _ := h.svc.Get(id)
	ok := met != nil && met.ProbeOK
	if err != nil && met == nil {
		writeJSON(w, 500, errResp(1003, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"metrics": met, "vps": v, "ok": ok}})
}

func (h *VPSHandler) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := h.svc.VerifyDomain(ctx, id)
	if err != nil {
		writeJSON(w, 422, map[string]any{"code": 1002, "message": err.Error(), "data": res})
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res})
}

func (h *VPSHandler) CFStatus(w http.ResponseWriter, r *http.Request) {
	ready := h.svc.CFReady()
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"ready": ready}})
}

func (h *VPSHandler) SyncCFDNS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := h.svc.SyncCFDNS(ctx, req.Domain, req.IP)
	if err != nil {
		writeJSON(w, 422, map[string]any{"code": 1002, "message": err.Error(), "data": res})
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res})
}

func (h *VPSHandler) Diagnose(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	diag, err := h.svc.Diagnose(ctx, id)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
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
	_ = json.NewDecoder(r.Body).Decode(&req)
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	res, err := h.svc.RenewCert(ctx, id, req.Force)
	if err != nil {
		writeJSON(w, 502, map[string]any{"code": 1006, "message": err.Error(), "data": res})
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res})
}

func (h *VPSHandler) ProbePurity(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	res, err := h.svc.ProbePurity(ctx, id)
	if err != nil {
		writeJSON(w, 500, errResp(1003, err.Error()))
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
