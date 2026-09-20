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
		Remark      string `json:"remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 422, errResp(1002, "invalid body"))
		return
	}
	if err := h.svc.UpdateMeta(id, UpdateVPSParams{
		Name: req.Name, Role: req.Role, SSHPort: req.SSHPort,
		SSHUsername: req.SSHUsername, Remark: req.Remark,
	}); err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
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
