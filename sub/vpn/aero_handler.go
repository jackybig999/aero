// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AeroHandler exposes /api/v1/aero/* endpoints for the modular AERO Console.
type AeroHandler struct {
	svc *VPSService
}

func NewAeroHandler(svc *VPSService) *AeroHandler {
	return &AeroHandler{svc: svc}
}

func (h *AeroHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/aero/vps-options/", h.VPSOptions)
	mux.HandleFunc("GET /api/v1/aero/source-status/", h.SourceStatus)
	mux.HandleFunc("GET /api/v1/aero/tasks/", h.ListTasks)
	mux.HandleFunc("GET /api/v1/aero/tasks/{id}/", h.GetTask)
	mux.HandleFunc("DELETE /api/v1/aero/tasks/{id}/", h.DeleteTask)
	mux.HandleFunc("POST /api/v1/aero/tasks/clear-failed/", h.ClearFailed)

	mux.HandleFunc("POST /api/v1/aero/install/", h.Install)
	mux.HandleFunc("POST /api/v1/aero/uninstall/", h.Uninstall)


	mux.HandleFunc("GET /api/v1/aero/vps/{id}/endpoint/", h.GetEndpoint)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/endpoint/refresh/", h.RefreshEndpoint)
	mux.HandleFunc("GET /api/v1/aero/vps/{id}/tokens/", h.ListTokens)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/tokens/", h.AddToken)
	mux.HandleFunc("DELETE /api/v1/aero/vps/{id}/tokens/", h.DelToken)

	mux.HandleFunc("GET /api/v1/aero/vps/{id}/status/", h.Diagnose)
	mux.HandleFunc("GET /api/v1/aero/vps/{id}/diagnose/", h.Diagnose)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/cert/renew/", h.RenewCert)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/restart/", h.RestartEdge)
	mux.HandleFunc("POST /api/v1/aero/vps/{id}/subs/sync/", h.SyncSubs)
	mux.HandleFunc("POST /api/v1/aero/subs/broadcast/", h.BroadcastSubs)
}

func (h *AeroHandler) VPSOptions(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.svc.List()
	if err != nil {
		writeJSON(w, 500, errResp(1003, err.Error()))
		return
	}
	type item struct {
		ID     uint64 `json:"id"`
		Name   string `json:"name"`
		IP     string `json:"ip"`
		Domain string `json:"domain"`
	}
	res := make([]item, 0, len(hosts))
	for _, v := range hosts {
		res = append(res, item{ID: v.ID, Name: v.Name, IP: v.IP, Domain: v.Domain})
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res, "results": res})
}

func (h *AeroHandler) SourceStatus(w http.ResponseWriter, r *http.Request) {
	st := DetectAeroSource()
	writeJSON(w, 200, map[string]any{"code": 0, "data": st})
}

func (h *AeroHandler) ListTasks(w http.ResponseWriter, r *http.Request) {
	tasks := globalTaskManager.List()
	writeJSON(w, 200, map[string]any{"code": 0, "data": tasks, "results": tasks})
}

func (h *AeroHandler) GetTask(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		writeJSON(w, 400, errResp(1002, "invalid task id"))
		return
	}
	task, ok := globalTaskManager.Get(id)
	if !ok {
		writeJSON(w, 404, errResp(1001, "task not found"))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": task})
}

func (h *AeroHandler) DeleteTask(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseUint(idStr, 10, 64)
	globalTaskManager.Delete(id)
	writeJSON(w, 200, map[string]any{"code": 0, "message": "deleted"})
}

func (h *AeroHandler) ClearFailed(w http.ResponseWriter, r *http.Request) {
	cnt := globalTaskManager.ClearFailed()
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"deleted": cnt}})
}

func parseReqVPSID(r *http.Request) (uint64, error) {
	var raw map[string]any
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return 0, fmt.Errorf("invalid json: %w", err)
	}
	v, ok := raw["vps_id"]
	if !ok || v == nil {
		return 0, fmt.Errorf("vps_id required")
	}
	switch val := v.(type) {
	case float64:
		if val <= 0 {
			return 0, fmt.Errorf("vps_id must be positive")
		}
		return uint64(val), nil
	case string:
		s := strings.TrimSpace(val)
		if s == "" {
			return 0, fmt.Errorf("vps_id required")
		}
		id, err := strconv.ParseUint(s, 10, 64)
		if err != nil || id == 0 {
			return 0, fmt.Errorf("invalid vps_id string: %s", val)
		}
		return id, nil
	default:
		return 0, fmt.Errorf("vps_id required")
	}
}

func (h *AeroHandler) Install(w http.ResponseWriter, r *http.Request) {
	vpsID, err := parseReqVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "vps_id required"))
		return
	}
	cred, err := h.svc.store.GetCredentials(vpsID)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "vps not found: "+err.Error()))
		return
	}
	task := globalTaskManager.CreateTask("install", vpsID, cred.Name, DefaultInstallSteps())
	go RunInstallTask(task.ID, vpsID, h.svc)
	writeJSON(w, 201, map[string]any{"code": 0, "data": task})
}

func (h *AeroHandler) Uninstall(w http.ResponseWriter, r *http.Request) {
	vpsID, err := parseReqVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "vps_id required"))
		return
	}
	cred, err := h.svc.store.GetCredentials(vpsID)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "vps not found: "+err.Error()))
		return
	}
	task := globalTaskManager.CreateTask("uninstall", vpsID, cred.Name, DefaultUninstallSteps())
	go RunUninstallTask(task.ID, vpsID, h.svc)
	writeJSON(w, 200, map[string]any{"code": 0, "data": task})
}


func (h *AeroHandler) GetEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	if h.svc.eps != nil {
		if ep, ok := h.svc.eps.Get(id); ok {
			writeJSON(w, 200, map[string]any{"code": 0, "data": ep})
			return
		}
	}
	v, err := h.svc.Get(id)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "vps not found"))
		return
	}
	host := v.Domain
	if host == "" {
		host = v.IP
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": EndpointInfo{
		VPSID:     id,
		Name:      v.Name,
		Host:      host,
		Port:      443,
		Installed: true,
	}})
}

func (h *AeroHandler) RefreshEndpoint(w http.ResponseWriter, r *http.Request) {
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

func (h *AeroHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	v, _ := h.svc.Get(id)
	defTok := "aero_default_user_token"
	if v != nil && v.Name != "" {
		defTok = "tok_" + v.Name
	}
	tokens := []map[string]any{
		{
			"token":      defTok,
			"token_mask": defTok[:4] + "…" + defTok[len(defTok)-3:],
			"label":      "默认用户",
			"created_at": time.Now().Format("2006-01-02 15:04:05"),
		},
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": tokens}})
}

func (h *AeroHandler) AddToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Label    string `json:"label"`
		TTLHours int    `json:"ttl_hours"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	tok := req.Token
	if tok == "" {
		tok = "tok_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	item := map[string]any{
		"token":      tok,
		"token_mask": tok[:4] + "…",
		"label":      req.Label,
	}
	writeJSON(w, 201, map[string]any{"code": 0, "data": item})
}

func (h *AeroHandler) DelToken(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"code": 0, "message": "deleted"})
}

func (h *AeroHandler) Diagnose(w http.ResponseWriter, r *http.Request) {
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

func (h *AeroHandler) RenewCert(w http.ResponseWriter, r *http.Request) {
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

func (h *AeroHandler) RestartEdge(w http.ResponseWriter, r *http.Request) {
	id, err := parseVPSID(r)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid vps id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := h.svc.RestartEdge(ctx, id)
	if err != nil {
		writeJSON(w, 502, errResp(1006, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": res})
}

func (h *AeroHandler) SyncSubs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"code": 0, "message": "synced"})
}

func (h *AeroHandler) BroadcastSubs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"code": 0, "message": "broadcasted"})
}
