// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package api

import (
	"encoding/json"
	"net/http"
	"time"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	s.syncFromRuntime()
	st := s.State()
	// optional live probe: /api/v1/status?probe=1
	if r.URL.Query().Get("probe") == "1" {
		if p := s.runProbe(); p != nil {
			if ok, has := p["ok"].(bool); has {
				b := ok
				st.ProbeOK = &b
			}
			switch ms := p["ms"].(type) {
			case int64:
				st.ProbeMS = ms
			case float64:
				st.ProbeMS = int64(ms)
			case int:
				st.ProbeMS = int64(ms)
			}
			if d, ok := p["detail"].(string); ok {
				st.ProbeDetail = d
			}
			if e, ok := p["error"].(string); ok && e != "" && st.ProbeDetail == "" {
				st.ProbeDetail = e
			}
		}
	}
	writeJSON(w, st)
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
		return
	}
	p := s.runProbe()
	if p == nil {
		writeJSON(w, map[string]string{"error": "probe not available", "ok": "false"})
		return
	}
	writeJSON(w, p)
}

func (s *Server) runProbe() map[string]interface{} {
	rt := s.runtimeOrNil()
	if rt == nil {
		return map[string]interface{}{"ok": false, "error": "runtime not ready"}
	}
	if p := rt.Probe(); p != nil {
		return p
	}
	return map[string]interface{}{"ok": false, "error": "probe not implemented"}
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	rt := s.runtimeOrNil()
	if rt == nil {
		writeJSON(w, map[string]string{"status": "error", "error": "runtime not ready"})
		return
	}
	if err := rt.Connect(); err != nil {
		writeJSON(w, map[string]string{"status": "error", "error": err.Error()})
		return
	}
	s.UpdateState(func(st *AppState) {
		st.Connected = true
		if st.UptimeStart.IsZero() {
			st.UptimeStart = time.Now()
		}
		st.Node = rt.ActiveNode()
	})
	writeJSON(w, map[string]string{"status": "connected", "node": rt.ActiveNode()})
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	rt := s.runtimeOrNil()
	if rt == nil {
		writeJSON(w, map[string]string{"status": "error", "error": "runtime not ready"})
		return
	}
	if err := rt.Disconnect(); err != nil {
		writeJSON(w, map[string]string{"status": "error", "error": err.Error()})
		return
	}
	s.UpdateState(func(st *AppState) { st.Connected = false })
	writeJSON(w, map[string]string{"status": "disconnected"})
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Sub string `json:"sub"`
		// QR payload: same as subscription URL (运维台二维码内容)
		QR string `json:"qr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]string{"error": "invalid json"})
		return
	}
	src := req.Sub
	if src == "" {
		src = req.QR
	}
	if src == "" {
		writeJSON(w, map[string]string{"error": "need {\"sub\":\"url\"} or {\"qr\":\"url\"}"})
		return
	}
	rt := s.runtimeOrNil()
	if rt == nil {
		writeJSON(w, map[string]string{"status": "error", "error": "runtime not ready"})
		return
	}
	if err := rt.ImportSub(src); err != nil {
		s.UpdateState(func(st *AppState) { st.LastError = err.Error() })
		writeJSON(w, map[string]string{"status": "error", "error": err.Error()})
		return
	}
	s.UpdateState(func(st *AppState) {
		st.SubURL = src
		st.SubURLMask = maskSubURL(src)
		st.LastError = ""
	})
	s.syncFromRuntime()
	writeJSON(w, map[string]string{"status": "imported", "node": rt.ActiveNode(), "sub_url_mask": maskSubURL(src)})
}

func (s *Server) handleMode(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.syncFromRuntime()
		st := s.State()
		writeJSON(w, map[string]string{"mode": st.Mode, "listen": st.Listen})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Mode == "" {
		writeJSON(w, map[string]string{"error": "need {\"mode\":\"socks|sysproxy|tun\"}"})
		return
	}
	rt := s.runtimeOrNil()
	if rt == nil {
		writeJSON(w, map[string]string{"status": "error", "error": "runtime not ready"})
		return
	}
	if err := rt.SetMode(req.Mode); err != nil {
		s.UpdateState(func(st *AppState) { st.LastError = err.Error() })
		writeJSON(w, map[string]string{"status": "error", "error": err.Error()})
		return
	}
	s.UpdateState(func(st *AppState) {
		st.Mode = rt.Mode()
		st.LastError = ""
	})
	writeJSON(w, map[string]string{"status": "ok", "mode": rt.Mode()})
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleNodeSwitch(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
		return
	}
	s.syncFromRuntime()
	writeJSON(w, s.State().Nodes)
}

func (s *Server) handleNodeSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Node string `json:"node"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Node == "" {
		writeJSON(w, map[string]string{"error": "need {\"node\":\"host:port\"}"})
		return
	}
	rt := s.runtimeOrNil()
	if rt == nil {
		writeJSON(w, map[string]string{"error": "runtime not ready"})
		return
	}
	if err := rt.SwitchNode(req.Node); err != nil {
		writeJSON(w, map[string]string{"status": "error", "error": err.Error(), "node": req.Node})
		return
	}
	s.UpdateState(func(st *AppState) {
		st.Node = req.Node
		for i := range st.Nodes {
			st.Nodes[i].Active = st.Nodes[i].Address == req.Node
		}
	})
	writeJSON(w, map[string]string{"status": "switched", "node": req.Node})
}

func (s *Server) handleSplitRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.State().SplitRules)
}

func (s *Server) handleQoSStats(w http.ResponseWriter, r *http.Request) {
	st := s.State()
	out := map[string]interface{}{
		"ftl_avg_ms": st.FTLAvgMs, "jitter_ms": st.JitterMs,
		"loss_rate": st.LossRate, "rtt_ms": st.RTTMs,
	}
	if rt := s.runtimeOrNil(); rt != nil {
		if ai := rt.AIStats(); ai != nil {
			out["ai"] = ai
		}
	}
	writeJSON(w, out)
}

func (s *Server) handleAIStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	rt := s.runtimeOrNil()
	if rt == nil {
		writeJSON(w, map[string]string{"error": "runtime not ready"})
		return
	}
	if ai := rt.AIStats(); ai != nil {
		writeJSON(w, ai)
		return
	}
	writeJSON(w, map[string]string{"error": "ai stats unavailable"})
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	st := s.State()
	writeJSON(w, map[string]uint64{"bytes_sent": st.BytesSent, "bytes_recv": st.BytesRecv})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"format": "yaml", "path": "configs/client.yaml"})
}

func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok", "message": "use import or restart for full reload"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"version": "aero-ech v2.0.0"})
}

func (s *Server) handlePAC(w http.ResponseWriter, r *http.Request) {
	// Mixed inbound: HTTP + HTTPS CONNECT + SOCKS5 share one port (Clash-style)
	mixed := "127.0.0.1:55555"
	s.syncFromRuntime()
	st := s.State()
	if st.Listen != "" {
		mixed = st.Listen
	} else if st.HTTPListen != "" {
		mixed = st.HTTPListen
	}
	pac := "function FindProxyForURL(url, host) {\n" +
		"  if (isPlainHostName(host) || host === \"127.0.0.1\" || host === \"localhost\" || host === \"::1\") return \"DIRECT\";\n" +
		"  if (shExpMatch(host, \"10.*\") || shExpMatch(host, \"192.168.*\") ||\n" +
		"      shExpMatch(host, \"172.16.*\") || shExpMatch(host, \"172.17.*\") ||\n" +
		"      shExpMatch(host, \"172.18.*\") || shExpMatch(host, \"172.19.*\") ||\n" +
		"      shExpMatch(host, \"172.2*.*\") || shExpMatch(host, \"172.30.*\") ||\n" +
		"      shExpMatch(host, \"172.31.*\")) return \"DIRECT\";\n" +
		"  return \"PROXY " + mixed + "; SOCKS5 " + mixed + "; DIRECT\";\n" +
		"}\n"
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pac))
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	_ = json.NewEncoder(w).Encode(v)
}

func corsWrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
