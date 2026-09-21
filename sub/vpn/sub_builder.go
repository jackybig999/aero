// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// SubBuilder manages subscription distribution, SNI matrix mapping, and AI Tier-1 circuit breaking.
type SubBuilder struct {
	users  UserStore
	eps    *EndpointStore
	vps    VPSStore
	sniMgr *SNIMatrixManager
}

func NewSubBuilder(users UserStore, eps *EndpointStore, vps VPSStore, sniMgr *SNIMatrixManager) *SubBuilder {
	return &SubBuilder{
		users:  users,
		eps:    eps,
		vps:    vps,
		sniMgr: sniMgr,
	}
}

func (sb *SubBuilder) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /sub/{param}", sb.ServeSub)
	mux.HandleFunc("GET /api/v1/user/subscription", sb.ServePrivateSub)
}

func (sb *SubBuilder) ServePrivateSub(w http.ResponseWriter, r *http.Request) {
	uid, ok := r.Context().Value(CtxUserID).(uint64)
	if !ok || uid == 0 {
		writeJSON(w, http.StatusUnauthorized, errResp(1003, "unauthorized: login required"))
		return
	}
	user, err := sb.users.GetUser(uid)
	if err != nil || user == nil {
		writeJSON(w, http.StatusNotFound, errResp(1001, "user not found"))
		return
	}
	if !user.Status {
		writeJSON(w, http.StatusForbidden, errResp(1003, "account disabled"))
		return
	}
	if !user.ExpireAt.IsZero() && time.Now().After(user.ExpireAt) {
		writeJSON(w, http.StatusForbidden, errResp(1003, "subscription expired, please renew"))
		return
	}

	isp := r.URL.Query().Get("isp")
	purpose := r.URL.Query().Get("purpose")
	allowDegrade := r.URL.Query().Get("allow_degrade") == "true"
	sb.writeUserSubscription(w, user, isp, purpose, allowDegrade)
}

func (sb *SubBuilder) ServeSub(w http.ResponseWriter, r *http.Request) {
	param := r.PathValue("param")
	if param == "" {
		param = strings.TrimPrefix(r.URL.Path, "/sub/")
		param = strings.Trim(param, "/")
	}
	if param == "" {
		http.NotFound(w, r)
		return
	}

	// 1. 系统管理员常用不限制订阅: /sub/superadmin (无六位随机码，全节点永久有效)
	if param == "superadmin" {
		var staffUser *User
		if sb.users != nil {
			staffUser, _ = sb.users.GetUserBySlug("superadmin")
			if staffUser == nil {
				staffUser, _ = sb.users.GetUserByUsername("admin")
			}
		}
		if staffUser == nil {
			staffUser = &User{
				Username: "admin",
				SubSlug:  "superadmin",
				SubToken: "usr_superadmin",
				Status:   true,
				IsStaff:  true,
			}
		}
		isp := r.URL.Query().Get("isp")
		purpose := r.URL.Query().Get("purpose")
		sb.writeUserSubscription(w, staffUser, isp, purpose, true)
		return
	}

	// 2. 普通用户专属 Slug 订阅 (格式: {username}{6位随机码})
	if sb.users != nil {
		if user, err := sb.users.GetUserBySlug(param); err == nil && user != nil {
			if !user.Status {
				http.Error(w, `{"code": 1003, "message": "account disabled"}`, http.StatusForbidden)
				return
			}
			if !user.IsStaff && !user.ExpireAt.IsZero() && time.Now().After(user.ExpireAt) {
				http.Error(w, `{"code": 1003, "message": "subscription expired"}`, http.StatusForbidden)
				return
			}
			isp := r.URL.Query().Get("isp")
			purpose := r.URL.Query().Get("purpose")
			allowDegrade := r.URL.Query().Get("allow_degrade") == "true"
			sb.writeUserSubscription(w, user, isp, purpose, allowDegrade)
			return
		}
	}

	http.NotFound(w, r)
}

func (sb *SubBuilder) writeUserSubscription(w http.ResponseWriter, user *User, isp, purpose string, allowDegrade bool) {
	vpsMap := make(map[uint64]*VPSHost)
	if sb.vps != nil {
		if hosts, err := sb.vps.List(); err == nil {
			for _, h := range hosts {
				vpsMap[h.ID] = h
			}
		}
	}

	var allServers []map[string]any
	var tier1Servers []map[string]any

	if sb.eps != nil {
		for _, ep := range sb.eps.List() {
			host := strings.TrimSpace(ep.Host)
			if host == "" || net.ParseIP(host) != nil {
				continue
			}
			port := ep.Port
			if port <= 0 {
				port = 443
			}
			name := ep.Name
			if name == "" {
				name = fmt.Sprintf("VPS-%d", ep.VPSID)
			}
			token := user.SubToken
			if token == "" {
				token = "usr_" + user.Username
			}
			sni := host
			if sb.sniMgr != nil {
				regionKey := ep.Region
				if regionKey == "" {
					regionKey = name + " " + host
				}
				matched := sb.sniMgr.Match(isp, regionKey)
				if matched != "" {
					sni = matched
				}
			}
			srv := map[string]any{
				"name":     name,
				"address":  fmt.Sprintf("%s:%d", host, port),
				"token":    token,
				"sni":      sni,
				"protocol": "tcp_h2",
			}

			// 匹配 VPS 纯净度元数据
			isTier1 := false
			vps := vpsMap[ep.VPSID]
			if vps == nil && ep.IP != "" {
				for _, hst := range vpsMap {
					if hst.IP == ep.IP {
						vps = hst
						break
					}
				}
			}
			if vps != nil {
				srv["purityScore"] = vps.PurityScore
				srv["aiBlocked"] = vps.AIBlocked
				if !vps.AIBlocked && vps.PurityScore >= 90 && !vps.IsWARPEgress {
					isTier1 = true
				}
			}

			allServers = append(allServers, srv)
			if isTier1 {
				tier1Servers = append(tier1Servers, srv)
			}
		}
	}

	var servers []map[string]any
	var riskWarning string

	if purpose == "ai" {
		if len(tier1Servers) > 0 {
			servers = tier1Servers
		} else {
			if !allowDegrade {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"code":  http.StatusServiceUnavailable,
					"error": "TIER1_AI_NODES_EXHAUSTED",
				})
				return
			}
			servers = allServers
			riskWarning = "dirty_ip_degraded"
		}
	} else {
		servers = allServers
	}

	if len(servers) == 0 {
		defaultSNI := "edge.microsoft.com"
		if sb.sniMgr != nil {
			defaultSNI = sb.sniMgr.Match(isp, "DEFAULT")
		}
		servers = append(servers, map[string]any{
			"name":     "Default-Edge",
			"address":  "127.0.0.1:443",
			"token":    user.SubToken,
			"sni":      defaultSNI,
			"protocol": "tcp_h2",
		})
	}

	expireUnix := int64(0)
	if user.IsStaff {
		expireUnix = 0 // 0 indicates unrestricted / permanent
	} else if !user.ExpireAt.IsZero() {
		expireUnix = user.ExpireAt.Unix()
	} else {
		expireUnix = time.Now().AddDate(1, 0, 0).Unix()
	}

	doc := map[string]any{
		"version":   "aero/2.0",
		"userId":    user.Username,
		"slug":      user.SubSlug,
		"expireAt":  expireUnix,
		"createdAt": user.CreatedAt.Unix(),
		"servers":   servers,
		"optimization": map[string]any{
			"defaultQoS": "ultra-low-latency",
			"ispMatched": isp,
			"purpose":    purpose,
		},
	}
	if user.IsStaff {
		doc["role"] = "superadmin"
		doc["unrestricted"] = true
	}
	if riskWarning != "" {
		doc["riskWarning"] = riskWarning
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}
