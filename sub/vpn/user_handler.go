// Copyright 2025 AERO Protocol Contributors
// Plan.md Phase 2: 平铺无子包运营中台 — 用户中心 HTTP 路由与管理员初始化
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
)

type UserHandler struct {
	svc *UserService
}

func NewUserHandler(svc *UserService) *UserHandler {
	return &UserHandler{svc: svc}
}

func (h *UserHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login/", h.Login)
	mux.HandleFunc("POST /api/v1/users/", h.CreateUser)
	mux.HandleFunc("GET /api/v1/users/", h.ListUsers)
	mux.HandleFunc("GET /api/v1/users/{id}/", h.GetUser)
	mux.HandleFunc("PATCH /api/v1/users/{id}/", h.UpdateUser)
	mux.HandleFunc("PUT /api/v1/users/{id}/", h.UpdateUser)
	mux.HandleFunc("POST /api/v1/users/{id}/renew/", h.RenewUser)
	mux.HandleFunc("POST /api/v1/users/{id}/reset-slug/", h.ResetSlug)
	mux.HandleFunc("DELETE /api/v1/users/{id}/", h.DeleteUser)
	mux.HandleFunc("GET /api/v1/users/{id}/traffic/", h.GetTraffic)
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Phone      string `json:"phone"`
		Email      string `json:"email"`
		PlanName   string `json:"plan_name"`
		PlanMonths int32  `json:"plan_months"`
		PriceCents int64  `json:"price_cents"`
		IsStaff    bool   `json:"is_staff"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "invalid body"})
		return
	}
	u, err := h.svc.Register(CreateUserParams{
		Username:   req.Username,
		Password:   req.Password,
		Phone:      req.Phone,
		Email:      req.Email,
		PlanName:   req.PlanName,
		PlanMonths: req.PlanMonths,
		PriceCents: req.PriceCents,
		IsStaff:    req.IsStaff,
	})
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"code": 0, "data": u.Sanitize()})
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Portal   string `json:"portal"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	token, user, err := h.svc.Login(req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 1003, "message": "invalid credentials"})
		return
	}
	if req.Portal == "user" && user.IsStaff {
		writeJSON(w, http.StatusForbidden, map[string]any{"code": 1003, "message": "管理员账号禁止在普通用户端登录"})
		return
	}
	if req.Portal == "admin" && !user.IsStaff {
		writeJSON(w, http.StatusForbidden, map[string]any{"code": 1003, "message": "非管理员账号禁止访问管理后台"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"data": map[string]any{
			"token":     token,
			"username":  user.Username,
			"is_staff":  user.IsStaff,
			"user_id":   user.ID,
			"sub_slug":  user.SubSlug,
			"expire_at": user.ExpireAt,
		},
	})
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": 1002, "message": "invalid id"})
		return
	}
	u, err := h.svc.GetUser(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": u.Sanitize()})
}

func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	users, total, _ := h.svc.ListUsers(page, pageSize)
	safeUsers := make([]*User, 0, len(users))
	for i := range users {
		safeUsers = append(safeUsers, users[i].Sanitize())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code": 0, "data": map[string]any{"results": safeUsers, "count": total},
	})
}

func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var req struct {
		Phone      *string `json:"phone"`
		Email      *string `json:"email"`
		Status     *bool   `json:"status"`
		IsStaff    *bool   `json:"is_staff"`
		PlanName   *string `json:"plan_name"`
		PlanMonths *int32  `json:"plan_months"`
		PriceCents *int64  `json:"price_cents"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	err := h.svc.UpdateUserFull(id, UpdateUserParams{
		Phone:      req.Phone,
		Email:      req.Email,
		Status:     req.Status,
		IsStaff:    req.IsStaff,
		PlanName:   req.PlanName,
		PlanMonths: req.PlanMonths,
		PriceCents: req.PriceCents,
	})
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": "not found"})
		return
	}
	u, _ := h.svc.GetUser(id)
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": u.Sanitize()})
}

func (h *UserHandler) RenewUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var req struct {
		PlanName   string `json:"plan_name"`
		PlanMonths int32  `json:"plan_months"`
		PriceCents int64  `json:"price_cents"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	u, err := h.svc.RenewUser(id, req.PlanName, req.PlanMonths, req.PriceCents)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": u.Sanitize()})
}

func (h *UserHandler) ResetSlug(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	newSlug, err := h.svc.ResetSlug(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"sub_slug": newSlug}})
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err := h.svc.DeleteUser(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "message": "success"})
}

func (h *UserHandler) GetTraffic(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	stats, err := h.svc.GetTraffic(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 1001, "message": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": stats})
}

func seedAdmin(svc *UserService, db UserStore) {
	initPwd := os.Getenv("ADMIN_INIT_PASSWORD")
	if initPwd == "" {
		initPwd = "admin123"
	}
	existing, err := db.GetUserByUsername("admin")
	if err == nil && existing != nil {
		if !existing.IsStaff {
			_ = db.SetStaff(existing.ID, true)
		}
		if existing.PasswordHash == "" {
			_ = db.SetPassword(existing.ID, HashPassword(initPwd))
		}
	} else {
		u, err := svc.Register(CreateUserParams{
			Username: "admin", Password: initPwd, Email: "admin@vpn.local", IsStaff: true,
		})
		if err == nil && u != nil {
			_ = db.SetStaff(u.ID, true)
		}
	}
}
