// Package handler implements HTTP endpoints for user-center.
package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/vpn-platform/vpsserver/vpn/internal/middleware"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/service"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/store"
)

type Handler struct {
	svc *service.Service
}

func New(svc *service.Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
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
	// plans 由 billing 模块独占，避免与统一入口路由冲突
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
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
		writeJSON(w, 422, errResp(1002, "invalid body"))
		return
	}
	u, err := h.svc.Register(domain.CreateUserParams{
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
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 201, map[string]any{
		"code": 0, "data": u.Sanitize(),
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Portal   string `json:"portal"` // "user" | "admin" | "client"
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	token, user, err := h.svc.Login(req.Username, req.Password)
	if err != nil {
		writeJSON(w, 401, errResp(1003, "invalid credentials"))
		return
	}
	if req.Portal == "user" && user.IsStaff {
		writeJSON(w, 403, errResp(1003, "管理员账号禁止在普通用户端登录"))
		return
	}
	if req.Portal == "admin" && !user.IsStaff {
		writeJSON(w, 403, errResp(1003, "非管理员账号禁止访问管理后台"))
		return
	}
	writeJSON(w, 200, map[string]any{
		"code": 0, "data": map[string]any{
			"token": token, "username": user.Username,
			"is_staff": user.IsStaff, "user_id": user.ID,
			"sub_slug": user.SubSlug, "expire_at": user.ExpireAt,
		},
	})
}

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 422, errResp(1002, "invalid id"))
		return
	}
	u, err := h.svc.GetUser(id)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "not found"))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": u.Sanitize()})
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	users, total, _ := h.svc.ListUsers(page, pageSize)
	safeUsers := make([]*domain.User, 0, len(users))
	for i := range users {
		safeUsers = append(safeUsers, users[i].Sanitize())
	}
	writeJSON(w, 200, map[string]any{
		"code": 0, "data": map[string]any{"results": safeUsers, "count": total},
	})
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
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
	err := h.svc.UpdateUserFull(id, store.UpdateUserParams{
		Phone:      req.Phone,
		Email:      req.Email,
		Status:     req.Status,
		IsStaff:    req.IsStaff,
		PlanName:   req.PlanName,
		PlanMonths: req.PlanMonths,
		PriceCents: req.PriceCents,
	})
	if err != nil {
		writeJSON(w, 404, errResp(1001, "not found"))
		return
	}
	u, _ := h.svc.GetUser(id)
	writeJSON(w, 200, map[string]any{"code": 0, "data": u.Sanitize()})
}

func (h *Handler) RenewUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var req struct {
		PlanName   string `json:"plan_name"`
		PlanMonths int32  `json:"plan_months"`
		PriceCents int64  `json:"price_cents"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	u, err := h.svc.RenewUser(id, req.PlanName, req.PlanMonths, req.PriceCents)
	if err != nil {
		writeJSON(w, 404, errResp(1001, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": u.Sanitize()})
}

func (h *Handler) ResetSlug(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	newSlug, err := h.svc.ResetSlug(id)
	if err != nil {
		writeJSON(w, 404, errResp(1001, err.Error()))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"sub_slug": newSlug}})
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err := h.svc.DeleteUser(id); err != nil {
		writeJSON(w, 404, errResp(1001, "not found"))
		return
	}
	writeJSON(w, 200, okResp())
}

func (h *Handler) GetTraffic(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	stats, err := h.svc.GetTraffic(id)
	if err != nil {
		writeJSON(w, 404, errResp(1001, "not found"))
		return
	}
	writeJSON(w, 200, map[string]any{"code": 0, "data": stats})
}

func (h *Handler) ListPlans(w http.ResponseWriter, r *http.Request) {
	plans, _ := h.svc.ListPlans(true)
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"results": plans}})
}

// middleware integration

func (h *Handler) Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := middleware.ExtractToken(r)
		if token == "" {
			writeJSON(w, 401, errResp(1003, "unauthorized"))
			return
		}
		uid, staff, err := h.svc.VerifyToken(token)
		if err != nil {
			writeJSON(w, 401, errResp(1003, "invalid token"))
			return
		}
		ctx := middleware.WithUser(r, uid, staff)
		next(w, r.WithContext(ctx))
	}
}

// JSON helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func errResp(code int, msg string) map[string]any {
	return map[string]any{"code": code, "message": msg}
}

func okResp() map[string]any {
	return map[string]any{"code": 0, "message": "success"}
}
