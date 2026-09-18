// Package handler implements HTTP endpoints for user-center.
package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/vpn-platform/vpsserver/vpn/internal/middleware"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/domain"
	"github.com/vpn-platform/vpsserver/vpn/internal/modules/user/service"
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
	mux.HandleFunc("DELETE /api/v1/users/{id}/", h.DeleteUser)
	mux.HandleFunc("GET /api/v1/users/{id}/traffic/", h.GetTraffic)
	// plans 由 billing 模块独占，避免与统一入口路由冲突
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		IsStaff  bool   `json:"is_staff"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 422, errResp(1002, "invalid body"))
		return
	}
	// 开放注册禁止自提管理员；is_staff 仅能由已有管理员改 PATCH
	u, err := h.svc.Register(domain.CreateUserParams{
		Username: req.Username, Password: req.Password, Email: req.Email, IsStaff: false,
	})
	if err != nil {
		writeJSON(w, 422, errResp(1002, err.Error()))
		return
	}
	writeJSON(w, 201, map[string]any{
		"code": 0, "data": map[string]any{"id": u.ID, "username": u.Username, "is_staff": u.IsStaff},
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	token, user, err := h.svc.Login(req.Username, req.Password)
	if err != nil {
		writeJSON(w, 401, errResp(1003, "invalid credentials"))
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
	writeJSON(w, 200, map[string]any{"code": 0, "data": u})
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	users, total, _ := h.svc.ListUsers(page, pageSize)
	writeJSON(w, 200, map[string]any{
		"code": 0, "data": map[string]any{"results": users, "count": total},
	})
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	var req struct {
		Email   *string `json:"email"`
		Status  *bool   `json:"status"`
		IsStaff *bool   `json:"is_staff"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if err := h.svc.UpdateUser(id, req.Email, req.Status, req.IsStaff); err != nil {
		writeJSON(w, 404, errResp(1001, "not found"))
		return
	}
	writeJSON(w, 200, okResp())
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
