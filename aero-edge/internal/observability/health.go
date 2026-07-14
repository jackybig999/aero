// 健康检查端点增强
package observability

import (
	"encoding/json"
	"net/http"
	"time"
)

var startTime = time.Now()

// HealthResponse 健康检查响应
type HealthResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	UptimeSec int64  `json:"uptime_sec"`
}

// HealthHandler 返回增强的健康检查处理器
func HealthHandler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		uptime := int64(time.Since(startTime).Seconds())
		resp := HealthResponse{
			Status:    "ok",
			Version:   version,
			UptimeSec: uptime,
		}
		data, _ := json.Marshal(resp)
		w.Write(data)
	}
}
