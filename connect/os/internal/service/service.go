package service

import (
	"database/sql"
	"sync"
	"time"

	"aisys/connect/os/internal/domain/proxy"
)

// AppService 核心业务协调总线
type AppService struct {
	DB               *sql.DB
	SysProxyDetector proxy.SysProxyDetector
	DataDir          string
	ServerPort       int
	healthTicker     *time.Ticker
	healthStopChan   chan struct{}
	statusCache      sync.Map // profID(int64) -> status(string)
	mu               sync.RWMutex
}

var (
	GlobalService *AppService
	serviceOnce   sync.Once
)

// InitAppService 初始化全局服务 (保证并发线程安全)
func InitAppService(db *sql.DB, detector proxy.SysProxyDetector, dataDir string, port int) *AppService {
	if port <= 0 {
		port = 18888
	}
	serviceOnce.Do(func() {
		GlobalService = &AppService{
			DB:               db,
			SysProxyDetector: detector,
			DataDir:          dataDir,
			ServerPort:       port,
			healthStopChan:   make(chan struct{}),
		}
	})

	if GlobalService != nil {
		GlobalService.mu.Lock()
		if db != nil {
			GlobalService.DB = db
		}
		if detector != nil {
			GlobalService.SysProxyDetector = detector
		}
		if dataDir != "" {
			GlobalService.DataDir = dataDir
		}
		if port > 0 {
			GlobalService.ServerPort = port
		}
		GlobalService.mu.Unlock()
	}
	return GlobalService
}

// SetProfileStatusCache 更新环境运行状态内存快照
func (s *AppService) SetProfileStatusCache(id int64, status string) {
	s.statusCache.Store(id, status)
}

// GetProfileStatusCache 获取环境运行状态内存快照
func (s *AppService) GetProfileStatusCache(id int64) (string, bool) {
	if val, ok := s.statusCache.Load(id); ok {
		if str, ok := val.(string); ok {
			return str, true
		}
	}
	return "", false
}
