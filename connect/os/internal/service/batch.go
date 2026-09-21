package service

import "fmt"

// BatchStartProfiles 批量启动环境
func (s *AppService) BatchStartProfiles(ids []int64) map[string]interface{} {
	success := 0
	failed := 0
	var errs []string
	for _, id := range ids {
		if err := s.StartProfile(id); err != nil {
			failed++
			errs = append(errs, fmt.Sprintf("ID %d: %v", id, err))
		} else {
			success++
		}
	}
	return map[string]interface{}{
		"success_count": success,
		"failed_count":  failed,
		"errors":        errs,
	}
}

// BatchStopProfiles 批量停止环境
func (s *AppService) BatchStopProfiles(ids []int64) map[string]interface{} {
	stopped := 0
	for _, id := range ids {
		_ = s.StopProfile(id)
		stopped++
	}
	return map[string]interface{}{"stopped_count": stopped}
}

// BatchDeleteProfiles 批量删除环境
func (s *AppService) BatchDeleteProfiles(ids []int64) map[string]interface{} {
	deleted := 0
	for _, id := range ids {
		if err := s.DeleteProfile(id); err == nil {
			deleted++
		}
	}
	return map[string]interface{}{"deleted_count": deleted}
}
