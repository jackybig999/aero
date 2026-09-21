package ipc

import (
	"aisys/connect/os/internal/audit"
)

func RegisterAuditHandlers(w IPCBinder, history *audit.HistoryStore) {
	w.Bind("goGetLogs", func() []audit.LogEntry {
		return audit.GlobalLogger.GetLogs()
	})

	w.Bind("goClearLogs", func() map[string]interface{} {
		audit.GlobalLogger.Clear()
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goExportLogs", func(customPath string) map[string]interface{} {
		err := audit.GlobalLogger.ExportToFile(customPath)
		if err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goGetHistory", func() []audit.HistoryItem {
		if history == nil {
			return nil
		}
		return history.GetItems()
	})

	w.Bind("goClearHistory", func() map[string]interface{} {
		if history != nil {
			history.Clear()
		}
		return map[string]interface{}{"status": "ok"}
	})
}
