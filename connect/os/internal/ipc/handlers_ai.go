package ipc

import (
	"aisys/connect/os/internal/aitools"
)

func RegisterAIHandlers(w IPCBinder, scanner *aitools.Scanner, executor *aitools.Executor, store *aitools.ToolStore, dirSelector func() string) {
	w.Bind("goGetAITools", func() []aitools.ToolInfo {
		if scanner == nil {
			return nil
		}
		return scanner.ScanAll()
	})

	w.Bind("goLaunchAITool", func(toolKey, cwd string) map[string]interface{} {
		if executor == nil {
			return map[string]interface{}{"status": "error", "error": "executor not initialized"}
		}
		msg, err := executor.Launch(toolKey, cwd)
		if err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "ok", "message": msg}
	})

	w.Bind("goSetToolCWD", func(toolKey, cwd string) map[string]interface{} {
		if store != nil {
			store.SetCWD(toolKey, cwd)
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goSelectDirectory", func() string {
		if dirSelector != nil {
			return dirSelector()
		}
		return ""
	})
}
