package ipc

import (
	"aisys/connect/os/internal/apimatrix"
)

func RegisterAPIHandlers(w IPCBinder, vault *apimatrix.APIVault, tester *apimatrix.Tester) {
	w.Bind("goGetAPIs", func() []*apimatrix.APIProviderConfig {
		if vault == nil {
			return nil
		}
		return vault.GetAll()
	})

	w.Bind("goSaveAPI", func(id, key, baseURL string) map[string]interface{} {
		if vault != nil {
			vault.SaveKey(id, key, baseURL)
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goTestAPI", func(id string) map[string]interface{} {
		if tester == nil {
			return map[string]interface{}{"status": "error", "error": "tester not initialized"}
		}
		status, latency, err := tester.TestProvider(id)
		res := map[string]interface{}{
			"status":     status,
			"latency_ms": latency,
		}
		if err != nil {
			res["error"] = err.Error()
		}
		return res
	})
}
