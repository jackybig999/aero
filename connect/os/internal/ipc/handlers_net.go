package ipc

import (
	"log"

	"aisys/connect/os/internal/netcore"
)

func RegisterNetHandlers(w IPCBinder, bridge *netcore.ClientBridge, daemon *netcore.ClientDaemon) {
	w.Bind("goGetNetStatus", func() map[string]interface{} {
		st, err := bridge.GetStatus(true)
		if err != nil {
			return map[string]interface{}{
				"connected": false,
				"error":     err.Error(),
				"listen":    netcore.DefaultMixedProxy,
				"ready":     false,
			}
		}
		res := map[string]interface{}{
			"connected":    st.Connected,
			"mode":         st.Mode,
			"listen":       st.Listen,
			"node":         st.Node,
			"rtt_ms":       st.RTTMs,
			"sub_url":      st.SubURL,
			"sub_url_mask": st.SubURLMask,
			"last_error":   st.LastError,
			"protocol":     st.Protocol,
			"isp":          st.ISP,
			"ready":        true,
		}
		if st.ProbeOK != nil {
			res["probe_ok"] = *st.ProbeOK
			res["probe_ms"] = st.ProbeMS
			res["probe_detail"] = st.ProbeDetail
		}
		return res
	})

	w.Bind("goToggleNetPower", func(targetOn bool) map[string]interface{} {
		var err error
		if targetOn {
			if daemon != nil {
				_ = daemon.EnsureRunning()
			}
			err = bridge.Connect()
		} else {
			err = bridge.Disconnect()
		}
		if err != nil {
			log.Printf("[IPC-NET] power toggle error: %v", err)
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goSetNetMode", func(mode string) map[string]interface{} {
		if err := bridge.SetMode(mode); err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goApplyNetSub", func(subURL string) map[string]interface{} {
		if err := bridge.ImportSub(subURL); err != nil {
			return map[string]interface{}{"status": "error", "error": err.Error()}
		}
		return map[string]interface{}{"status": "ok"}
	})

	w.Bind("goProbeNet", func() map[string]interface{} {
		res, err := bridge.Probe()
		if err != nil {
			return map[string]interface{}{"ok": false, "error": err.Error()}
		}
		return res
	})
}
