//go:build !windows

package main

import (
	"log"
)

func runClientWindow(uiURL string, shutdown func()) {
	log.Printf("[CLIENT] Native GUI window is only supported on Windows. Running in headless mode. Access Web UI at: %s", uiURL)
	runHeadless(shutdown)
}
