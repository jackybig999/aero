//go:build !windows

package main

import (
	"log"
	"net/http"
)

func runClientWindow(htmlUI string, handler http.Handler, shutdown func()) {
	log.Println("[CLIENT] Native GUI window is only supported on Windows. Running in headless mode.")
	runHeadless(shutdown)
}

func UpdateTrayIcon(mode string, connected bool) {}
