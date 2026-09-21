package netcore

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type ClientDaemon struct {
	bridge      *ClientBridge
	cmd         *exec.Cmd
	startedByMe bool
	mu          sync.Mutex
}

func NewClientDaemon(bridge *ClientBridge) *ClientDaemon {
	return &ClientDaemon{
		bridge: bridge,
	}
}

// EnsureRunning checks if client is online, launching aero-client-cli if offline
func (d *ClientDaemon) EnsureRunning() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.bridge.Ping() {
		log.Printf("[NETCORE] Client already active on 127.0.0.1:19877")
		return nil
	}

	binPath := d.findClientBinary()
	if binPath == "" {
		log.Printf("[NETCORE] aero-client-cli not found, expecting external client")
		return nil
	}

	log.Printf("[NETCORE] Starting background client daemon: %s", binPath)
	cmd := exec.Command(binPath)
	hideProcessWindow(cmd)

	if err := cmd.Start(); err != nil {
		log.Printf("[NETCORE] Failed to launch client daemon: %v", err)
		return err
	}

	d.cmd = cmd
	d.startedByMe = true

	// Wait up to 5 seconds for API to be ready
	for i := 0; i < 25; i++ {
		time.Sleep(200 * time.Millisecond)
		if d.bridge.Ping() {
			log.Printf("[NETCORE] Client daemon is ready on 127.0.0.1:19877")
			return nil
		}
	}
	log.Printf("[NETCORE] Client daemon launched (pid=%d), waiting for initialization...", cmd.Process.Pid)
	return nil
}

// Stop cleanly terminates the daemon if it was started by AERO OS
func (d *ClientDaemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.startedByMe && d.cmd != nil && d.cmd.Process != nil {
		_ = d.bridge.Disconnect()
		_ = d.cmd.Process.Kill()
		log.Printf("[NETCORE] Stopped client daemon pid=%d", d.cmd.Process.Pid)
		d.cmd = nil
		d.startedByMe = false
	}
}

func (d *ClientDaemon) findClientBinary() string {
	if env := os.Getenv("AERO_CLIENT_BIN"); env != "" {
		if fi, err := os.Stat(env); err == nil && !fi.IsDir() {
			return env
		}
	}

	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "aero-client-cli.exe"),
			filepath.Join(dir, "aero-client.exe"),
			filepath.Join(dir, "..", "dist", "win", "aero-client-cli.exe"),
			filepath.Join(dir, "..", "dist", "win", "aero-client.exe"),
			filepath.Join(dir, "..", "..", "dist", "win", "aero-client-cli.exe"),
		)
	}

	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "aero-client-cli.exe"),
			filepath.Join(cwd, "dist", "win", "aero-client-cli.exe"),
			filepath.Join(cwd, "..", "dist", "win", "aero-client-cli.exe"),
			filepath.Join(cwd, "..", "..", "dist", "win", "aero-client-cli.exe"),
		)
	}

	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			abs, err := filepath.Abs(p)
			if err == nil {
				return abs
			}
			return p
		}
	}
	return ""
}
