//go:build !windows

package netcore

import "os/exec"

func hideProcessWindow(cmd *exec.Cmd) {}
