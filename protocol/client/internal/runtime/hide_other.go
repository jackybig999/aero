//go:build !windows

package runtime

import "os/exec"

func hideConsole(cmd *exec.Cmd) {}
