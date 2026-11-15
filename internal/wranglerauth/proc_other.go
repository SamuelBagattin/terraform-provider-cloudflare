//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly)

package wranglerauth

import "os/exec"

// setProcessGroup is a no-op here: exec.CommandContext kills the direct child
// on timeout, and cmd.WaitDelay bounds the wait for any grandchild.
func setProcessGroup(*exec.Cmd) {}
