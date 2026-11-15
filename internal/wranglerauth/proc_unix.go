//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package wranglerauth

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// setProcessGroup starts wrangler in its own process group and kills the whole
// group on timeout: `npx wrangler` runs node in a child process that would
// otherwise survive the kill and keep the output pipes open.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			// The group already exited: not a failure of the command.
			return os.ErrProcessDone
		}
		return err
	}
}
