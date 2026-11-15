//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package wranglerauth

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// flock locks belong to the open file description, so two opens of the same
// path exclude each other even inside one process.
func tryLock(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

func unlock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
