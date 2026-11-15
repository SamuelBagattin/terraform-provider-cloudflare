//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly || windows)

package wranglerauth

import "os"

// No advisory lock on this platform: wrangler runs are still deduplicated
// inside the process, just not across provider processes.
func tryLock(*os.File) (bool, error) { return true, nil }

func unlock(*os.File) error { return nil }
