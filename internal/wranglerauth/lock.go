package wranglerauth

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

const lockPollInterval = 50 * time.Millisecond

// DefaultLockPath is the lock shared by every provider process of the user,
// including provider aliases that Terraform runs in parallel.
func DefaultLockPath() string {
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "terraform-provider-cloudflare", "wrangler-auth.lock")
}

// acquireLock takes an exclusive advisory lock on path, polling until it is
// free or ctx is done. The lock is released by the returned function, or by
// the operating system if the process dies.
func acquireLock(ctx context.Context, path string) (release func(), err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		locked, err := tryLock(f)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if locked {
			return func() {
				_ = unlock(f)
				_ = f.Close()
			}, nil
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPollInterval):
		}
	}
}
