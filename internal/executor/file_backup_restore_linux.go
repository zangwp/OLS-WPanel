//go:build linux

package executor

import (
	"errors"
	"golang.org/x/sys/unix"
	"math"
)

// Exchange is a single kernel operation: a crash cannot leave the public
// document root absent between moving the old tree and installing the new one.
// Unsupported kernels/filesystems fail closed; there is no two-rename fallback.
func exchangeFileRestoreDirectories(live, staged string) error {
	return unix.Renameat2(unix.AT_FDCWD, live, unix.AT_FDCWD, staged, unix.RENAME_EXCHANGE)
}

func availableFileRestoreBytes(dir string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil {
		return 0, err
	}
	if stat.Bsize <= 0 || uint64(stat.Bavail) > uint64(math.MaxInt64)/uint64(stat.Bsize) {
		return 0, errors.New("invalid filesystem available space")
	}
	return int64(stat.Bavail) * stat.Bsize, nil
}
