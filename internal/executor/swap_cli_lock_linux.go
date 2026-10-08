package executor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const canonicalSwapCLILockPath = "/run/ols-wpanel/swap.lock"

func acquireSwapCLILock(path string) (*cronJobExecutionLock, error) {
	// Reuse the private runtime-directory and fd-identity checks used for cron
	// locks. Do not unlink the lock file: its inode coordinates all CLI processes.
	if path == canonicalSwapCLILockPath && os.Geteuid() != 0 {
		return nil, errors.New("Swap 管理锁需要 root 权限")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("Swap 管理锁路径必须是绝对路径")
	}
	if err := ensureOwnedPrivateDirectory(filepath.Dir(path), uint32(os.Geteuid())); err != nil {
		return nil, fmt.Errorf("Swap 管理锁目录不安全: %w", err)
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开 Swap 管理锁失败: %w", err)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Mode&0o777 != 0o600 {
		_ = syscall.Close(fd)
		return nil, errors.New("Swap 管理锁文件身份不安全")
	}
	file := os.NewFile(uintptr(fd), path)
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("另一个 Swap 设置正在执行，请稍后重试")
		}
		return nil, fmt.Errorf("获取 Swap 管理锁失败: %w", err)
	}
	return &cronJobExecutionLock{file: file}, nil
}
