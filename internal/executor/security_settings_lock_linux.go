//go:build linux

package executor

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func openSecuritySettingsLock(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("安全设置锁路径必须是绝对路径")
	}
	if err := ensureOwnedPrivateDirectory(filepath.Dir(path), uint32(os.Geteuid())); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		file.Close()
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Mode&0777 != 0600 {
		file.Close()
		return nil, errors.New("安全设置锁文件身份不安全")
	}
	return file, nil
}
