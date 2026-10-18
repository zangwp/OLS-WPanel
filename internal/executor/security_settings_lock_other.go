//go:build !linux

package executor

import (
	"errors"
	"os"
	"path/filepath"
)

// Non-Linux builds support isolated kernel-lock tests, never a live OLS host.
func openSecuritySettingsLock(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("安全设置锁路径必须是绝对路径")
	}
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("安全设置锁目录不安全")
	}
	previous, err := os.Lstat(path)
	if err == nil && !previous.Mode().IsRegular() {
		return nil, errors.New("安全设置锁不是普通文件")
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
}
