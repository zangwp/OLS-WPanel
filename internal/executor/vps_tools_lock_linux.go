//go:build linux

package executor

import (
	"fmt"
	"os"
	"syscall"
)

func lockSimpleVPSTools() (func(), error) {
	fd, err := syscall.Open("/run/lock/ols-wpanel-vps-tools.lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "vps-tools-lock")
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("VPS operation is already running")
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); file.Close() }, nil
}
