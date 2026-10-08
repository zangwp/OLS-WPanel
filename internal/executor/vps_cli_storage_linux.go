package executor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Every ancestor must be owned by the current privileged account and must not
// allow other users to replace the private directory. Never chmod existing
// administrator directories or follow symlinks to create CLI state.
func ensureVPSCLIPrivateDirectory(path string, create bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("终端状态目录路径无效")
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, current), current)
	for index, part := range parts {
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && create {
			mode := os.FileMode(0755)
			if index == len(parts)-1 {
				mode = 0700
			}
			if err = os.Mkdir(current, mode); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			st, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || stat.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("终端状态目录身份或权限不安全: %s", current)
		}
		if index == len(parts)-1 && st.Mode().Perm() != 0700 {
			return errors.New("终端私有状态目录权限必须为 0700")
		}
	}
	return nil
}

func readVPSCLIPrivateFile(path string, maxBytes int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if err := validateVPSCLIPrivateFD(fd); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err == nil && int64(len(data)) > maxBytes {
		err = errors.New("终端状态文件超过大小上限")
	}
	return data, err
}

func validateVPSCLIPrivateFD(fd int) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Mode&0777 != 0600 {
		return errors.New("终端状态文件身份、链接或权限不安全")
	}
	return nil
}

func writeVPSCLIPrivateFile(path string, data []byte) error {
	if err := ensureVPSCLIPrivateDirectory(filepath.Dir(path), false); err != nil {
		return err
	}
	if _, err := readVPSCLIPrivateFile(path, 1024*1024); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".vps-cli-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}
