//go:build linux

package executor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const dnsImmutableFlag = 0x10

func dnsFileOwner() (int, int) { return os.Geteuid(), os.Getegid() }

func openDNSStatusFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func dnsCanonicalPath(path string) bool {
	defaults := defaultDNSPaths()
	return path == defaults.ResolvConf || path == defaults.DropIn || path == defaults.Backup || path == defaults.Lock
}

func dnsExpectedUID(path string) (uint32, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return 0, errors.New("DNS 路径必须是规范绝对路径")
	}
	if dnsCanonicalPath(path) && os.Geteuid() != 0 {
		return 0, errors.New("修改 DNS 需要 root 权限")
	}
	return uint32(os.Geteuid()), nil
}

// Validate every existing ancestor. Only a root-owned sticky temp directory is
// permitted for noncanonical fixture paths; production never traverses it.
func validateDNSDirectory(path string, create, private, canonical bool) error {
	uid := uint32(os.Geteuid())
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	current := "/"
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && create {
			mode := os.FileMode(0o755)
			if private && i == len(parts)-1 {
				mode = 0o700
			}
			if err = os.Mkdir(current, mode); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (stat.Uid != 0 && stat.Uid != uid) {
			return fmt.Errorf("DNS 目录身份不安全: %s", current)
		}
		if info.Mode().Perm()&0o022 != 0 && !(!canonical && stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return fmt.Errorf("DNS 目录可被其他账户修改: %s", current)
		}
		if i == len(parts)-1 && private && (stat.Uid != uid || info.Mode().Perm() != 0o700) {
			return errors.New("DNS 私有目录必须由当前管理账户持有且权限为 0700")
		}
	}
	return nil
}

func ensureDNSPrivateDirectory(filePath string, create bool) error {
	if _, err := dnsExpectedUID(filePath); err != nil {
		return err
	}
	return validateDNSDirectory(filepath.Dir(filePath), create, true, dnsCanonicalPath(filePath))
}

func dnsOpenRegular(path string) (*os.File, os.FileInfo, error) {
	uid, err := dnsExpectedUID(path)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, nil, errors.New("DNS 文件不是受保护的普通文件")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	actual, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	stat, ok := actual.Sys().(*syscall.Stat_t)
	if !ok || !actual.Mode().IsRegular() || !os.SameFile(info, actual) || stat.Uid != uid || stat.Nlink != 1 || actual.Mode().Perm()&0o022 != 0 || actual.Size() > 128*1024 {
		file.Close()
		return nil, nil, errors.New("DNS 文件身份、所有权或大小检查失败")
	}
	return file, actual, nil
}

func dnsReadImmutable(file *os.File) (bool, error) {
	flags, err := unix.IoctlGetInt(int(file.Fd()), unix.FS_IOC_GETFLAGS)
	if errors.Is(err, syscall.ENOTTY) || errors.Is(err, syscall.EOPNOTSUPP) {
		return false, nil
	}
	return flags&dnsImmutableFlag != 0, err
}

func dnsSetImmutable(file *os.File, value bool) error {
	flags, err := unix.IoctlGetInt(int(file.Fd()), unix.FS_IOC_GETFLAGS)
	if errors.Is(err, syscall.ENOTTY) || errors.Is(err, syscall.EOPNOTSUPP) {
		if !value {
			return nil
		}
		return errors.New("文件系统不支持恢复 immutable 属性")
	}
	if err != nil {
		return err
	}
	next := flags & ^dnsImmutableFlag
	if value {
		next |= dnsImmutableFlag
	}
	if flags != next {
		if err := unix.IoctlSetPointerInt(int(file.Fd()), unix.FS_IOC_SETFLAGS, next); err != nil {
			return err
		}
	}
	actual, err := dnsReadImmutable(file)
	if err != nil || actual != value {
		return errors.New("DNS immutable 属性回读不一致")
	}
	return nil
}

func readDNSFileSnapshot(path string, allowMissing bool) (dnsFileSnapshot, error) {
	var snapshot dnsFileSnapshot
	if _, err := dnsExpectedUID(path); err != nil {
		return snapshot, err
	}
	// An absent resolved drop-in is supported without creating directories during
	// a status query. Existing ancestors still must be safe.
	dir := filepath.Dir(path)
	for {
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) && allowMissing {
			dir = filepath.Dir(dir)
			continue
		}
		break
	}
	if err := validateDNSDirectory(dir, false, false, dnsCanonicalPath(path)); err != nil {
		return snapshot, err
	}
	file, info, err := dnsOpenRegular(path)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 128*1024+1))
	if err != nil || len(data) > 128*1024 {
		return snapshot, errors.New("DNS 文件无法读取或过大")
	}
	immutable, err := dnsReadImmutable(file)
	if err != nil {
		return snapshot, fmt.Errorf("无法检查 DNS 文件 immutable 属性: %w", err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	return dnsFileSnapshot{Exists: true, Data: data, Mode: uint32(info.Mode().Perm()), UID: int(stat.Uid), GID: int(stat.Gid), Immutable: immutable}, nil
}

func writeDNSFileSnapshotAtomic(path string, next dnsFileSnapshot) (retErr error) {
	uid, err := dnsExpectedUID(path)
	if err != nil {
		return err
	}
	if next.Exists && (next.UID != int(uid) || next.GID < 0 || next.Mode & ^uint32(0o777) != 0 || next.Mode&0o022 != 0 || len(next.Data) > 128*1024) {
		return errors.New("DNS 写入身份或内容无效")
	}
	if err := validateDNSDirectory(filepath.Dir(path), true, false, dnsCanonicalPath(path)); err != nil {
		return err
	}
	previous, err := readDNSFileSnapshot(path, true)
	if err != nil {
		return err
	}
	var original *os.File
	var originalInfo os.FileInfo
	if previous.Exists {
		original, originalInfo, err = dnsOpenRegular(path)
		if err != nil {
			return err
		}
		defer original.Close()
	}
	var temp *os.File
	if next.Exists {
		temp, err = os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".ols-dns-*")
		if err != nil {
			return err
		}
		defer func() { temp.Close(); os.Remove(temp.Name()) }()
		if err = temp.Chown(next.UID, next.GID); err != nil {
			return err
		}
		if err = temp.Chmod(os.FileMode(next.Mode)); err != nil {
			return err
		}
		if _, err = temp.Write(next.Data); err != nil {
			return err
		}
		if err = temp.Sync(); err != nil {
			return err
		}
	}
	// Recheck the current path before unlocking or replacing it. Hold its fd so
	// attribute changes never follow a swapped symlink to an unrelated target.
	actual, err := readDNSFileSnapshot(path, true)
	if err != nil || !sameDNSSnapshot(previous, actual) {
		return errors.New("写入前 DNS 配置发生变化，未覆盖")
	}
	if original != nil {
		atPath, err := os.Lstat(path)
		if err != nil || !os.SameFile(originalInfo, atPath) {
			return errors.New("DNS 文件身份发生变化，未覆盖")
		}
		if previous.Immutable {
			if err := dnsSetImmutable(original, false); err != nil {
				return fmt.Errorf("无法临时解除 DNS immutable 锁: %w", err)
			}
			defer func() {
				if retErr != nil {
					if current, e := os.Lstat(path); e == nil && os.SameFile(originalInfo, current) {
						if e = dnsSetImmutable(original, true); e != nil {
							retErr = errors.Join(retErr, fmt.Errorf("恢复原 DNS 文件锁失败: %w", e))
						}
					}
				}
			}()
		}
	}
	if next.Exists {
		if err = os.Rename(temp.Name(), path); err != nil {
			return err
		}
		if err = dnsSetImmutable(temp, next.Immutable); err != nil {
			return fmt.Errorf("恢复 DNS immutable 属性失败: %w", err)
		}
	} else if previous.Exists {
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err = directory.Sync(); err != nil {
		return err
	}
	actual, err = readDNSFileSnapshot(path, true)
	if err != nil || !sameDNSSnapshot(next, actual) {
		return errors.New("DNS 写入回读验证失败")
	}
	return nil
}

func acquireDNSManagerLock(path string) (func(), error) {
	uid, err := dnsExpectedUID(path)
	if err != nil {
		return nil, err
	}
	if err := ensureDNSPrivateDirectory(path, true); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil || stat.Uid != uid || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
		file.Close()
		return nil, errors.New("DNS 管理锁身份不安全")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("另一个 DNS 设置正在执行，请稍后重试")
	}
	var once sync.Once
	return func() { once.Do(func() { syscall.Flock(fd, syscall.LOCK_UN); file.Close() }) }, nil
}
