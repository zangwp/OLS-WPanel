package executor

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const opcacheClearTimeout = 30 * time.Second

var opcacheCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return output, err
}

// ClearOPcache requests replacement of the server's PHP workers. Each site's
// PHP process group can have its own cache. Detached workers survive an OLS
// restart, so the official server-level restart marker is required as well.
// Detached pools rebuild their caches when OLS next needs that PHP handler;
// a successful return does not claim that every cache has already been cleared.
// https://docs.openlitespeed.org/config/php/detached/
func ClearOPcache() error {
	ctx, cancel := context.WithTimeout(context.Background(), opcacheClearTimeout)
	defer cancel()
	return requestOPcacheClear(ctx, currentOLSRuntimePaths(), opcacheCommand, writeOPcacheRestartMarker)
}

func requestOPcacheClear(ctx context.Context, paths olsRuntimePaths, run func(context.Context, string, ...string) ([]byte, error), mark func(string) error) error {
	if out, err := run(ctx, paths.binary, "-t"); err != nil {
		return fmt.Errorf("OpenLiteSpeed 配置检查失败: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := mark(paths.root); err != nil {
		return fmt.Errorf("请求重启脱离运行的 PHP 进程失败: %w", err)
	}
	out, err := run(ctx, "systemctl", "restart", "lshttpd")
	if err != nil {
		// The marker is intentionally retained: some detached handlers may
		// already have observed it, so pretending to roll it back is unsafe.
		return fmt.Errorf("PHP 重启标记已写入，但重启 OpenLiteSpeed 失败: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func writeOPcacheRestartMarker(serverRoot string) error {
	if !filepath.IsAbs(serverRoot) {
		return fmt.Errorf("OpenLiteSpeed root must be an absolute directory")
	}
	info, err := os.Lstat(serverRoot)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe OpenLiteSpeed root")
	}
	root, err := os.OpenRoot(serverRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	// Work only inside existing server directories. Root operations anchor
	// the writes to this directory tree and cannot follow a link outside it.
	for _, directory := range []string{"admin", filepath.Join("admin", "tmp")} {
		info, err := root.Lstat(directory)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe OpenLiteSpeed admin directory")
		}
	}
	directory, err := root.OpenRoot(filepath.Join("admin", "tmp"))
	if err != nil {
		return err
	}
	defer directory.Close()
	const marker = ".lsphp_restart.txt"
	if info, err := directory.Lstat(marker); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsafe PHP restart marker")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	name := ".ols-wpanel-opcache-" + rand.Text() + ".tmp"
	file, err := directory.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer directory.Remove(name)
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Replacing a marker, rather than touching it, never follows a preexisting
	// symlink or changes another file through a hard link.
	return directory.Rename(name, marker)
}
