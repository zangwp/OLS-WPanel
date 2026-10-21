//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// publishLiteSpeedCachePackage installs into a new directory. The caller has
// already checked the official package identity and compatibility; extraction
// verifies the exact archive digest again before any plugin can become live.
func publishLiteSpeedCachePackage(ctx context.Context, archivePath, expectedSHA256, webRoot, systemUser string) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !wpInventoryUserPattern.MatchString(systemUser) {
		return errors.New("invalid LiteSpeed Cache system user")
	}
	plugins, err := openLiteSpeedCachePluginParent(webRoot, true)
	if err != nil {
		return fmt.Errorf("open WordPress plugin directory: %w", err)
	}
	defer plugins.Close()
	if err := requireLiteSpeedCacheAbsent(plugins); err != nil {
		return err
	}

	// Extract outside the site-owned tree. Its owner cannot exchange an ancestor
	// underneath the archive extractor, and a second, private stage below the
	// held plugin directory keeps the final rename on the same filesystem.
	work, err := os.MkdirTemp("", "ols-wpanel-lscache-extract-*")
	if err != nil {
		return fmt.Errorf("create LiteSpeed Cache extraction directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(work); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("clean LiteSpeed Cache extraction directory: %w", err))
		}
	}()
	extracted, err := ExtractZIPToNewStaging(ctx, ZIPExtractRequest{
		ArchivePath: archivePath, StagingParent: work, ExpectedSHA256: expectedSHA256,
		Policy: WordPressFullZIPPolicy(),
	})
	if err != nil {
		return fmt.Errorf("extract LiteSpeed Cache package: %w", err)
	}
	source, err := os.OpenRoot(extracted.StagingPath)
	if err != nil {
		return fmt.Errorf("open extracted LiteSpeed Cache package: %w", err)
	}
	defer source.Close()
	entries, err := os.ReadDir(extracted.StagingPath)
	if err != nil || len(entries) != 1 || entries[0].Name() != "litespeed-cache" || !entries[0].IsDir() {
		return errors.New("invalid LiteSpeed Cache package root")
	}
	main, err := source.Lstat("litespeed-cache/litespeed-cache.php")
	if err != nil || !main.Mode().IsRegular() {
		return errors.New("invalid LiteSpeed Cache plugin entry")
	}
	parentPath := fmt.Sprintf("/proc/self/fd/%d", plugins.Fd())
	stagePath, err := os.MkdirTemp(parentPath, ".ols-wpanel-lscache-*")
	if err != nil {
		return fmt.Errorf("create LiteSpeed Cache publication directory: %w", err)
	}
	stageName := filepath.Base(stagePath)
	stageFD, err := unix.Openat(int(plugins.Fd()), stageName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Unlinkat(int(plugins.Fd()), stageName, unix.AT_REMOVEDIR)
		return fmt.Errorf("open LiteSpeed Cache publication directory: %w", err)
	}
	stage := os.NewFile(uintptr(stageFD), stagePath)
	defer stage.Close()
	stageRoot, err := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", stage.Fd()))
	if err != nil {
		_ = unix.Unlinkat(int(plugins.Fd()), stageName, unix.AT_REMOVEDIR)
		return fmt.Errorf("open LiteSpeed Cache publication root: %w", err)
	}
	defer stageRoot.Close()
	defer func() {
		if err := cleanLiteSpeedCachePublicationStage(plugins, stage, stageRoot, stageName); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("clean LiteSpeed Cache publication directory: %w", err))
		}
	}()
	if err := copyLiteSpeedCacheStagedTree(ctx, source, stageRoot, "litespeed-cache"); err != nil {
		return fmt.Errorf("prepare LiteSpeed Cache plugin files: %w", err)
	}
	if err := sameLiteSpeedCachePluginParent(webRoot, plugins); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The child resolves this process's held stage descriptor, rather than a
	// site-controlled pathname. The enclosing stage remains private and owned by
	// the panel while the plugin itself receives its website owner.
	ownerPath := fmt.Sprintf("/proc/%d/fd/%d/litespeed-cache", os.Getpid(), stage.Fd())
	if _, err := executeCommand("chown", "-h", "-R", "--", siteOwner(systemUser), ownerPath); err != nil {
		return fmt.Errorf("set LiteSpeed Cache plugin ownership: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sameLiteSpeedCachePluginParent(webRoot, plugins); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Renameat2(int(stage.Fd()), "litespeed-cache", int(plugins.Fd()), "litespeed-cache", unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish LiteSpeed Cache without replacing existing files: %w", err)
	}
	return nil
}

func openLiteSpeedCachePluginParent(webRoot string, create bool) (*os.File, error) {
	if !filepath.IsAbs(webRoot) || filepath.Clean(webRoot) != webRoot || webRoot == "/" {
		return nil, errors.New("invalid WordPress root")
	}
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(rootFD), "/")
	for _, part := range strings.Split(strings.TrimPrefix(webRoot, "/"), "/") {
		next, err := openLiteSpeedCacheChildDirectory(current, part, false)
		current.Close()
		if err != nil {
			return nil, err
		}
		current = next
	}
	for _, part := range []string{"wp-content", "plugins"} {
		next, err := openLiteSpeedCacheChildDirectory(current, part, create)
		current.Close()
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

func openLiteSpeedCacheChildDirectory(parent *os.File, name string, create bool) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if create && errors.Is(err, unix.ENOENT) {
		if mkdirErr := unix.Mkdirat(int(parent.Fd()), name, 0755); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
			return nil, mkdirErr
		}
		fd, err = unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("directory %s must exist without symbolic links: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

func requireLiteSpeedCacheAbsent(plugins *os.File) error {
	var stat unix.Stat_t
	err := unix.Fstatat(int(plugins.Fd()), "litespeed-cache", &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return fmt.Errorf("LiteSpeed Cache plugin directory already exists: %w", os.ErrExist)
	}
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect LiteSpeed Cache plugin directory: %w", err)
	}
	return nil
}

func sameLiteSpeedCachePluginParent(webRoot string, expected *os.File) error {
	actual, err := openLiteSpeedCachePluginParent(webRoot, false)
	if err != nil {
		return fmt.Errorf("WordPress plugin directory changed during installation: %w", err)
	}
	defer actual.Close()
	want, wantErr := expected.Stat()
	got, gotErr := actual.Stat()
	if wantErr != nil || gotErr != nil || !os.SameFile(want, got) {
		return errors.New("WordPress plugin directory changed during installation")
	}
	return nil
}

func copyLiteSpeedCacheStagedTree(ctx context.Context, source, target *os.Root, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := source.Lstat(name)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := target.Mkdir(name, 0755); err != nil {
			return err
		}
		if err := target.Chmod(name, 0755); err != nil {
			return err
		}
		dir, err := source.Open(name)
		if err != nil {
			return err
		}
		entries, readErr := dir.ReadDir(-1)
		closeErr := dir.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		for _, entry := range entries {
			if err := copyLiteSpeedCacheStagedTree(ctx, source, target, filepath.Join(name, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return errors.New("LiteSpeed Cache package contains a nonregular file")
	}
	src, err := source.Open(name)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := target.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, copyErr := copyWithContext(ctx, dst, src)
	chmodErr := dst.Chmod(0644)
	closeErr := dst.Close()
	return errors.Join(copyErr, chmodErr, closeErr)
}

func cleanLiteSpeedCachePublicationStage(plugins, stage *os.File, root *os.Root, name string) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		if err := root.RemoveAll(entry.Name()); err != nil {
			return err
		}
	}
	var held, named unix.Stat_t
	if err := unix.Fstat(int(stage.Fd()), &held); err != nil {
		return err
	}
	if err := unix.Fstatat(int(plugins.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if held.Dev != named.Dev || held.Ino != named.Ino {
		return errors.New("publication directory was moved; replacement was preserved")
	}
	return unix.Unlinkat(int(plugins.Fd()), name, unix.AT_REMOVEDIR)
}
