package executor

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type liteSpeedCacheInstallService struct {
	versions func(context.Context, string, string) (string, string, error)
	acquire  func(context.Context, string, string) (liteSpeedCachePackage, error)
	publish  func(context.Context, string, string, string, string) error
	activate func(string, string) error
}

func (s liteSpeedCacheInstallService) ensure(ctx context.Context, webRoot, systemUser, phpBranch string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	pluginDir, err := managedWordPressPath(webRoot, "wp-content", "plugins", "litespeed-cache")
	if err != nil {
		return false, fmt.Errorf("检查 LiteSpeed Cache 插件目录失败: %w", err)
	}
	if info, err := os.Lstat(pluginDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("LiteSpeed Cache 插件路径不是普通目录")
		}
		main, err := os.Lstat(filepath.Join(pluginDir, "litespeed-cache.php"))
		if err != nil || !main.Mode().IsRegular() {
			return false, fmt.Errorf("已有 LiteSpeed Cache 目录不完整，请先检查插件文件")
		}
		return false, s.activate(webRoot, systemUser)
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("检查 LiteSpeed Cache 插件失败: %w", err)
	}
	// Existing sites created before explicit runtime selection used PHP 8.3.
	// Fresh-site callers always pass the branch resolved from their selection.
	if strings.TrimSpace(phpBranch) == "" {
		phpBranch = "8.3"
	}
	wpVersion, phpVersion, err := s.versions(ctx, webRoot, phpBranch)
	if err != nil {
		return false, fmt.Errorf("检查 LiteSpeed Cache 兼容环境失败: %w", err)
	}
	pkg, err := s.acquire(ctx, wpVersion, phpVersion)
	if err != nil {
		return false, err
	}
	defer os.Remove(pkg.Path)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := s.publish(ctx, pkg.Path, pkg.SHA256, webRoot, systemUser); err != nil {
		return false, fmt.Errorf("安装 LiteSpeed Cache 插件失败: %w", err)
	}
	log.Printf("LiteSpeed Cache installed version=%s verified_fallback=%t", pkg.Version, pkg.Fallback)
	return true, s.activate(webRoot, systemUser)
}

// Read only the core version file and the selected site's trusted PHP binary.
// WordPress and downloaded plugin PHP are never executed during selection.
func readLiteSpeedCacheSiteVersions(ctx context.Context, webRoot, phpBranch string) (string, string, error) {
	versionFile, err := managedWordPressPath(webRoot, "wp-includes", "version.php")
	if err != nil {
		return "", "", err
	}
	root, err := os.OpenRoot(webRoot)
	if err != nil {
		return "", "", err
	}
	defer root.Close()
	info, err := root.Lstat(filepath.Join("wp-includes", "version.php"))
	if err != nil || !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("WordPress version file is unavailable or unsafe")
	}
	f, err := root.Open(filepath.Join("wp-includes", "version.php"))
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() > 128<<10 {
		return "", "", fmt.Errorf("WordPress version file changed or exceeds the size limit: %s", versionFile)
	}
	body, err := io.ReadAll(io.LimitReader(liteSpeedCacheContextReader{ctx, f}, (128<<10)+1))
	if err != nil {
		return "", "", fmt.Errorf("read WordPress version file: %w", err)
	}
	if len(body) > 128<<10 {
		return "", "", fmt.Errorf("could not read bounded WordPress version file")
	}
	wpVersion, _, err := parseWordPressVersionFile(string(body))
	if err != nil {
		return "", "", err
	}
	runtime, err := ResolveLSPHPRuntime(phpBranch, true)
	if err != nil {
		return "", "", err
	}
	php, err := validateInventoryBinary(runtime.CLIBinary, filepath.Dir(runtime.CLIBinary), 0, 0)
	if err != nil {
		return "", "", err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(probeCtx, php, "-n", "-r", "echo PHP_VERSION;").Output()
	if err != nil {
		return "", "", fmt.Errorf("read selected PHP version: %w", err)
	}
	return wpVersion, strings.TrimSpace(string(out)), nil
}
