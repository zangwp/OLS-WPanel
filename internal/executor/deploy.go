package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func deployWordPress(ctx context.Context, cfg *config.Config, webRoot, tmpDir string) error {
	os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	zipPath := filepath.Join(tmpDir, "wordpress.zip")

	if err := downloadWP(ctx, cfg, zipPath); err != nil {
		return err
	}

	extractDir := filepath.Join(tmpDir, "wp_extract")
	if _, err := executeCommand("unzip", "-q", "-o", zipPath, "-d", extractDir); err != nil {
		return fmt.Errorf("解压失败: %w", err)
	}

	srcDir := extractDir
	if info, err := os.Stat(filepath.Join(extractDir, "wordpress")); err == nil && info.IsDir() {
		srcDir = filepath.Join(extractDir, "wordpress")
	}

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("读取WordPress文件失败: %w", err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(webRoot, entry.Name())
		if err := copyPath(srcPath, dstPath); err != nil {
			return fmt.Errorf("移动文件 %s 失败: %w", entry.Name(), err)
		}
	}

	return nil
}

func copyPath(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if srcInfo.IsDir() {
		return copyDir(src, dst)
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()

	if _, err := io.Copy(d, s); err != nil {
		return err
	}

	return os.Chmod(dst, 0644)
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if err := copyPath(srcPath, dstPath); err != nil {
			return err
		}
	}
	return nil
}

func downloadWP(ctx context.Context, cfg *config.Config, destPath string) error {
	_, _, err := AcquireCorePackage(ctx, cfg.Paths.WordPressPackage, destPath, "", defaultCorePackageRefresher(cfg))
	return err
}

func removeDefaultPlugins(webRoot string) {
	os.RemoveAll(filepath.Join(webRoot, "wp-content", "plugins", "akismet"))
	os.Remove(filepath.Join(webRoot, "wp-content", "plugins", "hello.php"))
}

func removeUnusedThemes(webRoot string) {
	for _, slug := range []string{"twentytwentyfour", "twentytwentythree"} {
		os.RemoveAll(filepath.Join(webRoot, "wp-content", "themes", slug))
	}
}

func installLiteSpeedCachePlugin(webRoot, systemUser string) error {
	const packageURL = "https://downloads.wordpress.org/plugin/litespeed-cache.7.9.1.zip"
	const packageSHA256 = "03ee3e4904dda9b8326fbedb89297fbd03a6c3a3bc77af4e0a94fad03e7a7556"
	destDir := filepath.Join(webRoot, "wp-content", "plugins")
	tmp, err := os.CreateTemp("", "ols-wpanel-litespeed-cache-*.zip")
	if err != nil {
		return fmt.Errorf("创建 LiteSpeed Cache 插件临时文件失败: %w", err)
	}
	zipPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(zipPath)
		return fmt.Errorf("关闭 LiteSpeed Cache 插件临时文件失败: %w", err)
	}
	defer os.Remove(zipPath)

	if _, err := executeCommand("wget", "--no-config", "-q", "--https-only", "--no-hsts", "-T", "30", "-O", zipPath, packageURL); err != nil {
		return fmt.Errorf("下载 LiteSpeed Cache 插件失败: %w", err)
	}
	info, err := os.Stat(zipPath)
	if err != nil || info.Size() <= 0 || info.Size() > 8*1024*1024 {
		return fmt.Errorf("LiteSpeed Cache 插件包大小异常")
	}
	pkg, err := os.ReadFile(zipPath)
	if err != nil {
		return fmt.Errorf("读取 LiteSpeed Cache 插件包失败: %w", err)
	}
	digest := sha256.Sum256(pkg)
	if hex.EncodeToString(digest[:]) != packageSHA256 {
		return fmt.Errorf("LiteSpeed Cache 插件包 SHA-256 校验失败")
	}
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("创建 WordPress 插件目录失败: %w", err)
	}
	if _, err := executeCommand("unzip", "-q", "-o", zipPath, "-d", destDir); err != nil {
		return fmt.Errorf("解压 LiteSpeed Cache 插件失败: %w", err)
	}
	pluginDir := filepath.Join(destDir, "litespeed-cache")
	if _, err := executeCommand("chown", "-R", siteOwner(systemUser), pluginDir); err != nil {
		return fmt.Errorf("设置 LiteSpeed Cache 插件权限失败: %w", err)
	}
	return writeLiteSpeedCacheActivator(webRoot, systemUser)
}

// EnsureLiteSpeedCachePlugin installs the official WordPress plugin only when
// it is missing. Existing installations are never overwritten; an activation
// helper is refreshed so the next WordPress bootstrap can safely activate it.
func EnsureLiteSpeedCachePlugin(webRoot, systemUser string) (bool, error) {
	mainFile := filepath.Join(webRoot, "wp-content", "plugins", "litespeed-cache", "litespeed-cache.php")
	info, err := os.Lstat(mainFile)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("LiteSpeed Cache 插件入口不是普通文件")
		}
		return false, writeLiteSpeedCacheActivator(webRoot, systemUser)
	case !os.IsNotExist(err):
		return false, fmt.Errorf("检查 LiteSpeed Cache 插件失败: %w", err)
	default:
		if err := installLiteSpeedCachePlugin(webRoot, systemUser); err != nil {
			return false, err
		}
		return true, nil
	}
}

func writeLiteSpeedCacheActivator(webRoot, systemUser string) error {
	muDir := filepath.Join(webRoot, "wp-content", "mu-plugins")
	if err := os.MkdirAll(muDir, 0755); err != nil {
		return fmt.Errorf("创建 WordPress MU 插件目录失败: %w", err)
	}
	activator := liteSpeedCacheActivator()
	activatorPath := filepath.Join(muDir, "ols-wpanel-lscache-activate.php")
	if err := os.WriteFile(activatorPath, []byte(activator), 0644); err != nil {
		return fmt.Errorf("写入 LiteSpeed Cache 自动启用器失败: %w", err)
	}
	if _, err := executeCommand("chown", "-R", siteOwner(systemUser), muDir); err != nil {
		return fmt.Errorf("设置 LiteSpeed Cache 自动启用器权限失败: %w", err)
	}
	return nil
}

func liteSpeedCacheActivator() string {
	return `<?php
/** OLS WPanel: activate the pinned LiteSpeed Cache plugin after WordPress setup. */
add_action('init', static function () {
    if (!function_exists('is_blog_installed') || !is_blog_installed()) {
        return;
    }
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    $plugin = 'litespeed-cache/litespeed-cache.php';
    if (is_plugin_active($plugin)) {
        @unlink(__FILE__);
        return;
    }
    $result = activate_plugin($plugin, '', false, true);
    if (is_wp_error($result)) {
        error_log('OLS WPanel could not activate LiteSpeed Cache: ' . $result->get_error_message());
        return;
    }
    @unlink(__FILE__);
}, 1);
`
}
