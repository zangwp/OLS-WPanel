package executor

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func deployWordPress(ctx context.Context, cfg *config.Config, webRoot, tmpDir string) error {
	_, err := deployWordPressPackage(ctx, cfg, webRoot, tmpDir)
	return err
}

// The create-only wrapper passes the provenance of the actual deployed ZIP
// to the deferred cleanup. Reinstall/import/restore do not use this wrapper.
func deployNewWordPress(ctx context.Context, cfg *config.Config, webRoot, tmpDir string) error {
	report, err := deployWordPressPackage(ctx, cfg, webRoot, tmpDir)
	if err != nil {
		return err
	}
	// OLS reads the root .htaccess while loading this new vhost, before the
	// browser installer later saves WordPress's permalink configuration.
	if err := prepareNewWordPressRewrite(webRoot); err != nil {
		return err
	}
	return prepareNewWordPressDefaults(webRoot, report.OfficialDownload)
}

func deployWordPressPackage(ctx context.Context, cfg *config.Config, webRoot, tmpDir string) (WPPackageReport, error) {
	os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return WPPackageReport{}, fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	zipPath := filepath.Join(tmpDir, "wordpress.zip")

	report, _, err := AcquireCorePackage(ctx, cfg.Paths.WordPressPackage, zipPath, "", defaultCorePackageRefresher(cfg))
	if err != nil {
		return WPPackageReport{}, err
	}

	extractDir := filepath.Join(tmpDir, "wp_extract")
	if _, err := executeCommand("unzip", "-q", "-o", zipPath, "-d", extractDir); err != nil {
		return WPPackageReport{}, fmt.Errorf("解压失败: %w", err)
	}

	srcDir := extractDir
	if info, err := os.Stat(filepath.Join(extractDir, "wordpress")); err == nil && info.IsDir() {
		srcDir = filepath.Join(extractDir, "wordpress")
	}

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return WPPackageReport{}, fmt.Errorf("读取WordPress文件失败: %w", err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(webRoot, entry.Name())
		if err := copyPath(srcPath, dstPath); err != nil {
			return WPPackageReport{}, fmt.Errorf("移动文件 %s 失败: %w", entry.Name(), err)
		}
	}

	return report, nil
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

func installLiteSpeedCachePlugin(ctx context.Context, webRoot, systemUser, phpVersion string) error {
	_, err := EnsureLiteSpeedCachePlugin(ctx, webRoot, systemUser, phpVersion)
	return err
}

// EnsureLiteSpeedCachePlugin installs the official WordPress plugin only when
// it is missing. Existing installations are never overwritten; an activation
// helper is refreshed so the next WordPress bootstrap can safely activate it.
func EnsureLiteSpeedCachePlugin(ctx context.Context, webRoot, systemUser, phpVersion string) (bool, error) {
	service := liteSpeedCacheInstallService{
		versions: readLiteSpeedCacheSiteVersions,
		acquire:  acquireLiteSpeedCachePackage,
		publish:  publishLiteSpeedCachePackage,
		activate: writeLiteSpeedCacheActivator,
	}
	return service.ensure(ctx, webRoot, systemUser, phpVersion)
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
/** OLS WPanel: activate the verified LiteSpeed Cache plugin after WordPress setup. */
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
