package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// RetireOptimizerOwned requires the normal site operation lock. It preserves
// cache options and archives code outside the site's public directory.
func RetireOptimizerOwned(ctx context.Context, cfg *config.Config, site *models.Website) (string, error) {
	if site == nil || site.SiteType != "wordpress" {
		return "", errors.New("仅支持 WordPress 网站")
	}
	if site.FileLockEnabled {
		return "", errors.New("请先在面板关闭文件保护，迁移完成后重新启用")
	}
	source, err := managedWordPressPath(site.WebRoot, "wp-content", "plugins", pluginDirName)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(source)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("旧插件目录无效，未迁移")
	}
	if _, err := managedWordPressPath(site.WebRoot, "wp-config.php"); err != nil {
		return "", err
	}
	// Install equivalent panel-owned policy before disabling the legacy code.
	rollback, err := ApplyWPOptimizationsReversible(site.WebRoot, WPOptimizations{
		DisableUpdates: site.DisableWPUpdates, DisableFileEditing: site.DisableFileEditing,
		DisableApplicationPasswords: site.DisableApplicationPasswords,
		WPDebug:                     site.WPDebugEnabled, WPDebugDisplay: WPDebugDisplayEnabled(site.WebRoot),
		WPPostRevisions: site.WPPostRevisions, WPMemoryLimit: site.WPMemoryLimit,
	})
	if err != nil {
		return "", err
	}
	runner, err := NewWPInventoryRunner()
	if err != nil {
		_ = rollback()
		return "", err
	}
	runner.retireOptimizer = true
	result, err := runner.Collect(ctx, cfg, site, false)
	if err != nil {
		// The runner may have deactivated the plugin before output failed.
		// Keep native protection installed in this uncertain state.
		return "", err
	}
	if result.Inventory.WordPress.Multisite {
		return "", errors.New("暂不支持多站点迁移")
	}
	for _, plugin := range result.Inventory.Plugins {
		if plugin.File == pluginDirName+"/"+pluginDirName+".php" && (plugin.Active || plugin.NetworkActive) {
			return "", errors.New("旧插件仍处于启用状态，未移动文件")
		}
	}
	// The archive is private, with a unique destination; never delete a website.
	archiveDir := filepath.Join("/var/ols-wpanel/retired-plugins", fmt.Sprint(site.ID))
	for _, parent := range []string{"/var", "/var/ols-wpanel", "/var/ols-wpanel/retired-plugins", archiveDir} {
		if info, err := os.Lstat(parent); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return "", errors.New("归档路径包含链接或无效目录；插件已停用，未移动文件")
		} else if err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	if err := os.MkdirAll(archiveDir, 0700); err != nil {
		return "", fmt.Errorf("插件已停用，但创建归档目录失败: %w", err)
	}
	archive := filepath.Join(archiveDir, time.Now().UTC().Format("20060102T150405.000000000"))
	if err := os.Rename(source, archive); err != nil {
		return "", fmt.Errorf("插件已停用，但归档失败；可从 WordPress 插件页删除旧插件: %w", err)
	}
	if _, err := database.GetDB().Exec(`UPDATE websites SET plugin_api_key='', ssl_export_enabled=0 WHERE id=?`, site.ID); err != nil {
		return "", fmt.Errorf("插件已归档，但撤销旧插件权限失败: %w", err)
	}
	recordOperationLog("optimizer_retire", site.Domain, "success", "archived="+archive)
	return archive, nil
}
