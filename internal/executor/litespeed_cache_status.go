package executor

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

const liteSpeedCachePluginFile = "litespeed-cache/litespeed-cache.php"

type LiteSpeedCacheRuntimeStatus struct {
	StatusKnown                bool   `json:"status_known"`
	OverridesPresent           bool   `json:"overrides_present"`
	PluginStatus               string `json:"plugin_status"`
	PluginVersion              string `json:"plugin_version,omitempty"`
	PageCacheEnabled           bool   `json:"page_cache_enabled"`
	ServerPageCacheEnabled     bool   `json:"server_page_cache_enabled"`
	RedisObjectCacheConfigured bool   `json:"redis_object_cache_configured"`
	RedisHost                  string `json:"redis_host,omitempty"`
	RedisPort                  int    `json:"redis_port,omitempty"`
	RedisDatabase              int    `json:"redis_database"`
}

func ObserveLiteSpeedCacheStatus(ctx context.Context, cfg *config.Config, site *models.Website) LiteSpeedCacheRuntimeStatus {
	return observeLiteSpeedCacheStatus(site, func() (WPInventoryRunResult, error) {
		runner, err := NewWPInventoryRunner()
		if err != nil {
			return WPInventoryRunResult{}, err
		}
		return runner.Collect(ctx, cfg, site, false)
	})
}

func observeLiteSpeedCacheStatus(site *models.Website, collect func() (WPInventoryRunResult, error)) LiteSpeedCacheRuntimeStatus {
	status := LiteSpeedCacheRuntimeStatus{PluginStatus: "unknown"}
	if site == nil {
		return status
	}
	content, _ := os.ReadFile(filepath.Join(site.WebRoot, "wp-config.php"))
	status.OverridesPresent = wpConfigBoolConstant(string(content), "LITESPEED_CONF") && strings.Contains(string(content), "LITESPEED_CONF__OBJECT")
	status.ServerPageCacheEnabled = site.LSCacheEnabled
	if site.SiteType != "wordpress" || site.Status != models.StatusActive {
		return status
	}
	info, err := os.Lstat(filepath.Join(site.WebRoot, "wp-content", "plugins", liteSpeedCachePluginFile))
	if os.IsNotExist(err) {
		status.PluginStatus = "not_installed"
		status.StatusKnown = true
		status.PageCacheEnabled = false
		status.RedisObjectCacheConfigured = false
		return status
	}
	if err != nil || !info.Mode().IsRegular() {
		return status
	}
	result, err := collect()
	if err != nil || result.Inventory.WordPress.Multisite {
		return status
	}
	status.PluginStatus = "inactive"
	for _, plugin := range result.Inventory.Plugins {
		if plugin.File != liteSpeedCachePluginFile {
			continue
		}
		status.PluginVersion = plugin.Version
		if plugin.Active || plugin.NetworkActive {
			status.PluginStatus = "active"
		}
		break
	}
	if result.Inventory.Cache != nil {
		cache := result.Inventory.Cache
		status.StatusKnown = true
		active := status.PluginStatus == "active"
		status.PageCacheEnabled = active && cache.PageEnabled
		status.RedisObjectCacheConfigured = active && cache.ObjectEnabled
		status.RedisHost, status.RedisPort, status.RedisDatabase = cache.Host, cache.Port, cache.Database
	}
	return status
}

func wpConfigBoolConstant(content, name string) bool {
	re := regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*true\s*\)\s*;`)
	return re.MatchString(content)
}
