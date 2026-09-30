package executor

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/zangwp/OLS-WPanel/config"
	"github.com/zangwp/OLS-WPanel/models"
)

const liteSpeedCachePluginFile = "litespeed-cache/litespeed-cache.php"

type LiteSpeedCacheRuntimeStatus struct {
	PluginStatus               string `json:"plugin_status"`
	PluginVersion              string `json:"plugin_version,omitempty"`
	PageCacheEnabled           bool   `json:"page_cache_enabled"`
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
	status.PageCacheEnabled = site.LSCacheEnabled
	status.RedisHost, status.RedisPort, status.RedisDatabase, status.RedisObjectCacheConfigured = readLiteSpeedObjectCacheConfig(site.WebRoot)
	if site.SiteType != "wordpress" || site.Status != models.StatusActive {
		return status
	}
	info, err := os.Lstat(filepath.Join(site.WebRoot, "wp-content", "plugins", liteSpeedCachePluginFile))
	if os.IsNotExist(err) {
		status.PluginStatus = "not_installed"
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
	return status
}

func readLiteSpeedObjectCacheConfig(webRoot string) (string, int, int, bool) {
	data, err := os.ReadFile(filepath.Join(webRoot, "wp-config.php"))
	if err != nil {
		return "", 0, 0, false
	}
	content := string(data)
	host := extractWPConfigStringConstant(content, "LITESPEED_CONF__OBJECT__HOST")
	port := extractWPConfigIntConstant(content, "LITESPEED_CONF__OBJECT__PORT")
	database := extractWPConfigIntConstant(content, "LITESPEED_CONF__OBJECT__DB_ID")
	configured := wpConfigBoolConstant(content, "LITESPEED_CONF__OBJECT") &&
		wpConfigBoolConstant(content, "LITESPEED_CONF__OBJECT__KIND") && host != "" && port > 0
	return host, port, database, configured
}

func wpConfigBoolConstant(content, name string) bool {
	re := regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*true\s*\)\s*;`)
	return re.MatchString(content)
}

func extractWPConfigIntConstant(content, name string) int {
	re := regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*([0-9]+)\s*\)\s*;`)
	matches := re.FindStringSubmatch(content)
	if len(matches) != 2 {
		return 0
	}
	value, _ := strconv.Atoi(strings.TrimSpace(matches[1]))
	return value
}
