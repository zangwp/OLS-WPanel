package executor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

func TestObserveLiteSpeedCacheStatusSeparatesPluginPageAndRedisStates(t *testing.T) {
	root := t.TempDir()
	pluginDir := filepath.Join(root, "wp-content", "plugins", "litespeed-cache")
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "litespeed-cache.php"), []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	config := `<?php
define('LITESPEED_CONF__OBJECT', true);
define('LITESPEED_CONF__OBJECT__KIND', true);
define('LITESPEED_CONF__OBJECT__HOST', '127.0.0.1');
define('LITESPEED_CONF__OBJECT__PORT', 6379);
define('LITESPEED_CONF__OBJECT__DB_ID', 2);
`
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	site := &models.Website{WebRoot: root, SiteType: "wordpress", Status: models.StatusActive, LSCacheEnabled: true}
	status := observeLiteSpeedCacheStatus(site, func() (WPInventoryRunResult, error) {
		return WPInventoryRunResult{Inventory: WPInventory{Plugins: []WPInventoryPlugin{{
			File: liteSpeedCachePluginFile, Version: "7.9.1", Active: true,
		}}}}, nil
	})
	if status.PluginStatus != "active" || status.PluginVersion != "7.9.1" {
		t.Fatalf("plugin status = %#v", status)
	}
	if !status.PageCacheEnabled || !status.RedisObjectCacheConfigured {
		t.Fatalf("cache states = %#v", status)
	}
	if status.RedisHost != "127.0.0.1" || status.RedisPort != 6379 || status.RedisDatabase != 2 {
		t.Fatalf("redis endpoint = %#v", status)
	}
}

func TestObserveLiteSpeedCacheStatusDoesNotClaimRedisConnectionFromPartialConfig(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php\ndefine('LITESPEED_CONF__OBJECT', true);\n"), 0600); err != nil {
		t.Fatal(err)
	}
	site := &models.Website{WebRoot: root, SiteType: "wordpress", Status: models.StatusActive}
	status := observeLiteSpeedCacheStatus(site, func() (WPInventoryRunResult, error) {
		t.Fatal("inventory should not run when the official plugin is missing")
		return WPInventoryRunResult{}, nil
	})
	if status.PluginStatus != "not_installed" || status.RedisObjectCacheConfigured {
		t.Fatalf("unexpected status: %#v", status)
	}
}
