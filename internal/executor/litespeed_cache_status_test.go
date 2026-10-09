package executor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

func cacheStatusTestSite(t *testing.T) *models.Website {
	t.Helper()
	root := t.TempDir()
	pluginDir := filepath.Join(root, "wp-content", "plugins", "litespeed-cache")
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "litespeed-cache.php"), []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	return &models.Website{WebRoot: root, SiteType: "wordpress", Status: models.StatusActive}
}

func TestObserveLiteSpeedCacheStatusSeparatesPluginPageAndRedisStates(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		server, page, redis, active bool
	}{
		{"WordPress settings match screenshot with server off", false, true, true, true},
		{"plugin off with server on", true, false, false, true},
		{"Redis independent of page cache", true, false, true, true},
		{"page cache independent of Redis", true, true, false, true},
		{"inactive plugin ignores stored enabled settings", true, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := cacheStatusTestSite(t)
			site.LSCacheEnabled = tc.server
			// Old overrides must not supersede the current plugin inventory.
			if err := os.WriteFile(filepath.Join(site.WebRoot, "wp-config.php"), []byte("<?php\ndefine('LITESPEED_CONF__OBJECT__HOST', 'old-host');\n"), 0600); err != nil {
				t.Fatal(err)
			}
			status := observeLiteSpeedCacheStatus(site, func() (WPInventoryRunResult, error) {
				return WPInventoryRunResult{Inventory: WPInventory{
					Plugins: []WPInventoryPlugin{{File: liteSpeedCachePluginFile, Version: "7.9.1", Active: tc.active}},
					Cache:   &WPInventoryCache{PageEnabled: tc.page, ObjectEnabled: tc.redis, Host: "localhost", Port: 6379, Database: 0},
				}}, nil
			})
			wantPlugin := "inactive"
			if tc.active {
				wantPlugin = "active"
			}
			if !status.StatusKnown || status.PluginStatus != wantPlugin || status.PluginVersion != "7.9.1" {
				t.Fatalf("plugin status = %#v", status)
			}
			if status.ServerPageCacheEnabled != tc.server || status.PageCacheEnabled != (tc.active && tc.page) || status.RedisObjectCacheConfigured != (tc.active && tc.redis) {
				t.Fatalf("independent cache states = %#v", status)
			}
			if status.RedisHost != "localhost" || status.RedisPort != 6379 || status.RedisDatabase != 0 || status.OverridesPresent {
				t.Fatalf("current endpoint / inert overrides = %#v", status)
			}
		})
	}
}

func TestObserveLiteSpeedCacheStatusDoesNotGuessWhenCollectionFails(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result WPInventoryRunResult
		err    error
	}{
		{name: "collector failure", err: errors.New("bootstrap failed")},
		{name: "missing cache result", result: WPInventoryRunResult{Inventory: WPInventory{Plugins: []WPInventoryPlugin{{File: liteSpeedCachePluginFile, Active: true}}}}},
		{name: "unsupported multisite", result: WPInventoryRunResult{Inventory: WPInventory{WordPress: WPInventoryWordPress{Multisite: true}, Cache: &WPInventoryCache{PageEnabled: true, ObjectEnabled: true}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := cacheStatusTestSite(t)
			site.LSCacheEnabled = true
			if err := os.WriteFile(filepath.Join(site.WebRoot, "wp-config.php"), []byte("<?php\ndefine('LITESPEED_CONF', true);\ndefine('LITESPEED_CONF__OBJECT', true);\n"), 0600); err != nil {
				t.Fatal(err)
			}
			status := observeLiteSpeedCacheStatus(site, func() (WPInventoryRunResult, error) { return tc.result, tc.err })
			if status.StatusKnown || status.PageCacheEnabled || status.RedisObjectCacheConfigured || status.RedisHost != "" || status.RedisPort != 0 {
				t.Fatalf("failed collection must not report guessed state: %#v", status)
			}
			if !status.ServerPageCacheEnabled {
				t.Fatalf("stored server setting was lost: %#v", status)
			}
		})
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
	if !status.StatusKnown || status.PluginStatus != "not_installed" || status.RedisObjectCacheConfigured || status.PageCacheEnabled {
		t.Fatalf("unexpected status: %#v", status)
	}
}
