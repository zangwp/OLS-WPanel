package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

// installStubOpenLiteSpeed keeps the compatibility-named regeneration helpers isolated
// from a host OpenLiteSpeed installation.
func installStubOpenLiteSpeed(t *testing.T) {
	t.Helper()
	oldRunOLSCommand := runOLSCommand
	runOLSCommand = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runOLSCommand = oldRunOLSCommand })
}

func TestUpdateSiteLiteSpeedCachePublishesBeforeSuccess(t *testing.T) {
	openTestDB(t)
	result, err := database.GetDB().Exec(`INSERT INTO websites
		(name,domain,status,site_type,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path,litespeed_cache_enabled,litespeed_cache_ttl)
		VALUES ('site','cache.test','active','wordpress','nobody','/tmp/cache.test','','','','','','0',300)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()

	oldRegenerate := regenerateSiteOLSForCache
	regenerateSiteOLSForCache = func(siteID int) error {
		if siteID != int(id) {
			t.Fatalf("siteID=%d", siteID)
		}
		return nil
	}
	t.Cleanup(func() { regenerateSiteOLSForCache = oldRegenerate })

	if err := UpdateSiteLiteSpeedCache(int(id), 1, 600); err != nil {
		t.Fatal(err)
	}
	var enabled, ttl int
	if err := database.GetDB().QueryRow(`SELECT litespeed_cache_enabled,litespeed_cache_ttl FROM websites WHERE id=?`, id).Scan(&enabled, &ttl); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 || ttl != 600 {
		t.Fatalf("cache settings=(%d,%d)", enabled, ttl)
	}
}

func TestUpdateSiteLiteSpeedCacheRestoresOldSettingsOnPublishFailure(t *testing.T) {
	openTestDB(t)
	result, err := database.GetDB().Exec(`INSERT INTO websites
		(name,domain,status,site_type,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path,litespeed_cache_enabled,litespeed_cache_ttl)
		VALUES ('site','cache.test','active','wordpress','nobody','/tmp/cache.test','','','','','','1',300)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()

	oldRegenerate := regenerateSiteOLSForCache
	calls := 0
	regenerateSiteOLSForCache = func(int) error {
		calls++
		if calls == 1 {
			return errors.New("openlitespeed test failed")
		}
		return nil
	}
	t.Cleanup(func() { regenerateSiteOLSForCache = oldRegenerate })

	if err := UpdateSiteLiteSpeedCache(int(id), 0, 900); err == nil || !strings.Contains(err.Error(), "已恢复") {
		t.Fatalf("error=%v", err)
	}
	var enabled, ttl int
	if err := database.GetDB().QueryRow(`SELECT litespeed_cache_enabled,litespeed_cache_ttl FROM websites WHERE id=?`, id).Scan(&enabled, &ttl); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 || ttl != 300 || calls != 2 {
		t.Fatalf("cache settings=(%d,%d) calls=%d", enabled, ttl, calls)
	}
}

func TestClearSiteCacheRestoresOldKeyOnPublishFailure(t *testing.T) {
	openTestDB(t)
	result, err := database.GetDB().Exec(`INSERT INTO websites
		(name,domain,status,site_type,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path,litespeed_cache_key)
		VALUES ('site','cache.test','active','wordpress','nobody','/tmp/cache.test','','','','','','old-key')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()

	oldRegenerate := regenerateSiteOLSForCache
	calls := 0
	regenerateSiteOLSForCache = func(int) error {
		calls++
		if calls == 1 {
			return errors.New("reload failed")
		}
		return nil
	}
	t.Cleanup(func() { regenerateSiteOLSForCache = oldRegenerate })

	if err := ClearSiteCache(int(id)); err == nil || !strings.Contains(err.Error(), "已恢复") {
		t.Fatalf("error=%v", err)
	}
	var key string
	if err := database.GetDB().QueryRow(`SELECT litespeed_cache_key FROM websites WHERE id=?`, id).Scan(&key); err != nil {
		t.Fatal(err)
	}
	if key != "old-key" || calls != 2 {
		t.Fatalf("key=%q calls=%d", key, calls)
	}
}

func TestCompanionAutomaticUpgradeRequiresExistingPluginAndActiveSite(t *testing.T) {
	openTestDB(t)
	root := t.TempDir()
	pluginsDir := filepath.Join(root, "wp-content", "plugins")
	if err := os.MkdirAll(pluginsDir, 0755); err != nil {
		t.Fatal(err)
	}
	result, err := database.GetDB().Exec(`INSERT INTO websites
		(name,domain,status,site_type,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path,plugin_api_key)
		VALUES ('site','site.test','active','wordpress','nobody',?,'','','','','','managed-key')`, root)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"ols-wpanel-optimizer.php": []byte("new")}
	changed, err := deploySiteCompanionOwned(int(id), files, "new-version", true)
	if err != nil || changed {
		t.Fatalf("deleted plugin auto deployment = %v, %v", changed, err)
	}
	if _, err := os.Lstat(filepath.Join(pluginsDir, pluginDirName)); !os.IsNotExist(err) {
		t.Fatalf("deleted plugin was installed again: %v", err)
	}

	pluginDir := filepath.Join(pluginsDir, pluginDirName)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	mainFile := filepath.Join(pluginDir, pluginDirName+".php")
	target := filepath.Join(t.TempDir(), "plugin.php")
	if err := os.WriteFile(target, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, mainFile); err != nil {
		t.Fatal(err)
	}
	if changed, err := deploySiteCompanionOwned(int(id), files, "new-version", true); err == nil || changed {
		t.Fatalf("symlink plugin auto deployment = %v, %v", changed, err)
	}
	if err := os.Remove(mainFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mainFile, 0755); err != nil {
		t.Fatal(err)
	}
	if changed, err := deploySiteCompanionOwned(int(id), files, "new-version", true); err == nil || changed {
		t.Fatalf("directory plugin entry auto deployment = %v, %v", changed, err)
	}
	if err := os.Remove(mainFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainFile, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"paused", "migrated"} {
		if _, err := database.GetDB().Exec(`UPDATE websites SET status=? WHERE id=?`, status, id); err != nil {
			t.Fatal(err)
		}
		if changed, err := deploySiteCompanionOwned(int(id), files, "new-version", true); err == nil || changed {
			t.Fatalf("%s plugin auto deployment = %v, %v", status, changed, err)
		}
	}
	content, err := os.ReadFile(mainFile)
	if err != nil || string(content) != "old" {
		t.Fatalf("inactive-site plugin changed: %q, %v", content, err)
	}
}

func TestCompanionAutomaticUpgradeStopsWhenPluginRemovedBeforePublish(t *testing.T) {
	pluginsDir := t.TempDir()
	pluginDir := filepath.Join(pluginsDir, pluginDirName)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, pluginDirName+".php"), []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	err := deployPluginDirectoryPrepared(pluginsDir, pluginDir, map[string][]byte{pluginDirName + ".php": []byte("new")}, nil, func() error {
		if err := os.RemoveAll(pluginDir); err != nil {
			return err
		}
		return requireExistingCompanion(pluginDir)
	})
	if !errors.Is(err, errCompanionRemovedBeforePublish) {
		t.Fatalf("publish error = %v", err)
	}
	if _, err := os.Lstat(pluginDir); !os.IsNotExist(err) {
		t.Fatalf("removed plugin was published again: %v", err)
	}
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging directory was not cleaned: %#v", entries)
	}
}

func TestCompanionUpgradeIgnoresAIAndMaintenanceWindow(t *testing.T) {
	oldPermissions := setCompanionPluginPermissions
	setCompanionPluginPermissions = func(string, string, string) error { return nil }
	t.Cleanup(func() { setCompanionPluginPermissions = oldPermissions })
	openTestDB(t)
	root := t.TempDir()
	pluginDir := filepath.Join(root, "wp-content", "plugins", pluginDirName)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	mainFile := filepath.Join(pluginDir, pluginDirName+".php")
	if err := os.WriteFile(mainFile, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := database.GetDB().Exec(`INSERT INTO websites
		(name,domain,status,site_type,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path,plugin_api_key,maintenance_security)
		VALUES ('site','managed.test','active','wordpress','nobody',?,'','','','','','managed-key',?)`, root,
		`{"window":{"id":"11111111-1111-4111-8111-111111111111","state":"unlocked","expires":4102444800}}`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	if _, err := database.GetDB().Exec(`INSERT INTO website_ai_development_access
		(site_id,status,system_user,web_root,original_shell,original_home)
		VALUES (?,'enabled','nobody',?,'/bin/bash','/tmp')`, id, root); err != nil {
		t.Fatal(err)
	}
	if TryAcquireSiteOpLock(int(id), "ordinary") {
		ReleaseSiteOpLock(int(id))
		t.Fatal("ordinary operation unexpectedly ignored maintenance window")
	}
	if !TryAcquireCompanionDeployLock(int(id)) {
		t.Fatal("companion lock was blocked by maintenance window")
	}
	changed, err := deploySiteCompanionOwned(int(id), map[string][]byte{pluginDirName + ".php": []byte("new")}, "new", true)
	ReleaseSiteOpLock(int(id))
	if err != nil || !changed {
		t.Fatalf("companion deploy = %v, %v", changed, err)
	}
	content, err := os.ReadFile(mainFile)
	if err != nil || string(content) != "new" {
		t.Fatalf("plugin content = %q, %v", content, err)
	}
}

func TestCompanionPluginReleaseVersionUsesHeaderNotSourceHash(t *testing.T) {
	files := map[string][]byte{
		pluginDirName + ".php": []byte("<?php\n/**\n * Version: 1.1.21\n */\n"),
		"assets/example.css":   []byte("changed source"),
	}
	if got := companionPluginReleaseVersion(files); got != "1.1.21" {
		t.Fatalf("release version = %q", got)
	}
	if got := pluginSourceVersion(files); got == "1.1.21" || got == "" {
		t.Fatalf("source marker should remain an opaque hash, got %q", got)
	}
}

func insertRegenTestWebsite(t *testing.T, domain, olsVHostConfigPath, status string) int {
	t.Helper()
	res, err := database.GetDB().Exec(
		`INSERT INTO websites (name, domain, status, system_user, web_root, log_dir, db_name, db_user, lsphp_socket_path, ols_vhost_config_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		domain, domain, status, "wp_"+buildSiteName(domain), "/www/wwwroot/"+domain, "/www/wwwlogs/"+domain,
		"db_"+domain, "dbuser_"+domain, filepath.Join("/tmp/lshttpd", buildSiteName(domain)+".sock"), olsVHostConfigPath,
	)
	if err != nil {
		t.Fatalf("insert website %s: %v", domain, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id: %v", err)
	}
	return int(id)
}

// TestRegenerateAllSitesOLSConfigsKeepsPausedSitesDisabled reproduces the bug where
// restarting the panel (e.g. after a self-update) ran RegenerateAllSitesOLSConfigs
// for every site regardless of status, which recreated the OpenLiteSpeed
// sites-enabled symlink for paused sites and silently made them reachable
// again while the DB/UI still showed them as paused.
func TestRegenerateAllSitesOLSConfigsKeepsPausedSitesDisabled(t *testing.T) {
	openTestDB(t)
	installStubOpenLiteSpeed(t)

	baseDir := t.TempDir()
	sitesAvailable := filepath.Join(baseDir, "sites-available")
	sitesEnabled := filepath.Join(baseDir, "sites-enabled")
	backupDir := filepath.Join(baseDir, "backups")
	for _, dir := range []string{sitesAvailable, sitesEnabled, backupDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	oldConfig := config.AppConfig
	config.AppConfig = &config.Config{
		Panel: config.PanelConfig{BackupDir: backupDir},
		Paths: config.PathsConfig{
			OLSVHostsAvailable: sitesAvailable,
			OLSVHostsEnabled:   sitesEnabled,
			LSPHPSocketDir:     filepath.Join(baseDir, "lsphp"),
			OLSManagedConfig:   filepath.Join(baseDir, "ols", "sites.conf"),
			OLSListenerCert:    filepath.Join(baseDir, "tls", "default.crt"),
			OLSListenerKey:     filepath.Join(baseDir, "tls", "default.key"),
		},
	}
	t.Cleanup(func() { config.AppConfig = oldConfig })

	pausedConf := filepath.Join(sitesAvailable, "paused.example.com.conf")
	activeConf := filepath.Join(sitesAvailable, "active.example.com.conf")
	pausedEnabled := filepath.Join(sitesEnabled, "paused.example.com.conf")
	activeEnabled := filepath.Join(sitesEnabled, "active.example.com.conf")

	const oldPlaceholder = "# stale placeholder config\n"
	if err := os.WriteFile(pausedConf, []byte(oldPlaceholder), 0644); err != nil {
		t.Fatalf("seed paused conf: %v", err)
	}
	if err := os.WriteFile(activeConf, []byte(oldPlaceholder), 0644); err != nil {
		t.Fatalf("seed active conf: %v", err)
	}
	// Paused site: mirrors the state left behind by executePauseSite —
	// the enabled symlink has been removed.
	insertRegenTestWebsite(t, "paused.example.com", pausedConf, "paused")

	// Active site: enabled symlink present, as a normal running site would be.
	if err := os.Symlink(activeConf, activeEnabled); err != nil {
		t.Fatalf("seed active enabled symlink: %v", err)
	}
	insertRegenTestWebsite(t, "active.example.com", activeConf, "active")

	if err := RegenerateAllSitesOLSConfigs(); err != nil {
		t.Fatalf("RegenerateAllSitesOLSConfigs: %v", err)
	}

	// The paused site must stay disabled: no sites-enabled symlink...
	if _, err := os.Lstat(pausedEnabled); !os.IsNotExist(err) {
		t.Fatalf("expected paused site to remain without an enabled symlink, lstat err = %v", err)
	}
	// ...but its on-disk config should still have been refreshed with the
	// latest template, so re-enabling later serves the current rules.
	pausedContent, err := os.ReadFile(pausedConf)
	if err != nil {
		t.Fatalf("read paused conf: %v", err)
	}
	if strings.Contains(string(pausedContent), oldPlaceholder) || !strings.Contains(string(pausedContent), "paused.example.com") {
		t.Fatalf("expected paused site config to be refreshed with rendered template, got:\n%s", pausedContent)
	}
	// The active site must remain enabled and pointing at its config.
	target, err := os.Readlink(activeEnabled)
	if err != nil {
		t.Fatalf("expected active site to keep an enabled symlink: %v", err)
	}
	if target != activeConf {
		t.Fatalf("active enabled symlink target = %q, want %q", target, activeConf)
	}
	activeContent, err := os.ReadFile(activeConf)
	if err != nil {
		t.Fatalf("read active conf: %v", err)
	}
	if strings.Contains(string(activeContent), oldPlaceholder) || !strings.Contains(string(activeContent), "active.example.com") {
		t.Fatalf("expected active site config to be refreshed with rendered template, got:\n%s", activeContent)
	}
}
