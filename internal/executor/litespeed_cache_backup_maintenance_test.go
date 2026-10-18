package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func seedRegenerationBackupMaintenance(t *testing.T, domain string, legacy bool) (int, func()) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, domain+".conf")
	enabled := filepath.Join(root, domain+".enabled.conf")
	if config.AppConfig != nil {
		path = filepath.Join(config.AppConfig.Paths.OLSVHostsAvailable, domain+".conf")
		enabled = filepath.Join(config.AppConfig.Paths.OLSVHostsEnabled, domain+".conf")
	}
	maintenanceRoot := filepath.Join(root, "maintenance")
	if err := os.Mkdir(maintenanceRoot, 0755); err != nil {
		t.Fatal(err)
	}
	content, err := renderSiteBackupMaintenance(&models.Website{Domain: domain, SystemUser: "wp_fixture"}, maintenanceRoot, "31a48bf0-32c7-4a19-9237-27d4738fbdd9")
	if err != nil {
		t.Fatal(err)
	}
	if legacy {
		content = fmt.Sprintf(`# OLS-WPanel-Format: 1
# OLS-WPanel-VHost: olsw_%s
# OLS-WPanel-Domains: %s
# OLS-WPanel-VHRoot: %s
docRoot %s
vhDomain %s
enableGzip 0
index {
 useServer 0
 indexFiles maintenance.html
}
context / {
 type NULL
 location %s/
 allowBrowse 1
 extraHeaders <<<END_headers
Cache-Control: no-store
X-OLS-WPanel-Backup: 31a48bf0-32c7-4a19-9237-27d4738fbdd9
END_headers
}
rewrite {
 enable 1
 autoLoadHtaccess 0
 rules <<<END_rules
RewriteRule ^ - [R=503,L]
END_rules
}
`, buildSiteName(domain), domain, maintenanceRoot, maintenanceRoot, domain, maintenanceRoot)
	}
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, enabled); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	id := insertRegenTestWebsite(t, domain, path, string(models.StatusBackupMaintenance))
	// Invalid PHP deliberately proves the maintenance gate precedes runtime
	// resolution as well as any template, secret or cache-key rewrite.
	if _, err := database.GetDB().Exec(`UPDATE websites SET php_version='invalid-runtime',litespeed_cache_key='' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	return id, func() {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("backup maintenance configuration changed: %v", err)
		}
		after, err := os.Stat(path)
		if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
			t.Fatalf("backup maintenance configuration was replaced: %v", err)
		}
		if target, err := os.Readlink(enabled); err != nil || target != path {
			t.Fatalf("backup maintenance enabled link changed: %q, %v", target, err)
		}
		var status, cacheKey, phpVersion string
		if err := database.GetDB().QueryRow(`SELECT status,litespeed_cache_key,php_version FROM websites WHERE id=?`, id).Scan(&status, &cacheKey, &phpVersion); err != nil || status != string(models.StatusBackupMaintenance) || cacheKey != "" || phpVersion != "invalid-runtime" {
			t.Fatalf("backup maintenance persisted state changed: status=%q, cache=%q, PHP=%q, err=%v", status, cacheKey, phpVersion, err)
		}
	}
}

func TestRegenerateSiteOLSConfigPreservesBackupMaintenance(t *testing.T) {
	openTestDB(t)
	oldConfig := config.AppConfig
	config.AppConfig = nil
	t.Cleanup(func() { config.AppConfig = oldConfig })
	id, assertPreserved := seedRegenerationBackupMaintenance(t, "backup.example.com", false)
	if err := RegenerateSiteOLSConfig(id); err != nil {
		t.Fatal(err)
	}
	assertPreserved()
}

func TestRegenerateAllSitesOLSConfigsPreservesBackupMaintenance(t *testing.T) {
	openTestDB(t)
	fixture := newOLSIPv6RegistryFixture(t)
	if err := os.Remove(filepath.Join(fixture.enabled, "example.com.conf")); err != nil {
		t.Fatal(err)
	}
	_, first := seedRegenerationBackupMaintenance(t, "backup-one.example.com", true)
	_, second := seedRegenerationBackupMaintenance(t, "backup-two.example.com", true)
	current, err := renderOLSManagedRegistryWithIPv6(fixture.enabled, true)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.ReplaceAll(current, "  user                   www-data\n", "")
	legacy = strings.ReplaceAll(legacy, "  group                  www-data\n", "")
	if err := os.WriteFile(fixture.paths.managed, []byte(legacy), 0640); err != nil {
		t.Fatal(err)
	}
	validations, restarts := 0, 0
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		updated := readOLSIPv6Registry(t, fixture)
		if strings.Count(updated, "  user                   www-data\n") != 2 || strings.Count(updated, "  group                  www-data\n") != 2 || strings.Contains(updated, "  enableScript           1\n") {
			t.Fatalf("maintenance registry was not upgraded with explicit static identities:\n%s", updated)
		}
		if name == fixture.paths.binary && strings.Join(args, " ") == "-t" {
			validations++
			return nil, nil
		}
		if name == "systemctl" && strings.Join(args, " ") == "restart lshttpd" {
			restarts++
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected service command: %s %v", name, args)
	}
	if err := RegenerateAllSitesOLSConfigs(); err != nil {
		t.Fatal(err)
	}
	first()
	second()
	if validations != 1 || restarts != 1 || readOLSIPv6Registry(t, fixture) == legacy {
		t.Fatalf("maintenance-only upgrade did not reload exactly once: validation=%d restart=%d", validations, restarts)
	}
	// An offline paused site must not prevent the same registry-only upgrade.
	paused := filepath.Join(config.AppConfig.Paths.OLSVHostsAvailable, "paused.example.com.conf")
	insertRegenTestWebsite(t, "paused.example.com", paused, string(models.StatusPaused))
	if err := os.WriteFile(fixture.paths.managed, []byte(legacy), 0640); err != nil {
		t.Fatal(err)
	}
	if err := RegenerateAllSitesOLSConfigs(); err != nil {
		t.Fatal(err)
	}
	first()
	second()
	if _, err := os.Lstat(filepath.Join(fixture.enabled, "paused.example.com.conf")); !os.IsNotExist(err) {
		t.Fatalf("registry upgrade enabled a paused site: %v", err)
	}
	if validations != 2 || restarts != 2 {
		t.Fatalf("maintenance plus paused upgrade did not reload exactly once: validation=%d restart=%d", validations, restarts)
	}
}
