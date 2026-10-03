package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func setupPrimaryDomainTest(t *testing.T) (*models.Website, string) {
	t.Helper()
	openTestDB(t)
	root := t.TempDir()
	oldCfg := config.AppConfig
	oldSecretsRoot := siteSecretsRoot
	oldApplyOpenLiteSpeed := applyPrimaryDomainOLSVHost
	oldChange := changeWebsitePrimaryDomain
	oldReloadOpenLiteSpeed := reloadPrimaryDomainOLS
	oldUpdateURLs := updatePrimaryDomainWPSiteURLs
	oldReadURLs := readPrimaryDomainWPSiteURLs
	config.AppConfig = &config.Config{
		Panel: config.PanelConfig{BackupDir: filepath.Join(root, "backups")},
		Paths: config.PathsConfig{
			WWWRoot: filepath.Join(root, "www"), WWWLogs: filepath.Join(root, "logs"),
			Certificates: filepath.Join(root, "certs"), OLSVHostsAvailable: filepath.Join(root, "available"),
			OLSVHostsEnabled: filepath.Join(root, "enabled"), LSPHPSocketDir: "/run/php",
		},
	}
	siteSecretsRoot = filepath.Join(root, "secrets")
	t.Cleanup(func() {
		config.AppConfig = oldCfg
		siteSecretsRoot = oldSecretsRoot
		applyPrimaryDomainOLSVHost = oldApplyOpenLiteSpeed
		changeWebsitePrimaryDomain = oldChange
		reloadPrimaryDomainOLS = oldReloadOpenLiteSpeed
		updatePrimaryDomainWPSiteURLs = oldUpdateURLs
		readPrimaryDomainWPSiteURLs = oldReadURLs
	})

	oldDomain := "old.example.com"
	newDomain := "new.example.com"
	oldWebRoot := filepath.Join(config.AppConfig.Paths.WWWRoot, oldDomain)
	oldLogDir := filepath.Join(config.AppConfig.Paths.WWWLogs, oldDomain)
	olsVHostPath := filepath.Join(config.AppConfig.Paths.OLSVHostsAvailable, oldDomain+".conf")
	phpSocketPath := filepath.Join(config.AppConfig.Paths.LSPHPSocketDir, "old_example.sock")
	for _, dir := range []string{oldWebRoot, oldLogDir, filepath.Dir(olsVHostPath), config.AppConfig.Paths.OLSVHostsEnabled, filepath.Join(config.AppConfig.Panel.BackupDir, oldDomain)} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(olsVHostPath, []byte("old openlitespeed"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.AppConfig.Panel.BackupDir, oldDomain, "backup.tar"), []byte("backup"), 0644); err != nil {
		t.Fatal(err)
	}
	enabledPath := olsVHostEnabledPath(config.AppConfig, olsVHostPath, oldDomain)
	if err := os.Symlink(olsVHostPath, enabledPath); err != nil {
		t.Fatal(err)
	}
	site := &models.Website{
		ID: 92, Domain: oldDomain, Status: models.StatusActive, SiteType: "wordpress", SystemUser: "siteuser",
		WebRoot: oldWebRoot, LogDir: oldLogDir, OLSVHostConfigPath: olsVHostPath, LSPHPSocketPath: phpSocketPath,
		DBName: "wpdb", DBUser: "wpuser", TablePrefix: "wp_", LSPHPMaxChildren: 10,
	}
	if _, err := database.GetDB().Exec(`INSERT INTO websites
		(id,name,domain,aliases,status,site_type,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path,lsphp_max_children)
		VALUES (92,'domain-test',?,'','active','wordpress','siteuser',?,?,'wpdb','wpuser',?,?,10)`,
		oldDomain, oldWebRoot, oldLogDir, phpSocketPath, olsVHostPath); err != nil {
		t.Fatal(err)
	}
	reloadPrimaryDomainOLS = func() error { return nil }
	applyPrimaryDomainOLSVHost = func(_ *TemplateEngine, content, target, enabled string) error {
		if err := os.WriteFile(target, []byte(content), 0644); err != nil {
			return err
		}
		_ = os.Remove(enabled)
		return os.Symlink(target, enabled)
	}
	return site, newDomain
}

func runPrimaryDomainUpdate(site *models.Website, newDomain string) TaskResult {
	return executeUpdateDomains(&Task{Payload: &UpdateDomainsPayload{Site: site, NewDomain: newDomain}})
}

func TestPrimaryDomainPreflightRejectsOccupiedTargetWithoutChanges(t *testing.T) {
	site, newDomain := setupPrimaryDomainTest(t)
	target := filepath.Join(config.AppConfig.Paths.WWWRoot, newDomain)
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	result := runPrimaryDomainUpdate(site, newDomain)
	if result.Success || !strings.Contains(result.Message, "预检查") {
		t.Fatalf("result=%+v", result)
	}
	if _, err := os.Stat(site.WebRoot); err != nil {
		t.Fatalf("old web root changed: %v", err)
	}
	var domain string
	if err := database.GetDB().QueryRow("SELECT domain FROM websites WHERE id=92").Scan(&domain); err != nil || domain != "old.example.com" {
		t.Fatalf("domain=%q err=%v", domain, err)
	}
}

func TestPrimaryDomainDatabaseFailureRestoresFilesystemAndConfig(t *testing.T) {
	site, newDomain := setupPrimaryDomainTest(t)
	changeWebsitePrimaryDomain = func(int, string, *models.Website) error { return errors.New("database failed") }
	result := runPrimaryDomainUpdate(site, newDomain)
	if result.Success {
		t.Fatalf("result=%+v", result)
	}
	if _, err := os.Stat(site.WebRoot); err != nil {
		t.Fatalf("old web root not restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(config.AppConfig.Paths.WWWRoot, newDomain)); !os.IsNotExist(err) {
		t.Fatalf("new web root remains: %v", err)
	}
	content, err := os.ReadFile(site.OLSVHostConfigPath)
	if err != nil || string(content) != "old openlitespeed" {
		t.Fatalf("openlitespeed=%q err=%v", content, err)
	}
	if _, err := os.Stat(filepath.Join(config.AppConfig.Panel.BackupDir, "old.example.com", "backup.tar")); err != nil {
		t.Fatalf("old backup not restored: %v", err)
	}
}

func TestPrimaryDomainOpenLiteSpeedFailureRestoresMovedResources(t *testing.T) {
	site, newDomain := setupPrimaryDomainTest(t)
	applyPrimaryDomainOLSVHost = func(*TemplateEngine, string, string, string) error { return errors.New("openlitespeed failed") }
	result := runPrimaryDomainUpdate(site, newDomain)
	if result.Success || !strings.Contains(result.Message, "OpenLiteSpeed") {
		t.Fatalf("result=%+v", result)
	}
	if _, err := os.Stat(site.WebRoot); err != nil {
		t.Fatalf("old web root not restored: %v", err)
	}
	if _, err := os.Stat(site.LogDir); err != nil {
		t.Fatalf("old log dir not restored: %v", err)
	}
}

func TestPrimaryDomainWordPressURLVerificationFailureRollsBack(t *testing.T) {
	site, newDomain := setupPrimaryDomainTest(t)
	updatePrimaryDomainWPSiteURLs = func(string, string, string, string, *config.Config) error { return nil }
	readPrimaryDomainWPSiteURLs = func(string, string, *config.Config) (string, string, error) {
		return "https://old.example.com", "https://old.example.com", nil
	}
	result := executeUpdateDomains(&Task{Payload: &UpdateDomainsPayload{
		Site: site, NewDomain: newDomain,
		OldWPSiteURL: "https://old.example.com", OldWPHomeURL: "https://old.example.com",
		NewWPSiteURL: "https://new.example.com", NewWPHomeURL: "https://new.example.com",
	}})
	if result.Success || !strings.Contains(result.Message, "验证 WordPress") {
		t.Fatalf("result=%+v", result)
	}
	if _, err := os.Stat(site.WebRoot); err != nil {
		t.Fatalf("old web root not restored: %v", err)
	}
}

func TestPrimaryDomainReportsRollbackFailure(t *testing.T) {
	site, newDomain := setupPrimaryDomainTest(t)
	changeWebsitePrimaryDomain = func(int, string, *models.Website) error { return errors.New("database failed") }
	reloadPrimaryDomainOLS = func() error { return errors.New("reload failed") }
	result := runPrimaryDomainUpdate(site, newDomain)
	if result.Success || !strings.Contains(result.Message, "状态恢复不完整") || !strings.Contains(result.Message, "OpenLiteSpeed") {
		t.Fatalf("result=%+v", result)
	}
}

func TestPrimaryDomainSuccessPersistsAndVerifies(t *testing.T) {
	site, newDomain := setupPrimaryDomainTest(t)
	result := runPrimaryDomainUpdate(site, newDomain)
	if !result.Success || site.Domain != newDomain {
		t.Fatalf("result=%+v site=%+v", result, site)
	}
	var domain, webRoot, logDir string
	if err := database.GetDB().QueryRow("SELECT domain,web_root,log_dir FROM websites WHERE id=92").Scan(&domain, &webRoot, &logDir); err != nil {
		t.Fatal(err)
	}
	if domain != newDomain || webRoot != filepath.Join(config.AppConfig.Paths.WWWRoot, newDomain) || logDir != filepath.Join(config.AppConfig.Paths.WWWLogs, newDomain) {
		t.Fatalf("domain=%q webRoot=%q logDir=%q", domain, webRoot, logDir)
	}
	if data, err := os.ReadFile(filepath.Join(config.AppConfig.Panel.BackupDir, newDomain, "backup.tar")); err != nil || string(data) != "backup" {
		t.Fatalf("backup not moved: data=%q err=%v", data, err)
	}
}

func TestUpdateWebsitePrimaryDomainRejectsStaleDomain(t *testing.T) {
	site, _ := setupPrimaryDomainTest(t)
	proposed := *site
	proposed.Domain = "new.example.com"
	if err := updateWebsitePrimaryDomain(site.ID, "stale.example.com", &proposed); err == nil {
		t.Fatal("stale domain unexpectedly overwritten")
	}
}
