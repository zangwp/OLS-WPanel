package executor

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/config"
	"github.com/zangwp/OLS-WPanel/database"
	"github.com/zangwp/OLS-WPanel/models"
)

func setupWebsiteAliasTest(t *testing.T) *models.Website {
	t.Helper()
	openTestDB(t)
	root := t.TempDir()
	oldCfg := config.AppConfig
	oldChange, oldApply := changeWebsiteAliasSettings, applyAliasOLSVHost
	config.AppConfig = &config.Config{
		Panel: config.PanelConfig{BackupDir: filepath.Join(root, "backups")},
		Paths: config.PathsConfig{
			OLSVHostsAvailable: filepath.Join(root, "available"),
			OLSVHostsEnabled:   filepath.Join(root, "enabled"),
			LSPHPSocketDir:     filepath.Join(root, "php"),
			OLSManagedConfig:   filepath.Join(root, "ols", "managed.conf"),
		},
	}
	t.Cleanup(func() {
		config.AppConfig = oldCfg
		changeWebsiteAliasSettings, applyAliasOLSVHost = oldChange, oldApply
	})
	site := &models.Website{
		ID: 91, Domain: "example.com", Aliases: "www.example.com", AliasRedirectMode: AliasRedirectServe, Status: models.StatusActive,
		SiteType: "wordpress", SystemUser: "wp_alias", WebRoot: filepath.Join(root, "www"), LogDir: filepath.Join(root, "logs"),
		OLSVHostConfigPath: filepath.Join(root, "available", "example.com.conf"), LSPHPSocketPath: filepath.Join(root, "php", "example.com.conf"),
	}
	if _, err := database.GetDB().Exec(`INSERT INTO websites
		(id,name,domain,aliases,status,site_type,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path)
		VALUES (91,'alias','example.com','www.example.com','active','wordpress','wp_alias',?,'','db','wp_alias',?,?)`,
		site.WebRoot, site.LSPHPSocketPath, site.OLSVHostConfigPath); err != nil {
		t.Fatal(err)
	}
	return site
}

func runAliasUpdate(site *models.Website) TaskResult {
	return executeUpdateDomains(&Task{Payload: &UpdateDomainsPayload{
		Site: site, NewDomain: site.Domain, Aliases: []string{"cdn.example.com"},
	}})
}

func TestAliasUpdateDatabaseFailureDoesNotApplyOpenLiteSpeed(t *testing.T) {
	site := setupWebsiteAliasTest(t)
	changeWebsiteAliasSettings = func(int, string, string, string, string) error { return errors.New("database failed") }
	openlitespeedCalled := false
	applyAliasOLSVHost = func(*TemplateEngine, string, string, string) error { openlitespeedCalled = true; return nil }
	result := runAliasUpdate(site)
	if result.Success || openlitespeedCalled || site.Aliases != "www.example.com" {
		t.Fatalf("result=%+v openlitespeedCalled=%v aliases=%q", result, openlitespeedCalled, site.Aliases)
	}
}

func TestAliasUpdateOpenLiteSpeedFailureRestoresDatabase(t *testing.T) {
	site := setupWebsiteAliasTest(t)
	var transitions [][2]string
	changeWebsiteAliasSettings = func(_ int, from, _ string, to, _ string) error {
		transitions = append(transitions, [2]string{from, to})
		return nil
	}
	applyAliasOLSVHost = func(*TemplateEngine, string, string, string) error { return errors.New("openlitespeed failed") }
	result := runAliasUpdate(site)
	if result.Success || len(transitions) != 2 || transitions[1] != [2]string{"cdn.example.com", "www.example.com"} {
		t.Fatalf("result=%+v transitions=%v", result, transitions)
	}
}

func TestAliasUpdateReportsRecoveryFailure(t *testing.T) {
	site := setupWebsiteAliasTest(t)
	call := 0
	changeWebsiteAliasSettings = func(int, string, string, string, string) error {
		call++
		if call == 2 {
			return errors.New("restore failed")
		}
		return nil
	}
	applyAliasOLSVHost = func(*TemplateEngine, string, string, string) error { return errors.New("openlitespeed failed") }
	result := runAliasUpdate(site)
	if result.Success || !strings.Contains(result.Message, "状态恢复失败") {
		t.Fatalf("result=%+v", result)
	}
}

func TestAliasUpdateSuccessPersistsAndApplies(t *testing.T) {
	site := setupWebsiteAliasTest(t)
	openlitespeedCalled := false
	applyAliasOLSVHost = func(*TemplateEngine, string, string, string) error { openlitespeedCalled = true; return nil }
	result := runAliasUpdate(site)
	if !result.Success || !openlitespeedCalled {
		t.Fatalf("result=%+v openlitespeedCalled=%v", result, openlitespeedCalled)
	}
	var aliases string
	if err := database.GetDB().QueryRow("SELECT aliases FROM websites WHERE id=91").Scan(&aliases); err != nil || aliases != "cdn.example.com" {
		t.Fatalf("aliases=%q err=%v", aliases, err)
	}
}

func TestUpdateWebsiteAliasSettingsRejectsStaleValue(t *testing.T) {
	setupWebsiteAliasTest(t)
	if err := updateWebsiteAliasSettings(91, "stale.example.com", AliasRedirectServe, "new.example.com", AliasRedirectPermanent); err == nil {
		t.Fatal("stale aliases unexpectedly overwritten")
	}
}
