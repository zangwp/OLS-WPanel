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

func setupCDNRealIPTask(t *testing.T) (*models.Website, *[]string) {
	t.Helper()
	openTestDB(t)
	root := t.TempDir()
	oldConfig, oldSecretsRoot, oldPHPPath := config.AppConfig, siteSecretsRoot, phpRuntimeConfigPath
	oldTrusted, oldVHost, oldFail2ban := applyCDNRealIPTrustedProxies, applyCDNRealIPOLSVHost, applyCDNRealIPFail2ban
	t.Cleanup(func() {
		config.AppConfig, siteSecretsRoot, phpRuntimeConfigPath = oldConfig, oldSecretsRoot, oldPHPPath
		applyCDNRealIPTrustedProxies, applyCDNRealIPOLSVHost, applyCDNRealIPFail2ban = oldTrusted, oldVHost, oldFail2ban
	})
	config.AppConfig = &config.Config{
		Panel: config.PanelConfig{BackupDir: filepath.Join(root, "backups")},
		Paths: config.PathsConfig{WWWRoot: root, OLSVHostsAvailable: filepath.Join(root, "available"), OLSVHostsEnabled: filepath.Join(root, "enabled"), LSPHPBinary: filepath.Join(root, "lsphp"), LSPHPCLI: filepath.Join(root, "php")},
	}
	siteSecretsRoot, phpRuntimeConfigPath = filepath.Join(root, "secrets"), filepath.Join(root, "php.ini")
	path := filepath.Join(config.AppConfig.Paths.OLSVHostsAvailable, "cdn.example.com.conf")
	siteID := insertRegenTestWebsite(t, "cdn.example.com", path, "active")
	if _, err := database.GetDB().Exec(`INSERT INTO cdn_realip_groups(id,name,provider,header_name,ip_ranges,enabled)
		VALUES(201,'old','custom','X-Forwarded-For','203.0.113.0/24',1),(202,'new','custom','X-Forwarded-For','198.51.100.0/24',1)`); err != nil {
		t.Fatal(err)
	}
	if err := SaveWebsiteCDNRealIPSettings(siteID, false, []int{201}); err != nil {
		t.Fatal(err)
	}
	oldGroup, err := GetCDNRealIPGroup(201)
	if err != nil {
		t.Fatal(err)
	}
	site := &models.Website{ID: siteID, Domain: "cdn.example.com", SiteType: "wordpress", SystemUser: "wp_cdn", WebRoot: filepath.Join(root, "site"), LogDir: filepath.Join(root, "logs"),
		OLSVHostConfigPath: path, LSPHPSocketPath: filepath.VolumeName(root) + string(filepath.Separator) + "olsw-cdn-test.sock", PHPVersion: PrimaryLSPHPVersion(), CDNRealIPGroups: []models.CDNRealIPGroup{oldGroup}}
	var calls []string
	applyCDNRealIPTrustedProxies = func() error { calls = append(calls, "ACL"); return nil }
	applyCDNRealIPOLSVHost = func(engine *TemplateEngine, content, target, enabled string) error {
		calls = append(calls, "vhost")
		return engine.ApplyOLSVHostConfigKeepDisabled(content, target)
	}
	applyCDNRealIPFail2ban = func() error { calls = append(calls, "Fail2ban"); return nil }
	return site, &calls
}

func assertCDNRealIPTaskDatabase(t *testing.T, siteID int, enabled bool, groupID int) {
	t.Helper()
	var flag int
	if err := database.GetDB().QueryRow(`SELECT cdn_realip_enabled FROM websites WHERE id=?`, siteID).Scan(&flag); err != nil || (flag == 1) != enabled {
		t.Fatalf("persisted CDN flag=%d, error=%v", flag, err)
	}
	groups, err := GetWebsiteCDNRealIPGroups(siteID)
	if err != nil || len(groups) != 1 || groups[0].ID != groupID {
		t.Fatalf("persisted CDN bindings=%v, error=%v", groups, err)
	}
}

func runCDNRealIPTask(site *models.Website) TaskResult {
	return executeSetCDNRealIP(&Task{Payload: &SetCDNRealIPPayload{Site: site, Enabled: true, GroupIDs: []int{202}}})
}

func TestCDNRealIPTaskSuccessPersistsBeforeApplyingRuntime(t *testing.T) {
	site, calls := setupCDNRealIPTask(t)
	applyCDNRealIPTrustedProxies = func() error {
		*calls = append(*calls, "ACL")
		assertCDNRealIPTaskDatabase(t, site.ID, true, 202)
		return nil
	}
	result := runCDNRealIPTask(site)
	if !result.Success || strings.Join(*calls, ",") != "ACL,vhost,Fail2ban" {
		t.Fatalf("result=%+v, calls=%v", result, *calls)
	}
	if _, err := os.Stat(site.OLSVHostConfigPath); err != nil {
		t.Fatal("actual rendered vhost was not written", err)
	}
}

func TestCDNRealIPTaskFailedInitialTransactionDoesNotApplyRuntime(t *testing.T) {
	site, calls := setupCDNRealIPTask(t)
	if _, err := database.GetDB().Exec(`CREATE TRIGGER reject_new_cdn BEFORE INSERT ON website_cdn_realip_groups WHEN NEW.group_id=202 BEGIN SELECT RAISE(ABORT,'new binding rejected'); END`); err != nil {
		t.Fatal(err)
	}
	result := runCDNRealIPTask(site)
	if result.Success || len(*calls) != 0 || !strings.Contains(result.Message, "new binding rejected") {
		t.Fatalf("result=%+v, calls=%v", result, *calls)
	}
	// The flag update and deleted old binding belong to the same failed tx.
	assertCDNRealIPTaskDatabase(t, site.ID, false, 201)
}

func TestCDNRealIPTaskRuntimeFailuresRestoreRealDatabaseAndReportCause(t *testing.T) {
	for _, stage := range []string{"ACL", "vhost", "Fail2ban"} {
		t.Run(stage, func(t *testing.T) {
			site, calls := setupCDNRealIPTask(t)
			trusted, vhost, fail2ban := applyCDNRealIPTrustedProxies, applyCDNRealIPOLSVHost, applyCDNRealIPFail2ban
			failed := false
			applyCDNRealIPTrustedProxies = func() error {
				if err := trusted(); err != nil {
					return err
				}
				if stage == "ACL" && !failed {
					failed = true
					return errors.New("initial ACL failed")
				}
				return nil
			}
			applyCDNRealIPOLSVHost = func(engine *TemplateEngine, content, target, enabled string) error {
				if stage == "vhost" && !failed {
					failed = true
					*calls = append(*calls, "vhost")
					return errors.New("initial vhost failed")
				}
				return vhost(engine, content, target, enabled)
			}
			applyCDNRealIPFail2ban = func() error {
				if err := fail2ban(); err != nil {
					return err
				}
				if stage == "Fail2ban" {
					return errors.New("initial Fail2ban failed")
				}
				return nil
			}
			result := runCDNRealIPTask(site)
			if result.Success || !strings.Contains(result.Message, "initial "+stage+" failed") || !strings.Contains(result.Message, "数据库设置与可信代理 ACL 已恢复") {
				t.Fatalf("result=%+v", result)
			}
			assertCDNRealIPTaskDatabase(t, site.ID, false, 201)
			wantCalls := map[string]string{"ACL": "ACL,ACL", "vhost": "ACL,vhost,ACL", "Fail2ban": "ACL,vhost,Fail2ban,ACL,vhost"}[stage]
			if strings.Join(*calls, ",") != wantCalls {
				t.Fatalf("calls=%v, expected=%s", *calls, wantCalls)
			}
		})
	}
}

func TestCDNRealIPTaskReportsFailedRestoreTransactionAndOldVHost(t *testing.T) {
	site, calls := setupCDNRealIPTask(t)
	if _, err := database.GetDB().Exec(`CREATE TRIGGER reject_old_cdn BEFORE INSERT ON website_cdn_realip_groups WHEN NEW.group_id=201 BEGIN SELECT RAISE(ABORT,'old binding restore rejected'); END`); err != nil {
		t.Fatal(err)
	}
	vhost := applyCDNRealIPOLSVHost
	vhostCalls := 0
	applyCDNRealIPOLSVHost = func(engine *TemplateEngine, content, target, enabled string) error {
		vhostCalls++
		if vhostCalls == 2 {
			*calls = append(*calls, "vhost")
			return errors.New("old vhost restore failed")
		}
		return vhost(engine, content, target, enabled)
	}
	applyCDNRealIPFail2ban = func() error { *calls = append(*calls, "Fail2ban"); return errors.New("original Fail2ban failure") }
	result := runCDNRealIPTask(site)
	for _, detail := range []string{"original Fail2ban failure", "old binding restore rejected", "ACL 无法恢复", "old vhost restore failed", "恢复未完成"} {
		if result.Success || !strings.Contains(result.Message, detail) {
			t.Fatalf("missing recovery detail %q: %+v", detail, result)
		}
	}
	if strings.Contains(result.Message, "已回滚") || strings.Contains(result.Message, "ACL 已恢复") || strings.Join(*calls, ",") != "ACL,vhost,Fail2ban,vhost" {
		t.Fatalf("incorrect recovery claim or dependent ACL apply: %+v, calls=%v", result, *calls)
	}
	// Failed recovery is a real atomic tx: its flag update and old-binding
	// deletion roll back together, preserving the last committed new settings.
	assertCDNRealIPTaskDatabase(t, site.ID, true, 202)
}

func TestCDNRealIPTaskReportsAllRuntimeRecoveryFailures(t *testing.T) {
	site, calls := setupCDNRealIPTask(t)
	trusted, vhost := applyCDNRealIPTrustedProxies, applyCDNRealIPOLSVHost
	trustedCalls, vhostCalls := 0, 0
	applyCDNRealIPTrustedProxies = func() error {
		trustedCalls++
		if err := trusted(); err != nil {
			return err
		}
		if trustedCalls == 2 {
			assertCDNRealIPTaskDatabase(t, site.ID, false, 201)
			return errors.New("ACL restore failed")
		}
		return nil
	}
	applyCDNRealIPOLSVHost = func(engine *TemplateEngine, content, target, enabled string) error {
		vhostCalls++
		if vhostCalls == 2 {
			*calls = append(*calls, "vhost")
			return errors.New("old vhost restore failed")
		}
		return vhost(engine, content, target, enabled)
	}
	applyCDNRealIPFail2ban = func() error { *calls = append(*calls, "Fail2ban"); return errors.New("original Fail2ban failure") }
	result := runCDNRealIPTask(site)
	for _, detail := range []string{"original Fail2ban failure", "ACL restore failed", "old vhost restore failed", "恢复未完成"} {
		if result.Success || !strings.Contains(result.Message, detail) {
			t.Fatalf("missing recovery detail %q: %+v", detail, result)
		}
	}
	assertCDNRealIPTaskDatabase(t, site.ID, false, 201)
	if strings.Join(*calls, ",") != "ACL,vhost,Fail2ban,ACL,vhost" {
		t.Fatalf("recovery stopped before independent steps were attempted: %v", *calls)
	}
}

func TestCDNRealIPTaskReportsUnrenderableOldVHostDuringRecovery(t *testing.T) {
	site, calls := setupCDNRealIPTask(t)
	// A legacy unsupported header does not prevent selecting a valid new group,
	// but must not be silently ignored when restoring that previous vhost.
	if _, err := database.GetDB().Exec(`UPDATE cdn_realip_groups SET header_name='X-Real-IP' WHERE id=201`); err != nil {
		t.Fatal(err)
	}
	oldGroup, err := GetCDNRealIPGroup(201)
	if err != nil {
		t.Fatal(err)
	}
	site.CDNRealIPEnabled = true
	site.CDNRealIPGroups = []models.CDNRealIPGroup{oldGroup}
	if err := SaveWebsiteCDNRealIPSettings(site.ID, true, []int{201}); err != nil {
		t.Fatal(err)
	}
	applyCDNRealIPFail2ban = func() error { *calls = append(*calls, "Fail2ban"); return errors.New("original Fail2ban failure") }
	result := runCDNRealIPTask(site)
	for _, detail := range []string{"original Fail2ban failure", "恢复原虚拟主机配置无法生成", "X-Forwarded-For", "恢复未完成"} {
		if result.Success || !strings.Contains(result.Message, detail) {
			t.Fatalf("missing recovery detail %q: %+v", detail, result)
		}
	}
	assertCDNRealIPTaskDatabase(t, site.ID, true, 201)
	if strings.Join(*calls, ",") != "ACL,vhost,Fail2ban,ACL" || strings.Contains(result.Message, "ACL 已恢复") {
		t.Fatalf("invalid old vhost was applied or recovery overstated: %+v, calls=%v", result, *calls)
	}
}
