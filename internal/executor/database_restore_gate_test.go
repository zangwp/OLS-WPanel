package executor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func databaseRestoreSiteFixture(t *testing.T) *models.Website {
	t.Helper()
	openTestDB(t)
	insertMinimalWebsite(t, "restore.example.com")
	return &models.Website{ID: 1, Domain: "restore.example.com", DBName: "db1", DBUser: "u1", SystemUser: "u1"}
}

func insertDatabaseRestoreUpdate(t *testing.T, status string, attention int, disposition string) {
	t.Helper()
	if _, err := database.GetDB().Exec(`INSERT INTO wp_update_tasks
		(id,site_id,component_type,status,current_version,target_version,package_source,download_url,requested_at,requires_attention,manual_disposition)
		VALUES('restore_guard_update',1,'core',?,'6.8','6.9','wordpress.org','https://example.com/update.zip',CURRENT_TIMESTAMP,?,?)`, status, attention, disposition); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseRestoreRejectsStaleOrInvalidCurrentBindings(t *testing.T) {
	for _, query := range []string{
		`UPDATE websites SET domain='renamed.example.com' WHERE id=1`,
		`UPDATE websites SET db_name='db2' WHERE id=1`,
		`UPDATE websites SET db_user='u2' WHERE id=1`,
		`UPDATE websites SET system_user='u2' WHERE id=1`,
		`UPDATE websites SET status='deleting' WHERE id=1`,
		`UPDATE websites SET status='creating' WHERE id=1`,
		`UPDATE websites SET status='migrated' WHERE id=1`,
		`UPDATE websites SET status='error' WHERE id=1`,
		`UPDATE websites SET db_name='mysql' WHERE id=1`,
		`UPDATE websites SET db_user='' WHERE id=1`,
		`DELETE FROM websites WHERE id=1`,
	} {
		t.Run(query, func(t *testing.T) {
			expected := databaseRestoreSiteFixture(t)
			mustExec(t, database.GetDB(), query)
			if current, err := validateDatabaseRestoreSite(context.Background(), database.GetDB(), expected, false); err == nil || current != nil {
				t.Fatalf("stale/invalid restore binding accepted: current=%+v err=%v", current, err)
			}
		})
	}
}

func TestDatabaseRestorePersistentOperationGuardsAndRecoveryException(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		updateStatus          string
		attention             int
		disposition           string
		query                 string
		allowOrdinaryRecovery bool
		allowUpdateRecovery   bool
	}{
		{name: "preparing update", updateStatus: "preparing"},
		{name: "queued update", updateStatus: "queued"},
		{name: "running update", updateStatus: "running"},
		{name: "failed update needing recovery", updateStatus: "failed", attention: 1, allowUpdateRecovery: true},
		{name: "handled failed update", updateStatus: "failed", attention: 1, disposition: "manually_rolled_back", allowOrdinaryRecovery: true, allowUpdateRecovery: true},
		{name: "migration site"},
		{name: "migration domain"},
		{name: "AI development", query: `INSERT INTO website_ai_development_access(site_id,status,system_user,web_root,original_shell,original_home) VALUES(1,'enabled','u1','/unused','/usr/sbin/nologin','/unused')`},
		{name: "temporary maintenance", query: `UPDATE websites SET maintenance_security='{"window":{"state":"unlocked"}}' WHERE id=1`},
		{name: "failed relock", query: `UPDATE websites SET maintenance_security='{"window":{"state":"relock_failed"}}' WHERE id=1`},
		{name: "invalid maintenance", query: `UPDATE websites SET maintenance_security='unreadable' WHERE id=1`},
		{name: "file lock uncertain", query: `UPDATE websites SET file_lock_apply_status='failed' WHERE id=1`},
		{name: "unreadable update state", query: `DROP TABLE wp_update_tasks`},
		{name: "unreadable migration state", query: `DROP TABLE site_migration_locks`},
		{name: "paused offline restore", query: `UPDATE websites SET status='paused' WHERE id=1`, allowOrdinaryRecovery: true, allowUpdateRecovery: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected := databaseRestoreSiteFixture(t)
			db := database.GetDB()
			if tc.updateStatus != "" {
				insertDatabaseRestoreUpdate(t, tc.updateStatus, tc.attention, tc.disposition)
			}
			if strings.HasPrefix(tc.name, "migration") {
				insertWPInventoryMigrationLock(t, db, 1, "other.example.com")
				if tc.name == "migration domain" {
					mustExec(t, db, `UPDATE site_migration_locks SET site_id=NULL,domain='restore.example.com'`)
				}
			}
			if tc.query != "" {
				mustExec(t, db, tc.query)
			}
			for _, updateRecovery := range []bool{false, true} {
				_, err := validateDatabaseRestoreSite(context.Background(), db, expected, updateRecovery)
				allowed := tc.allowOrdinaryRecovery
				if updateRecovery {
					allowed = tc.allowUpdateRecovery
				}
				if (err == nil) != allowed {
					t.Fatalf("updateRecovery=%v allowed=%v err=%v", updateRecovery, allowed, err)
				}
			}
		})
	}
}

func TestExecuteDatabaseRestoreStopsPendingUpdateBeforeCredentialOrSubprocess(t *testing.T) {
	for _, kind := range []string{"ordinary", "upload", "protected update backup"} {
		t.Run(kind, func(t *testing.T) {
			task, statePath, _ := setupDatabaseRestoreTest(t, "CREATE TABLE replacement (id int); -- REPLACEMENT\n")
			payload := task.Payload.(*RestoreBackupPayload)
			var uploadPath string
			if kind == "upload" {
				file, err := os.CreateTemp("", "olswpanel_upload_*.sql")
				if err != nil {
					t.Fatal(err)
				}
				uploadPath = file.Name()
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(uploadPath)
				payload.FilePath, payload.RemoveFileAfter = uploadPath, true
			}
			if kind == "protected update backup" {
				if !TryAcquireSiteOpLock(1, "wp_update_restore") {
					t.Fatal("acquire transferred site lock")
				}
				defer ReleaseSiteOpLock(1)
				payload.UpdateBackupPath = "/unused/protected.sql.gz"
			}
			insertDatabaseRestoreUpdate(t, "queued", 0, "")
			restoreBackupPassword = func() string { t.Fatal("busy restore reached credentials"); return "" }
			databaseBackupCommand = func(context.Context, string, ...string) *exec.Cmd {
				t.Fatal("busy restore started subprocess")
				return nil
			}
			result := executeRestoreBackup(task)
			if result.Success || !strings.Contains(result.Message, "更新任务") || SiteOpLocked(1) {
				t.Fatalf("pending update was not rejected or lock leaked: %+v locked=%v", result, SiteOpLocked(1))
			}
			if content, err := os.ReadFile(statePath); err != nil || string(content) != "original" {
				t.Fatalf("busy restore changed original state: %q %v", content, err)
			}
			if uploadPath != "" {
				if _, err := os.Stat(uploadPath); !os.IsNotExist(err) {
					t.Fatalf("owned rejected upload was not removed: %v", err)
				}
			}
		})
	}
}

func TestDatabaseRestoreRechecksBindingAfterSafetySnapshot(t *testing.T) {
	task, statePath, safetyRoot := setupDatabaseRestoreTest(t, "CREATE TABLE replacement (id int); -- REPLACEMENT\n")
	commands := 0
	databaseBackupCommand = func(ctx context.Context, command string, args ...string) *exec.Cmd {
		commands++
		if command != "mysqldump" {
			t.Fatal("stale binding reached destructive/import subprocess")
		}
		mustExec(t, database.GetDB(), `UPDATE websites SET db_name='db2' WHERE id=1`)
		return backupTestCommand(ctx, command, args...)
	}
	result := executeRestoreBackup(task)
	if result.Success || !strings.Contains(result.Message, "绑定已变化") || commands != 1 {
		t.Fatalf("changed binding was not rejected: result=%+v commands=%d", result, commands)
	}
	if content, err := os.ReadFile(statePath); err != nil || string(content) != "original" {
		t.Fatalf("stale restore changed original state: %q %v", content, err)
	}
	paths, err := filepath.Glob(filepath.Join(safetyRoot, "restore-*", "before-restore.sql.gz"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("verified original copy was not retained: paths=%v err=%v", paths, err)
	}
}

func TestProtectedUpdateDatabaseRecoveryAllowsFailedAttentionAndReleasesLock(t *testing.T) {
	task, statePath, _ := setupDatabaseRestoreTest(t, "CREATE TABLE replacement (id int); -- REPLACEMENT\n")
	insertDatabaseRestoreUpdate(t, "failed", 1, "")
	root := filepath.Join(config.AppConfig.Panel.BackupDir, "wp-updates")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "protected.sql")
	if err := os.WriteFile(path, []byte("CREATE TABLE replacement (id int); -- REPLACEMENT\n"), 0600); err != nil {
		t.Fatal(err)
	}
	hash, _, err := hashRegularFile(path)
	if err != nil {
		t.Fatal(err)
	}
	payload := task.Payload.(*RestoreBackupPayload)
	payload.UpdateBackupPath, payload.ExpectedSHA256 = path, hash
	if !TryAcquireSiteOpLock(1, "wp_update_restore") {
		t.Fatal("acquire transferred site lock")
	}
	defer ReleaseSiteOpLock(1)
	result := executeRestoreBackup(task)
	if !result.Success || SiteOpLocked(1) {
		t.Fatalf("dedicated failed-update recovery blocked or leaked lock: result=%+v locked=%v", result, SiteOpLocked(1))
	}
	if content, err := os.ReadFile(statePath); err != nil || string(content) != "replacement" {
		t.Fatalf("recovery did not import expected data: %q %v", content, err)
	}
}
