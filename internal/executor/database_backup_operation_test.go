package executor

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func setupDatabaseBackupOperationTest(t *testing.T) (*CreateBackupPayload, *int) {
	t.Helper()
	restoreTask, _, _ := setupDatabaseRestoreTest(t, "CREATE TABLE original (id int);")
	payload := &CreateBackupPayload{Site: restoreTask.Payload.(*RestoreBackupPayload).Site}
	previousPassword, previousCommand := databaseBackupPassword, databaseBackupCommand
	databaseBackupPassword = func() string { return "fixture-only-password" }
	calls := new(int)
	databaseBackupCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		*calls++
		return backupTestCommand(ctx, name, args...)
	}
	t.Cleanup(func() {
		databaseBackupPassword, databaseBackupCommand = previousPassword, previousCommand
		ReleaseSiteOpLock(payload.Site.ID)
	})
	return payload, calls
}

func TestDatabaseBackupsSkipActiveRestoreBeforeDumpOrRecord(t *testing.T) {
	payload, calls := setupDatabaseBackupOperationTest(t)
	if !TryAcquireSiteOpLock(payload.Site.ID, "restore") {
		t.Fatal("fixture could not acquire restore operation")
	}
	result := executeCreateBackup(&Task{Payload: payload})
	if result.Success || !strings.Contains(result.Message, "未执行") {
		t.Fatalf("manual backup bypassed restore: %+v", result)
	}
	if _, err := database.GetDB().Exec("INSERT INTO backup_settings(site_id, enabled, keep_count) VALUES(1,1,3)"); err != nil {
		t.Fatal(err)
	}
	executeAutoBackups()
	var records int
	if err := database.GetDB().QueryRow("SELECT COUNT(*) FROM db_backups").Scan(&records); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 || records != 0 || !SiteOpLocked(payload.Site.ID) {
		t.Fatalf("busy backup dumped/recorded/released another owner: calls=%d records=%d", *calls, records)
	}
}

func TestDatabaseAutomaticBackupReportsBusyAndReleasesOwnOperation(t *testing.T) {
	payload, calls := setupDatabaseBackupOperationTest(t)
	task := automaticDatabaseBackup{siteID: payload.Site.ID, domain: payload.Site.Domain, dbName: payload.Site.DBName, keepCount: 3}
	if !TryAcquireSiteOpLock(task.siteID, "restore") {
		t.Fatal("fixture lock unavailable")
	}
	completed, skipped, err := executeAutomaticDatabaseBackup(task, "fixture-only-password")
	if completed || skipped != "site_operation_busy" || err != nil || *calls != 0 {
		t.Fatalf("busy result: %v %q %v calls=%d", completed, skipped, err, *calls)
	}
	ReleaseSiteOpLock(task.siteID)
	completed, skipped, err = executeAutomaticDatabaseBackup(task, "fixture-only-password")
	if !completed || skipped != "" || err != nil || *calls != 1 || SiteOpLocked(task.siteID) {
		t.Fatalf("normal auto result: %v %q %v calls=%d locked=%v", completed, skipped, err, *calls, SiteOpLocked(task.siteID))
	}
}

func TestDatabaseManualBackupReleasesOwnOperationOnSuccessAndFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failed_dump"}[fail], func(t *testing.T) {
			payload, calls := setupDatabaseBackupOperationTest(t)
			if fail {
				t.Setenv("OLS_BACKUP_TEST_DUMP_FAIL", "1")
			}
			result := executeCreateBackup(&Task{Payload: payload})
			if result.Success == fail || *calls != 1 || SiteOpLocked(payload.Site.ID) {
				t.Fatalf("manual result=%+v calls=%d locked=%v", result, *calls, SiteOpLocked(payload.Site.ID))
			}
		})
	}
}

func TestDatabaseAdministratorBackupRetainsVerifiedInheritedOperation(t *testing.T) {
	payload, calls := setupDatabaseBackupOperationTest(t)
	if !TryAcquireSiteOpLock(payload.Site.ID, "wp_administrator_update") {
		t.Fatal("fixture administrator lock unavailable")
	}
	payload.SiteOperation = CaptureDatabaseBackupSiteOperation(payload.Site.ID)
	if payload.SiteOperation == nil {
		t.Fatal("owned administrator slot was not captured")
	}
	result := executeCreateBackup(&Task{Payload: payload})
	if !result.Success || *calls != 1 || !SiteOpLocked(payload.Site.ID) {
		t.Fatalf("inherited backup failed or released caller: %+v calls=%d", result, *calls)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var restored CreateBackupPayload
	if json.Unmarshal(encoded, &restored) != nil || restored.SiteOperation != nil {
		t.Fatal("opaque ownership was serialized as a public capability")
	}
}

func TestDatabaseInheritedBackupRejectsStaleSameReasonOwner(t *testing.T) {
	payload, calls := setupDatabaseBackupOperationTest(t)
	if !TryAcquireSiteOpLock(payload.Site.ID, "wp_administrator_update") {
		t.Fatal("first owner unavailable")
	}
	payload.SiteOperation = CaptureDatabaseBackupSiteOperation(payload.Site.ID)
	ReleaseSiteOpLock(payload.Site.ID)
	if !TryAcquireSiteOpLock(payload.Site.ID, "wp_administrator_update") {
		t.Fatal("second owner unavailable")
	}
	result := executeCreateBackup(&Task{Payload: payload})
	if result.Success || !strings.Contains(result.Message, "归属已失效") || *calls != 0 || !SiteOpLocked(payload.Site.ID) {
		t.Fatalf("stale owner was accepted: %+v calls=%d", result, *calls)
	}
}
