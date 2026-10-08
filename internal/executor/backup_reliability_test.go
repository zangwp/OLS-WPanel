package executor

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// Exercise the production subprocess/pipe paths without a MariaDB daemon. The
// child models durable table state so tests observe the rollback result, not
// merely a sequence of mock calls.
func TestDatabaseBackupProcessHelper(t *testing.T) {
	if os.Getenv("OLS_BACKUP_TEST_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(2)
	}
	command := args[1]
	statePath := os.Getenv("OLS_BACKUP_TEST_STATE")
	fail := func(message string) {
		fmt.Fprintln(os.Stderr, message)
		os.Exit(1)
	}
	if command == "flood" {
		buf := make([]byte, 64*1024)
		for {
			_, _ = rand.Read(buf)
			if _, err := os.Stdout.Write(buf); err != nil {
				os.Exit(1)
			}
		}
	}
	if command == "mysqldump" {
		if os.Getenv("OLS_BACKUP_TEST_DUMP_FAIL") == "1" {
			fail("snapshot unavailable")
		}
		state, err := os.ReadFile(statePath)
		if err != nil {
			fail(err.Error())
		}
		fmt.Printf("CREATE TABLE original (id int);\nINSERT INTO original VALUES (1);\n-- ORIGINAL_%s\n", state)
		os.Exit(0)
	}
	if command != "mysql" {
		fail("unexpected command")
	}
	for index, arg := range args[2:] {
		if arg == "-e" {
			if index+3 < len(args) && strings.Contains(args[index+3], "INFORMATION_SCHEMA.ROUTINES") {
				fmt.Println("DROP VIEW IF EXISTS imported_view;")
			}
			fmt.Println("DROP TABLE IF EXISTS original;")
			os.Exit(0)
		}
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err.Error())
	}
	sql := string(input)
	state := ""
	switch {
	case strings.Contains(sql, "INVALID_IMPORT"):
		_ = os.WriteFile(statePath, []byte("partial"), 0600)
		if strings.Contains(sql, "CREATE VIEW") {
			_ = os.WriteFile(statePath+".view", []byte("unexpected view"), 0600)
		}
		fail("injected import error after partial write")
	case strings.Contains(sql, "ORIGINAL_original"):
		if os.Getenv("OLS_BACKUP_TEST_ROLLBACK_FAIL") == "1" {
			fail("injected rollback error")
		}
		state = "original"
	case strings.Contains(sql, "REPLACEMENT"):
		state = "replacement"
	case strings.Contains(sql, "DROP TABLE"):
		state = ""
		if strings.Contains(sql, "DROP VIEW") {
			_ = os.Remove(statePath + ".view")
		}
	default:
		fail("unexpected SQL")
	}
	if err := os.WriteFile(statePath, []byte(state), 0600); err != nil {
		fail(err.Error())
	}
	os.Exit(0)
}

func backupTestCommand(ctx context.Context, command string, args ...string) *exec.Cmd {
	childArgs := append([]string{"-test.run=^TestDatabaseBackupProcessHelper$", "--", command}, args...)
	return exec.CommandContext(ctx, os.Args[0], childArgs...)
}

func setupDatabaseRestoreTest(t *testing.T, sql string) (*Task, string, string) {
	t.Helper()
	openTestDB(t)
	domain := "restore.example.com"
	insertMinimalWebsite(t, domain)
	root := t.TempDir()
	backupDir := filepath.Join(root, domain, "db")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "source.sql"), []byte(sql), 0600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "database-state")
	if err := os.WriteFile(statePath, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OLS_BACKUP_TEST_HELPER", "1")
	t.Setenv("OLS_BACKUP_TEST_STATE", statePath)
	oldCommand, oldPassword, oldConfig := databaseBackupCommand, restoreBackupPassword, config.AppConfig
	databaseBackupCommand = backupTestCommand
	restoreBackupPassword = func() string { return "test-password" }
	config.AppConfig = &config.Config{Panel: config.PanelConfig{BackupDir: root}}
	t.Cleanup(func() {
		databaseBackupCommand, restoreBackupPassword, config.AppConfig = oldCommand, oldPassword, oldConfig
	})
	return &Task{Payload: &RestoreBackupPayload{Site: &models.Website{ID: 1, Domain: domain, DBName: "db1"}, Filename: "source.sql"}}, statePath, filepath.Join(root, domain, "restore-safety")
}

func TestExecuteRestoreBackupRollsBackFailedImport(t *testing.T) {
	task, state, safetyRoot := setupDatabaseRestoreTest(t, "CREATE TABLE replacement (id int);\nCREATE VIEW imported_view AS SELECT 1;\nINVALID_IMPORT;\n")
	result := executeRestoreBackup(task)
	if result.Success || !strings.Contains(result.Message, "已自动恢复") {
		t.Fatalf("result = %#v, want failed operation with successful rollback", result)
	}
	if got, err := os.ReadFile(state); err != nil || string(got) != "original" {
		t.Fatalf("database = %q, error = %v, want original data", got, err)
	}
	if _, err := os.Stat(state + ".view"); !os.IsNotExist(err) {
		t.Fatalf("failed import left an unexpected view after rollback: %v", err)
	}
	entries, err := os.ReadDir(safetyRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("completed rollback left temporary snapshots: %v, %v", entries, err)
	}
}

func TestExecuteRestoreBackupStopsBeforeDeleteWhenSnapshotFails(t *testing.T) {
	task, state, _ := setupDatabaseRestoreTest(t, "CREATE TABLE replacement (id int); -- REPLACEMENT\n")
	t.Setenv("OLS_BACKUP_TEST_DUMP_FAIL", "1")
	result := executeRestoreBackup(task)
	if result.Success || !strings.Contains(result.Message, "数据库未修改") {
		t.Fatalf("result = %#v", result)
	}
	if got, err := os.ReadFile(state); err != nil || string(got) != "original" {
		t.Fatalf("database changed despite failed safety snapshot: %q, %v", got, err)
	}
}

func TestExecuteRestoreBackupRetainsSnapshotWhenRollbackFails(t *testing.T) {
	task, _, safetyRoot := setupDatabaseRestoreTest(t, "CREATE TABLE replacement (id int);\nINVALID_IMPORT;\n")
	t.Setenv("OLS_BACKUP_TEST_ROLLBACK_FAIL", "1")
	result := executeRestoreBackup(task)
	if result.Success || !strings.Contains(result.Message, "自动回滚失败") {
		t.Fatalf("result = %#v", result)
	}
	paths, err := filepath.Glob(filepath.Join(safetyRoot, "restore-*", "before-restore.sql.gz"))
	if err != nil || len(paths) != 1 || !strings.Contains(result.Message, paths[0]) {
		t.Fatalf("rollback copy not retained/reported: paths = %v, result = %#v, err = %v", paths, result, err)
	}
	if err := verifyDatabaseSnapshot(paths[0]); err != nil {
		t.Fatalf("retained snapshot is not valid: %v", err)
	}
}

func TestExecuteRestoreBackupSucceedsAndCleansSnapshot(t *testing.T) {
	task, state, safetyRoot := setupDatabaseRestoreTest(t, "CREATE TABLE replacement (id int); -- REPLACEMENT\n")
	result := executeRestoreBackup(task)
	if !result.Success {
		t.Fatalf("result = %#v", result)
	}
	if got, err := os.ReadFile(state); err != nil || string(got) != "replacement" {
		t.Fatalf("database = %q, error = %v", got, err)
	}
	entries, err := os.ReadDir(safetyRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("successful restore left temporary snapshots: %v, %v", entries, err)
	}
}

func TestRestoreBackupCleansUploadWhenSiteBusy(t *testing.T) {
	openTestDB(t)
	insertMinimalWebsite(t, "busy.example.com")
	if !TryAcquireSiteOpLock(1, "other-operation") {
		t.Fatal("acquire site lock")
	}
	defer ReleaseSiteOpLock(1)
	file, err := os.CreateTemp("", "olswpanel_upload_*.sql")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	_ = file.Close()
	defer os.Remove(path)
	result := executeRestoreBackup(&Task{Payload: &RestoreBackupPayload{
		Site: &models.Website{ID: 1}, FilePath: path, RemoveFileAfter: true,
	}})
	if result.Success || !strings.Contains(result.Message, "维护操作") {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rejected upload remains: %v", err)
	}
	if !SiteOpLocked(1) {
		t.Fatal("must not release another operation's site lock")
	}
}

func TestRestoreBackupDoesNotDeleteUnownedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "must-remain.sql")
	if err := os.WriteFile(path, []byte("unrelated file"), 0600); err != nil {
		t.Fatal(err)
	}
	result := executeRestoreBackup(&Task{Payload: &RestoreBackupPayload{
		Site: &models.Website{ID: 1}, FilePath: path, RemoveFileAfter: true,
	}})
	if result.Success || !strings.Contains(result.Message, "路径不合法") {
		t.Fatalf("result = %#v", result)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "unrelated file" {
		t.Fatalf("unowned file changed: %q, %v", got, err)
	}
}

func TestRestoreBackupReleasesTransferredLockOnQueryFailure(t *testing.T) {
	openTestDB(t)
	insertMinimalWebsite(t, "busy.example.com")
	if !TryAcquireSiteOpLock(1, "wp_update_restore") {
		t.Fatal("acquire site lock")
	}
	defer ReleaseSiteOpLock(1)
	if err := database.GetDB().Close(); err != nil {
		t.Fatal(err)
	}
	result := executeRestoreBackup(&Task{Payload: &RestoreBackupPayload{
		Site: &models.Website{ID: 1}, UpdateBackupPath: "/unused/backup.sql.gz",
	}})
	if result.Success || !strings.Contains(result.Message, "检查 AI") {
		t.Fatalf("result = %#v", result)
	}
	if SiteOpLocked(1) {
		t.Fatal("failed task leaked the transferred site lock")
	}
}

func TestVerifyDatabaseSnapshotRejectsCorruptTrailer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	_, _ = io.WriteString(gz, "CREATE TABLE original (id int);\n")
	_ = gz.Close()
	_ = f.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-5] ^= 0xff
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDatabaseSnapshot(path); err == nil {
		t.Fatal("snapshot checksum corruption was ignored")
	}
}

func TestDatabaseDumpWriteFailureStopsProducerPromptly(t *testing.T) {
	t.Setenv("OLS_BACKUP_TEST_HELPER", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := backupTestCommand(ctx, "flood")
	started := time.Now()
	err := streamDatabaseDumpToGzip(ctx, cancel, cmd, &failingWriter{limit: 4096})
	if err == nil || !strings.Contains(err.Error(), "写入备份失败") {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 8*time.Second {
		t.Fatalf("producer was not stopped promptly: %v", elapsed)
	}
	if ctx.Err() != context.Canceled || cmd.ProcessState == nil {
		t.Fatalf("producer was not canceled and reaped: context = %v, state = %v", ctx.Err(), cmd.ProcessState)
	}
}
