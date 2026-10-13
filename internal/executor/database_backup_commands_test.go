package executor

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDatabaseBackupCommandSelectionMatchesHealth(t *testing.T) {
	oldLookup := backupDependencyLookPath
	t.Cleanup(func() { backupDependencyLookPath = oldLookup })
	for _, name := range []string{"mysql", "mysqldump"} {
		candidates := backupCommandCandidates(name)
		for _, missing := range [][]string{nil, {name}, candidates} {
			backupDependencyLookPath = backupDependencyTestLookup(missing...)
			args := []string{"--raw", "database_name", "literal; argument"}
			cmd := newDatabaseBackupCommand(context.Background(), name, args...)
			path, err := findBackupCommand(candidates, backupDependencyLookPath)
			if err != nil {
				if !errors.Is(cmd.Start(), exec.ErrNotFound) {
					t.Fatalf("missing %s command was allowed to run: %v", name, cmd.Err)
				}
				continue
			}
			if cmd.Err != nil || cmd.Path != path || !reflect.DeepEqual(cmd.Args[1:], args) {
				t.Fatalf("execution diverged from health or changed arguments: %+v; path=%q", cmd, path)
			}
		}
	}
	for _, failure := range []error{exec.ErrDot, os.ErrPermission} {
		calls := 0
		backupDependencyLookPath = func(string) (string, error) { calls++; return "", failure }
		cmd := newDatabaseBackupCommand(context.Background(), "mysql", "--version")
		if calls != 1 || !errors.Is(cmd.Start(), failure) {
			t.Fatalf("unsafe command lookup silently fell back: calls=%d err=%v", calls, cmd.Err)
		}
	}
}

// Exercise real subprocesses through the selected native command path. The
// existing helper models database state while the product owns dump, restore,
// isolated import credentials and rollback sequencing.
func TestNativeDatabaseBackupCommandsCoverRestoreAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name, sql, wantState string
		success              bool
	}{
		{"restore", "CREATE TABLE replacement (id int); -- REPLACEMENT\n", "replacement", true},
		{"rollback", "CREATE TABLE replacement (id int);\nINVALID_IMPORT;\n", "original", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task, statePath, _ := setupDatabaseRestoreTest(t, tc.sql)
			oldLookup := backupDependencyLookPath
			t.Cleanup(func() { backupDependencyLookPath = oldLookup })
			used := map[string]int{}
			backupDependencyLookPath = func(name string) (string, error) {
				switch name {
				case "mysql", "mysqldump":
					return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
				case "mariadb", "mariadb-dump":
					used[name]++
					return os.Args[0], nil
				default:
					return oldLookup(name)
				}
			}
			databaseBackupCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				childArgs := append([]string{"-test.run=^TestDatabaseBackupProcessHelper$", "--", name}, args...)
				return newDatabaseBackupCommand(ctx, name, childArgs...)
			}
			// Whole-site snapshots use the same native dump selection.
			snapshot := filepath.Join(t.TempDir(), "site.sql.gz")
			if err := dumpSiteBackupDatabase(context.Background(), "db1", "test-password", snapshot); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			gz, err := gzip.NewReader(file)
			if err != nil {
				file.Close()
				t.Fatal(err)
			}
			data, err := io.ReadAll(gz)
			gz.Close()
			file.Close()
			if err != nil || !strings.Contains(string(data), "ORIGINAL_original") {
				t.Fatalf("native dump not stored as valid SQL gzip: %q, %v", data, err)
			}
			result := executeRestoreBackup(task)
			if result.Success != tc.success {
				t.Fatalf("unexpected restore result: %+v", result)
			}
			state, err := os.ReadFile(statePath)
			if err != nil || string(state) != tc.wantState {
				t.Fatalf("database state=%q, expected %q: %v; %+v", state, tc.wantState, err, result)
			}
			if used["mariadb"] == 0 || used["mariadb-dump"] < 2 {
				t.Fatalf("restore and safety snapshot did not use native commands: %v", used)
			}
		})
	}
}
