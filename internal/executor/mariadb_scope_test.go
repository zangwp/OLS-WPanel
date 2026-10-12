package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestMariaDBScopeProcessHelper(t *testing.T) {
	if os.Getenv("OLS_DB_SCOPE_HELPER") != "1" {
		return
	}
	if os.Getenv("OLS_DB_SCOPE_SLOW") == "1" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	input, _ := io.ReadAll(os.Stdin)
	f, err := os.OpenFile(os.Getenv("OLS_DB_SCOPE_OUTPUT"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(2)
	}
	_, _ = f.WriteString(strings.Join(os.Args[3:], "\n") + "\n" + string(input) + "\n")
	_ = f.Close()
	if os.Getenv("OLS_DB_SCOPE_SIZES") == "1" {
		_, _ = os.Stdout.WriteString("site_db\t4096\n")
	}
	os.Exit(0)
}

func databaseScopeProcess(ctx context.Context, _ string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestMariaDBScopeProcessHelper$", "--"}, args...)...)
}

func TestMariaDBCreationGrantsOnlyLiteralSelectedSchema(t *testing.T) {
	old := runMariaDBManagementCommand
	runMariaDBManagementCommand = func(name string, args ...string) *exec.Cmd {
		return databaseScopeProcess(context.Background(), name, args...)
	}
	t.Cleanup(func() { runMariaDBManagementCommand = old })
	t.Setenv("OLS_DB_SCOPE_HELPER", "1")
	cfg := &config.Config{}
	cfg.MariaDB.RootUser, cfg.MariaDB.RootPassword = "root", "fixture-only"
	for _, migration := range []bool{false, true} {
		output := filepath.Join(t.TempDir(), "commands")
		t.Setenv("OLS_DB_SCOPE_OUTPUT", output)
		var err error
		if migration {
			err = createMigrationMariaDBDatabase("site_db", "site_user", strings.Repeat("a", 24), cfg)
		} else {
			err = createMariaDBDatabase("site_db", "site_user", "fixture-only", cfg)
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		sql := string(body)
		if !strings.Contains(sql, "CREATE DATABASE") || !strings.Contains(sql, "`site_db` CHARACTER SET") || !strings.Contains(sql, "GRANT ALL PRIVILEGES ON `site\\_db`.*") || strings.Contains(sql, "GRANT ALL PRIVILEGES ON `site_db`.*") {
			t.Fatalf("migration=%v selected database/grant mismatch: %s", migration, sql)
		}
	}
}

func TestMariaDBSizeReadReturnsUnknownOnDeadlineAndActualSizeOnSuccess(t *testing.T) {
	old, timeout := runMariaDBSizeCommand, mariaDBSizeReadTimeout
	runMariaDBSizeCommand = databaseScopeProcess
	mariaDBSizeReadTimeout = 100 * time.Millisecond
	t.Cleanup(func() { runMariaDBSizeCommand, mariaDBSizeReadTimeout = old, timeout })
	t.Setenv("OLS_DB_SCOPE_HELPER", "1")
	t.Setenv("OLS_DB_SCOPE_OUTPUT", filepath.Join(t.TempDir(), "commands"))
	t.Setenv("OLS_DB_SCOPE_SLOW", "1")
	cfg := &config.Config{}
	cfg.MariaDB.RootUser, cfg.MariaDB.RootPassword = "root", "fixture-only"
	started := time.Now()
	if result, err := GetMariaDBDatabaseSizes(cfg); result != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline was represented as valid sizes: %v, %v", result, err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("database size subprocess exceeded cancellation budget")
	}
	t.Setenv("OLS_DB_SCOPE_SLOW", "0")
	t.Setenv("OLS_DB_SCOPE_SIZES", "1")
	mariaDBSizeReadTimeout = 5 * time.Second
	if sizes, err := GetMariaDBDatabaseSizes(cfg); err != nil || sizes["site_db"] != 4096 {
		t.Fatalf("valid size read failed: %v, %v", sizes, err)
	}
}
