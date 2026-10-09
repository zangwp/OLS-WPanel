package executor

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func TestGetSQLiProtectionSettingsReadsExplicitGlobalSwitches(t *testing.T) {
	old := database.DB
	t.Cleanup(func() { database.DB = old })
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	database.DB = db
	if _, err := db.Exec("CREATE TABLE security_settings (skey TEXT PRIMARY KEY, svalue TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if block, ban := GetSQLiProtectionSettings(); !block || !ban {
		t.Fatalf("missing global settings must use defaults; block=%v ban=%v", block, ban)
	}
	for _, tt := range []struct{ block, ban bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		for key, value := range map[string]bool{"wp_sqli_block_enabled": tt.block, "wp_sqli_autoban_enabled": tt.ban} {
			if _, err := db.Exec("INSERT OR REPLACE INTO security_settings(skey,svalue) VALUES (?,?)", key, fmt.Sprint(value)); err != nil {
				t.Fatal(err)
			}
		}
		if block, ban := GetSQLiProtectionSettings(); block != tt.block || ban != tt.ban {
			t.Fatalf("global SQLi settings=(%v,%v), want (%v,%v)", block, ban, tt.block, tt.ban)
		}
	}
}

func TestCleanupOLSVHostConfigBackupsKeepsNewestForTargetOnly(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		"example.com.conf.bak.100",
		"example.com.conf.bak.200",
		"example.com.conf.bak.300",
		"example.com.conf.bak.bad",
		"other.com.conf.bak.100",
		"notes.txt",
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	removed := cleanupOLSVHostConfigBackups(dir, "/usr/local/lsws/conf/ols-wpanel/sites-available/example.com.conf", 2)
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}

	if _, err := os.Stat(filepath.Join(dir, "example.com.conf.bak.100")); !os.IsNotExist(err) {
		t.Fatalf("oldest target backup still exists or stat failed: %v", err)
	}
	for _, name := range []string{
		"example.com.conf.bak.200",
		"example.com.conf.bak.300",
		"example.com.conf.bak.bad",
		"other.com.conf.bak.100",
		"notes.txt",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s should remain: %v", name, err)
		}
	}
}

func TestCleanupOLSVHostConfigBackupsDefaultsKeepCount(t *testing.T) {
	dir := t.TempDir()
	for i := int64(1); i <= olsVHostConfigBackupKeepCount+1; i++ {
		name := fmt.Sprintf("example.com.conf.bak.%d", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	removed := cleanupOLSVHostConfigBackups(dir, "/usr/local/lsws/conf/ols-wpanel/sites-available/example.com.conf", 0)
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
}

func TestCleanupOLSVHostConfigBackupsNoopCases(t *testing.T) {
	target := "/usr/local/lsws/conf/ols-wpanel/sites-available/example.com.conf"
	if removed := cleanupOLSVHostConfigBackups(filepath.Join(t.TempDir(), "missing"), target, 2); removed != 0 {
		t.Fatalf("missing dir removed = %d, want 0", removed)
	}

	dir := t.TempDir()
	for _, name := range []string{"other.conf.bak.1", "example.com.conf.tmp", "example.com.conf.bak.bad"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if removed := cleanupOLSVHostConfigBackups(dir, target, 2); removed != 0 {
		t.Fatalf("unmatched files removed = %d, want 0", removed)
	}

	for _, name := range []string{"example.com.conf.bak.1", "example.com.conf.bak.2"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if removed := cleanupOLSVHostConfigBackups(dir, target, 2); removed != 0 {
		t.Fatalf("exact keep count removed = %d, want 0", removed)
	}
}
