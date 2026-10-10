package database

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupPanelBackupTestDB(t *testing.T) (string, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE sample (value TEXT NOT NULL); INSERT INTO sample VALUES ('original')`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	previous := DB
	DB = db
	t.Cleanup(func() {
		_ = db.Close()
		DB = previous
	})
	return filepath.Join(dir, "backups"), db
}

func panelBackupSample(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var value string
	if err := db.QueryRow(`SELECT value FROM sample`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestBackupDatabaseSameSecondPreservesExistingValidSnapshot(t *testing.T) {
	dir, db := setupPanelBackupTestDB(t)
	now := time.Date(2026, 10, 10, 2, 30, 0, 0, time.Local)
	first, err := backupDatabaseAt(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(first) != "panel_20261010_023000.db" {
		t.Fatalf("legacy filename = %q", filepath.Base(first))
	}
	before, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sample SET value = 'changed'`); err != nil {
		t.Fatal(err)
	}
	second, err := backupDatabaseAt(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("same-second backup reused the existing filename")
	}
	after, err := os.ReadFile(first)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("existing backup changed or was removed: %v", err)
	}
	if got := panelBackupSample(t, first); got != "original" {
		t.Fatalf("old snapshot = %q", got)
	}
	if got := panelBackupSample(t, second); got != "changed" {
		t.Fatalf("new snapshot = %q", got)
	}
	for _, path := range []string{first, second} {
		if err := VerifyDBBackup(path); err != nil {
			t.Fatalf("snapshot integrity %q: %v", path, err)
		}
		if restored, err := RestoreDBBackupPath(dir, filepath.Base(path)); err != nil || restored != path {
			t.Fatalf("snapshot remains selectable: path=%q error=%v", restored, err)
		}
	}
	backups, err := ListDBBackups(dir)
	if err != nil || len(backups) != 2 {
		t.Fatalf("list = %#v, error = %v", backups, err)
	}
	if backups[0].Filename != filepath.Base(second) || backups[1].Filename != filepath.Base(first) {
		t.Fatalf("same-second ordering = %#v", backups)
	}
	for _, backup := range backups {
		if backup.CreatedAt != "2026-10-10 02:30:00" {
			t.Fatalf("legacy/new display timestamp = %q", backup.CreatedAt)
		}
	}
}

func TestBackupDatabaseRapidSameSecondSnapshotsRemainDistinctAndOrdered(t *testing.T) {
	dir, db := setupPanelBackupTestDB(t)
	now := time.Date(2026, 10, 10, 2, 30, 0, 0, time.Local)
	var paths []string
	for i := 0; i < 4; i++ {
		value := fmt.Sprintf("snapshot-%d", i)
		if _, err := db.Exec(`UPDATE sample SET value = ?`, value); err != nil {
			t.Fatal(err)
		}
		path, err := backupDatabaseAt(dir, now)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	for i, path := range paths {
		if got, want := panelBackupSample(t, path), fmt.Sprintf("snapshot-%d", i); got != want {
			t.Fatalf("snapshot %d overwritten: got %q, want %q", i, got, want)
		}
	}
	if removed := CleanupOldDBBackups(dir, 2); removed != 2 {
		t.Fatalf("retention removed %d backups, want 2", removed)
	}
	backups, err := ListDBBackups(dir)
	if err != nil || len(backups) != 2 {
		t.Fatalf("retained list = %#v, error = %v", backups, err)
	}
	for i, backup := range backups {
		if backup.Filename != filepath.Base(paths[3-i]) {
			t.Fatalf("retention kept wrong snapshot: %#v", backups)
		}
	}
}

func TestBackupDatabaseFailureOnlyCleansItsReservedFile(t *testing.T) {
	dir, db := setupPanelBackupTestDB(t)
	now := time.Date(2026, 10, 10, 2, 30, 0, 0, time.Local)
	snapshots := make(map[string][]byte)
	for i := 0; i < 2; i++ {
		path, err := backupDatabaseAt(dir, now)
		if err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		snapshots[path] = content
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if path, err := backupDatabaseAt(dir, now); err == nil || path != "" {
		t.Fatalf("closed database should fail: path=%q error=%v", path, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(snapshots) {
		t.Fatalf("failed backup left a new file or removed an existing one: entries=%v error=%v", entries, err)
	}
	for path, before := range snapshots {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("failed backup changed %q: %v", path, err)
		}
		if err := VerifyDBBackup(path); err != nil {
			t.Fatalf("existing snapshot is no longer valid: %v", err)
		}
	}
}

func TestVerifyDBBackup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "panel_valid.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE sample (id INTEGER PRIMARY KEY, name TEXT)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec("INSERT INTO sample (name) VALUES (?)", "ok"); err != nil {
		t.Fatalf("insert sample: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}

	if err := VerifyDBBackup(dbPath); err != nil {
		t.Fatalf("VerifyDBBackup(valid) error = %v", err)
	}
}

func TestVerifyDBBackupRejectsInvalidSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel_bad.db")
	if err := os.WriteFile(path, []byte("not a sqlite database"), 0600); err != nil {
		t.Fatalf("write invalid db: %v", err)
	}

	if err := VerifyDBBackup(path); err == nil {
		t.Fatal("VerifyDBBackup(invalid) error = nil, want error")
	}
}

func TestRestoreDBBackupPathValidatesFilename(t *testing.T) {
	dir := t.TempDir()
	validName := "panel_20260107_023000.db"
	if err := os.WriteFile(filepath.Join(dir, validName), []byte("x"), 0600); err != nil {
		t.Fatalf("write valid backup: %v", err)
	}

	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: validName, wantErr: false},
		{name: "panel_missing.db", wantErr: true},
		{name: "../" + validName, wantErr: true},
		{name: `..\` + validName, wantErr: true},
		{name: "evil.db", wantErr: true},
		{name: "panel_20260107_023000.txt", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RestoreDBBackupPath(dir, tt.name)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RestoreDBBackupPath(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestDBBackupSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_version(version TEXT NOT NULL,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP); INSERT INTO schema_version(version) VALUES ('9.1.2')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	version, err := DBBackupSchemaVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if version != "9.1.2" {
		t.Fatalf("version = %q", version)
	}
}
