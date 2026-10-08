package database

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenExistingNeverCreatesDatabaseOrDirectories(t *testing.T) {
	for _, readOnly := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "missing-dir", "panel.db")
		if err := OpenExisting(path, readOnly); err == nil {
			t.Fatal("missing database was accepted")
		}
		if _, err := os.Lstat(filepath.Dir(path)); !os.IsNotExist(err) {
			t.Fatalf("missing directory was created: %v", err)
		}
		if GetDB() != nil {
			t.Fatal("failed open installed a database handle")
		}
	}
}

func TestOpenExistingReadOnlyPreservesJournalAndSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel # %.db")
	if err := Open(path); err != nil {
		t.Fatal(err)
	}
	if _, err := GetDB().Exec("CREATE TABLE cli_fixture (value TEXT); INSERT INTO cli_fixture VALUES ('existing')"); err != nil {
		t.Fatal(err)
	}
	// Starting from a non-WAL database verifies this maintenance path does not
	// reuse Open's automatic journal-mode change.
	if _, err := GetDB().Exec("PRAGMA journal_mode=DELETE"); err != nil {
		t.Fatal(err)
	}
	if err := Close(); err != nil {
		t.Fatal(err)
	}
	if err := OpenExisting(path, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Close() })
	var value, journal string
	if err := GetDB().QueryRow("SELECT value FROM cli_fixture").Scan(&value); err != nil || value != "existing" {
		t.Fatalf("value=%q error=%v", value, err)
	}
	if err := GetDB().QueryRow("PRAGMA journal_mode").Scan(&journal); err != nil || journal != "delete" {
		t.Fatalf("journal=%q error=%v", journal, err)
	}
	if _, err := GetDB().Exec("INSERT INTO cli_fixture VALUES ('unexpected')"); err == nil {
		t.Fatal("read-only CLI database accepted a write")
	}
	var tables int
	if err := GetDB().QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&tables); err != nil || tables != 1 {
		t.Fatalf("tables=%d error=%v", tables, err)
	}
}

func TestOpenExistingWritableKeepsExistingSchemaAndRejectsSecondOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	if err := Open(path); err != nil {
		t.Fatal(err)
	}
	if _, err := GetDB().Exec("CREATE TABLE cli_fixture (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := Close(); err != nil {
		t.Fatal(err)
	}
	if err := OpenExisting(path, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Close() })
	if _, err := GetDB().Exec("INSERT INTO cli_fixture VALUES ('audit')"); err != nil {
		t.Fatal(err)
	}
	var journal string
	if err := GetDB().QueryRow("PRAGMA journal_mode").Scan(&journal); err != nil || journal != "wal" {
		t.Fatalf("journal=%q error=%v", journal, err)
	}
	original := GetDB()
	if err := OpenExisting(path, true); err == nil || GetDB() != original {
		t.Fatal("second open replaced the existing database handle")
	}
}

func TestOpenExistingRejectsRelativeDirectoryAndSymlinkPaths(t *testing.T) {
	if err := OpenExisting("relative.db", true); err == nil {
		t.Fatal("relative path accepted")
	}
	dir := t.TempDir()
	if err := OpenExisting(dir, false); err == nil {
		t.Fatal("directory accepted")
	}
	file := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(file, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := OpenExisting(link, false); err == nil {
		t.Fatal("symlink accepted")
	}
}
