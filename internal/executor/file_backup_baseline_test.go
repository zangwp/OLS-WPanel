package executor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func writeFullBaselineFixture(t *testing.T, dir, name string) int64 {
	t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	content := []byte("baseline upload")
	if err := tw.WriteHeader(&tar.Header{Name: "site/wp-content/uploads/old.txt", Mode: 0644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return int64(data.Len())
}

func TestLocalFileBackupBaselineDeterminesFullOrIncremental(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wantFull bool
	}{
		{"valid current full", false},
		{"current full missing with older full retained", true},
		{"last full file and record deleted", true},
		{"archive exists without a full record", true},
		{"current full truncated", true},
		{"current full replaced by a directory", true},
		{"stamp removed after deleting the current baseline", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			openTestDB(t)
			insertMinimalWebsite(t, "baseline.example.com")
			dir := t.TempDir()
			stamp := filepath.Join(dir, ".last_backup.stamp")
			if err := os.WriteFile(stamp, []byte("previous cutoff"), 0600); err != nil {
				t.Fatal(err)
			}
			const current = "file_full_current.tar.gz"
			size := writeFullBaselineFixture(t, dir, current)
			db := database.GetDB()
			if tc.name == "current full missing with older full retained" || tc.name == "stamp removed after deleting the current baseline" {
				oldSize := writeFullBaselineFixture(t, dir, "file_full_old.tar.gz")
				if _, err := db.Exec(`INSERT INTO file_backups (id, site_id, filename, file_size, mode) VALUES (1, 1, 'file_full_old.tar.gz', ?, 'full')`, oldSize); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name != "archive exists without a full record" {
				if _, err := db.Exec(`INSERT INTO file_backups (id, site_id, filename, file_size, mode) VALUES (2, 1, ?, ?, 'full')`, current, size); err != nil {
					t.Fatal(err)
				}
			}
			switch tc.name {
			case "current full missing with older full retained":
				if err := os.Remove(filepath.Join(dir, current)); err != nil {
					t.Fatal(err)
				}
			case "last full file and record deleted", "stamp removed after deleting the current baseline":
				if err := os.Remove(filepath.Join(dir, current)); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("DELETE FROM file_backups WHERE id = 2"); err != nil {
					t.Fatal(err)
				}
				if tc.name == "stamp removed after deleting the current baseline" {
					if err := os.Remove(stamp); err != nil {
						t.Fatal(err)
					}
				}
			case "current full truncated":
				if err := os.Truncate(filepath.Join(dir, current), size-1); err != nil {
					t.Fatal(err)
				}
			case "current full replaced by a directory":
				if err := os.Remove(filepath.Join(dir, current)); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(dir, current), 0700); err != nil {
					t.Fatal(err)
				}
			}
			full, err := fileBackupShouldCreateFullContext(context.Background(), 1, "incremental", dir, stamp, false)
			if err != nil || full != tc.wantFull {
				t.Fatalf("backup mode full=%v err=%v, want full=%v", full, err, tc.wantFull)
			}
		})
	}
}

func TestLocalFileBackupBaselineDoesNotHideDatabaseFailure(t *testing.T) {
	openTestDB(t)
	dir := t.TempDir()
	stamp := filepath.Join(dir, ".last_backup.stamp")
	if err := os.WriteFile(stamp, []byte("previous cutoff"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetDB().Exec("DROP TABLE file_backups"); err != nil {
		t.Fatal(err)
	}
	if full, err := fileBackupShouldCreateFullContext(context.Background(), 1, "incremental", dir, stamp, false); err == nil || full {
		t.Fatalf("unreadable baseline metadata selected a new chain: full=%v err=%v", full, err)
	}
	if _, err := os.Stat(stamp); err != nil {
		t.Fatalf("failed baseline lookup modified the existing cutoff: %v", err)
	}
}

func TestRemoteOnlyFileBackupDoesNotRequireLocalBaseline(t *testing.T) {
	dir := t.TempDir()
	stamp := filepath.Join(dir, ".last_backup.stamp")
	if err := os.WriteFile(stamp, []byte("previous cutoff"), 0600); err != nil {
		t.Fatal(err)
	}
	// No database or local archive is needed here: the caller must still run its
	// existing remote-target full-baseline check before creating an increment.
	if full, err := fileBackupShouldCreateFullContext(context.Background(), 1, "incremental", dir, stamp, true); err != nil || full {
		t.Fatalf("remote-only retention forced a local baseline: full=%v err=%v", full, err)
	}
}

func TestLocalFullFileBackupRejectsUnownedOrEmptyBaseline(t *testing.T) {
	dir := t.TempDir()
	const name = "file_full_valid.tar.gz"
	size := writeFullBaselineFixture(t, dir, name)
	for _, candidate := range []struct {
		name string
		size int64
	}{
		{"../" + name, size},
		{"..\\" + name, size},
		{"file_inc_valid.tar.gz", size},
		{name, 0},
		{name, size + 1},
	} {
		if valid, err := validLocalFullFileBackup(dir, candidate.name, candidate.size); err != nil || valid {
			t.Fatalf("invalid baseline %q/%d accepted: valid=%v err=%v", candidate.name, candidate.size, valid, err)
		}
	}
	const link = "file_full_link.tar.gz"
	if err := os.Symlink(filepath.Join(dir, name), filepath.Join(dir, link)); err == nil {
		if valid, err := validLocalFullFileBackup(dir, link, size); err != nil || valid {
			t.Fatalf("symlink baseline accepted: valid=%v err=%v", valid, err)
		}
	}
}

func TestFileBackupOperationLockUsesCreatorLockAndCancellation(t *testing.T) {
	oldPath := fileBackupLockPath
	fileBackupLockPath = filepath.Join(t.TempDir(), "file-backup.lock")
	t.Cleanup(func() { fileBackupLockPath = oldPath })
	creator, err := acquireFileBackupLock(context.Background(), fileBackupLockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer creator.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	operation, err := AcquireFileBackupOperationLock(ctx)
	if operation != nil {
		operation.Close()
		t.Fatal("delete operation acquired the lock while the creator held it")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked operation error=%v, want deadline exceeded", err)
	}
	if err := creator.Close(); err != nil {
		t.Fatal(err)
	}
	operation, err = AcquireFileBackupOperationLock(context.Background())
	if err != nil {
		t.Fatalf("operation could not acquire released creator lock: %v", err)
	}
	if err := operation.Close(); err != nil {
		t.Fatal(err)
	}
}
