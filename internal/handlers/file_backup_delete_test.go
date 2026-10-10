package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

type fileBackupDeleteLock struct{ closed bool }

func (lock *fileBackupDeleteLock) Close() error {
	lock.closed = true
	return nil
}

func setupFileBackupDeleteFixture(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	setupBackupOverviewTestDB(t)
	db := database.GetDB()
	if _, err := db.Exec(`INSERT INTO websites (id, name, domain, system_user, web_root, log_dir, db_name, db_user, lsphp_socket_path, ols_vhost_config_path)
		VALUES (1, 'site', 'delete-baseline.example.com', 'u1', '/www/wwwroot/delete-baseline.example.com', '/www/wwwlogs/delete-baseline.example.com', 'db1', 'u1', '/p', '/n')`); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	oldRoot := fileBackupStorageRoot
	fileBackupStorageRoot = root
	t.Cleanup(func() { fileBackupStorageRoot = oldRoot })
	dir := filepath.Join(root, "delete-baseline.example.com", "files")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"file_full_old.tar.gz", "file_full_current.tar.gz", ".last_backup.stamp"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO file_backups (id, site_id, filename, file_size, mode) VALUES
		(1, 1, 'file_full_old.tar.gz', 7, 'full'), (2, 1, 'file_full_current.tar.gz', 7, 'full')`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	handler := &BackupHandler{}
	router.DELETE("/api/websites/:id/file-backups/:bid", handler.DeleteFileBackup)
	return router, dir
}

func TestDeleteCurrentFileBaselineInvalidatesCutoffAndKeepsOlderFull(t *testing.T) {
	for _, remoteEnabled := range []int{0, 1} {
		t.Run(map[int]string{0: "local only", 1: "remote enabled"}[remoteEnabled], func(t *testing.T) {
			router, dir := setupFileBackupDeleteFixture(t)
			if _, err := database.GetDB().Exec("UPDATE remote_backup_settings SET enabled = ? WHERE id = 1", remoteEnabled); err != nil {
				t.Fatal(err)
			}
			lock := &fileBackupDeleteLock{}
			acquireFileBackupOperationLock = func(context.Context) (io.Closer, error) { return lock, nil }
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/websites/1/file-backups/2", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
			}
			if !lock.closed {
				t.Fatal("delete operation did not release its shared backup lock")
			}
			for _, name := range []string{"file_full_current.tar.gz", ".last_backup.stamp"} {
				if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
					t.Fatalf("current baseline deletion left %s: %v", name, err)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "file_full_old.tar.gz")); err != nil {
				t.Fatalf("retained older full backup was removed: %v", err)
			}
			var count int
			if err := database.GetDB().QueryRow("SELECT COUNT(*) FROM file_backups WHERE id = 2").Scan(&count); err != nil || count != 0 {
				t.Fatalf("deleted baseline record count=%d err=%v", count, err)
			}
		})
	}
}

func TestDeleteOlderFullBackupKeepsCurrentIncrementalCutoff(t *testing.T) {
	router, dir := setupFileBackupDeleteFixture(t)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/websites/1/file-backups/1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, name := range []string{"file_full_current.tar.gz", ".last_backup.stamp"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("deleting an older retained full invalidated %s: %v", name, err)
		}
	}
}

func TestDeleteCurrentFileBaselineAbortsWhenCutoffCannotBeInvalidated(t *testing.T) {
	router, dir := setupFileBackupDeleteFixture(t)
	stamp := filepath.Join(dir, ".last_backup.stamp")
	if err := os.Remove(stamp); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stamp, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stamp, "prevent-removal"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/websites/1/file-backups/2", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete status=%d body=%s, want no deletion", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "file_full_current.tar.gz")); err != nil {
		t.Fatalf("baseline file was removed despite invalidation failure: %v", err)
	}
	var count int
	if err := database.GetDB().QueryRow("SELECT COUNT(*) FROM file_backups WHERE id = 2").Scan(&count); err != nil || count != 1 {
		t.Fatalf("baseline record changed after invalidation failure: count=%d err=%v", count, err)
	}
}

func TestDeleteFileBackupCancelledWhileWaitingKeepsFileAndRecord(t *testing.T) {
	router, dir := setupFileBackupDeleteFixture(t)
	acquireFileBackupOperationLock = func(ctx context.Context) (io.Closer, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodDelete, "/api/websites/1/file-backups/2", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("cancelled wait status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, name := range []string{"file_full_current.tar.gz", ".last_backup.stamp"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("cancelled wait modified %s: %v", name, err)
		}
	}
	var count int
	if err := database.GetDB().QueryRow("SELECT COUNT(*) FROM file_backups WHERE id = 2").Scan(&count); err != nil || count != 1 {
		t.Fatalf("cancelled wait changed record: count=%d err=%v", count, err)
	}
}

func TestDeleteFileBackupReadsCurrentRecordOnlyAfterAcquiringLock(t *testing.T) {
	router, dir := setupFileBackupDeleteFixture(t)
	waiting, release := make(chan struct{}), make(chan struct{})
	lock := &fileBackupDeleteLock{}
	acquireFileBackupOperationLock = func(ctx context.Context) (io.Closer, error) {
		close(waiting)
		select {
		case <-release:
			return lock, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		defer close(done)
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/websites/1/file-backups/2", nil).WithContext(ctx))
	}()
	select {
	case <-waiting:
	case <-ctx.Done():
		t.Fatal("delete did not wait for the operation lock")
	}
	// Simulate a creator completing a record update before releasing its lock.
	const freshName = "file_full_refreshed.tar.gz"
	if err := os.WriteFile(filepath.Join(dir, freshName), []byte("updated"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetDB().Exec("UPDATE file_backups SET filename = ? WHERE id = 2", freshName); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("delete did not resume after the operation lock became available")
	}
	if rec.Code != http.StatusOK || !lock.closed {
		t.Fatalf("resumed delete status=%d lock released=%v body=%s", rec.Code, lock.closed, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, freshName)); !os.IsNotExist(err) {
		t.Fatalf("delete used a stale filename read before its lock: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "file_full_current.tar.gz")); err != nil {
		t.Fatalf("delete removed the stale pre-lock filename: %v", err)
	}
}
