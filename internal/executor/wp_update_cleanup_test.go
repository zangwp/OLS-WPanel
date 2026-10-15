package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func resolvedCleanupTask(t *testing.T, store *wpUpdateStore, siteID int, finished time.Time) WPUpdateTask {
	t.Helper()
	task := createAndSealUpdateTask(t, store, siteID, finished.Add(-time.Hour))
	if _, err := store.db.Exec(`UPDATE wp_update_tasks SET status='success',finished_at=? WHERE id=?`, wpUpdateDBTime(finished), task.ID); err != nil {
		t.Fatal(err)
	}
	return task
}

func TestWPUpdateCleanupIsBoundedAndNeverRevisitsCompletedDirectories(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	root := t.TempDir()
	service, err := newWPUpdateArtifactService(store, root, func(context.Context, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < wpUpdateCleanupBatchSize+3; i++ {
		resolvedCleanupTask(t, store, siteID, now.Add(-25*time.Hour))
	}
	if err := service.cleanupExpiredArtifacts(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var count int
	var completed string
	if err := store.db.QueryRow(`SELECT COUNT(*),MIN(task_id) FROM wp_update_artifact_cleanup`).Scan(&count, &completed); err != nil || count != wpUpdateCleanupBatchSize {
		t.Fatalf("first completed=%d err=%v", count, err)
	}
	// An already cleaned task is not reconsidered even if an administrator later
	// places a directory there. Old task IDs are never reused by the worker.
	kept := filepath.Join(root, completed)
	if err := os.Mkdir(kept, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kept, "do-not-revisit"), []byte("kept"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := service.cleanupExpiredArtifacts(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("completed task directory was revisited: %v", err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM wp_update_artifact_cleanup`).Scan(&count); err != nil || count != wpUpdateCleanupBatchSize+3 {
		t.Fatalf("second completed=%d err=%v", count, err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM wp_update_tasks`).Scan(&count); err != nil || count != wpUpdateCleanupBatchSize+3 {
		t.Fatalf("task history count=%d err=%v", count, err)
	}
}

func TestWPUpdateCleanupKeepsAttentionAndReferencedDatabaseBackups(t *testing.T) {
	for _, protection := range []string{"attention", "failed_rollback", "active_reference", "recent_reference", "attention_reference", "failed_rollback_reference"} {
		t.Run(protection, func(t *testing.T) {
			store, siteID := newWPUpdateStoreTest(t)
			root := t.TempDir()
			service, err := newWPUpdateArtifactService(store, root, func(context.Context, string, string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			source := resolvedCleanupTask(t, store, siteID, now.Add(-25*time.Hour))
			dir := filepath.Join(root, source.ID)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "database.sql.gz")
			if err := os.WriteFile(path, []byte("safe backup"), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := store.db.Exec(`INSERT INTO wp_update_task_backups(task_id,kind,file_path,file_size,sha256,created_at) VALUES(?,'database',?,11,?,?)`, source.ID, path, strings.Repeat("a", 64), wpUpdateDBTime(now.Add(-26*time.Hour)))
			if err != nil {
				t.Fatal(err)
			}
			backupID, _ := result.LastInsertId()
			switch protection {
			case "attention":
				_, err = store.db.Exec(`UPDATE wp_update_tasks SET requires_attention=1 WHERE id=?`, source.ID)
			case "failed_rollback":
				_, err = store.db.Exec(`UPDATE wp_update_tasks SET rollback_status='failed' WHERE id=?`, source.ID)
			default:
				dependent := createAndSealUpdateTask(t, store, siteID, now.Add(-time.Hour))
				_, err = store.db.Exec(`UPDATE wp_update_tasks SET database_backup_source_id=? WHERE id=?`, backupID, dependent.ID)
				if protection != "active_reference" {
					_, err = store.db.Exec(`UPDATE wp_update_tasks SET status='failed',finished_at=? WHERE id=?`, wpUpdateDBTime(now.Add(-25*time.Hour)), dependent.ID)
				}
				if protection == "recent_reference" {
					_, err = store.db.Exec(`UPDATE wp_update_tasks SET finished_at=? WHERE id=?`, wpUpdateDBTime(now), dependent.ID)
				}
				if protection == "attention_reference" {
					_, err = store.db.Exec(`UPDATE wp_update_tasks SET requires_attention=1 WHERE id=?`, dependent.ID)
				}
				if protection == "failed_rollback_reference" {
					_, err = store.db.Exec(`UPDATE wp_update_tasks SET rollback_status='failed' WHERE id=?`, dependent.ID)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := service.cleanupExpiredArtifacts(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("protected backup removed: %v", err)
			}
			var marked int
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM wp_update_artifact_cleanup WHERE task_id=?`, source.ID).Scan(&marked); err != nil || marked != 0 {
				t.Fatalf("protected source marked complete=%d err=%v", marked, err)
			}
		})
	}
}

func TestWPUpdateCleanupDoesNotCompleteUnsafeDirectoryAndCancels(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	root := t.TempDir()
	service, _ := newWPUpdateArtifactService(store, root, func(context.Context, string, string) error { return nil })
	now := time.Now().UTC()
	task := resolvedCleanupTask(t, store, siteID, now.Add(-25*time.Hour))
	path := filepath.Join(root, task.ID)
	if err := os.WriteFile(path, []byte("not a task directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := service.cleanupExpiredArtifacts(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var marked int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM wp_update_artifact_cleanup WHERE task_id=?`, task.ID).Scan(&marked); err != nil || marked != 0 {
		t.Fatalf("unsafe task marked=%d err=%v", marked, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.cleanupExpiredArtifacts(ctx, now); err == nil {
		t.Fatal("cancelled cleanup succeeded")
	}
}

func TestWPUpdateCleanupBackoffLetsHealthyTasksPastAnUnsafeFirstBatch(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	root := t.TempDir()
	service, _ := newWPUpdateArtifactService(store, root, func(context.Context, string, string) error { return nil })
	now := time.Now().UTC()
	var retryTask string
	for i := 0; i < wpUpdateCleanupBatchSize; i++ {
		task := resolvedCleanupTask(t, store, siteID, now.Add(-26*time.Hour))
		if i == 0 {
			retryTask = task.ID
		}
		if err := os.WriteFile(filepath.Join(root, task.ID), []byte("unsafe regular file"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		resolvedCleanupTask(t, store, siteID, now.Add(-25*time.Hour))
	}
	if err := service.cleanupExpiredArtifacts(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var retries, completed int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM wp_update_artifact_cleanup_retries`).Scan(&retries); err != nil || retries != wpUpdateCleanupBatchSize {
		t.Fatalf("retries=%d err=%v", retries, err)
	}
	if err := service.cleanupExpiredArtifacts(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM wp_update_artifact_cleanup`).Scan(&completed); err != nil || completed != 3 {
		t.Fatalf("healthy tasks starved: completed=%d err=%v", completed, err)
	}
	if err := os.Remove(filepath.Join(root, retryTask)); err != nil {
		t.Fatal(err)
	}
	if err := service.cleanupExpiredArtifacts(context.Background(), now.Add(wpUpdateCleanupRetryDelay+time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM wp_update_artifact_cleanup WHERE task_id=?`, retryTask).Scan(&completed); err != nil || completed != 1 {
		t.Fatalf("repaired task did not retry: completed=%d err=%v", completed, err)
	}
}

func TestWPUpdateLogCleanupUsesBoundedBatchesWithoutDeletingHistory(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	service, _ := newWPUpdateArtifactService(store, t.TempDir(), func(context.Context, string, string) error { return nil })
	now := time.Now().UTC()
	task := resolvedCleanupTask(t, store, siteID, now.Add(-8*24*time.Hour))
	if _, err := store.db.Exec(`DELETE FROM wp_update_task_events WHERE task_id=?`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?) INSERT INTO wp_update_task_events(task_id,stage,result,created_at) SELECT ?,'done','success',? FROM n`, wpUpdateLogCleanupBatchSize+3, task.ID, wpUpdateDBTime(now.Add(-8*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := service.cleanupExpiredUpdateLogs(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if got := countWPUpdateLogEvents(t, store.db, task.ID); got != 3 {
		t.Fatalf("remaining events=%d", got)
	}
	if err := service.cleanupExpiredUpdateLogs(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if got := countWPUpdateLogEvents(t, store.db, task.ID); got != 0 {
		t.Fatalf("remaining events=%d", got)
	}
	if _, err := store.getTask(context.Background(), task.ID); err != nil {
		t.Fatalf("history removed: %v", err)
	}
}

type cleanupCadenceBackups struct {
	mu       sync.Mutex
	calls    int
	observed chan struct{}
}

func (b *cleanupCadenceBackups) prepareCoreBackups(context.Context, string, string) error { return nil }
func (b *cleanupCadenceBackups) cleanupExpiredArtifacts(context.Context, time.Time) error {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	select {
	case b.observed <- struct{}{}:
	default:
	}
	return nil
}

func TestWPUpdateLeaseSweepDoesNotRunRetentionEveryTick(t *testing.T) {
	store, _ := newWPUpdateStoreTest(t)
	backups := &cleanupCadenceBackups{observed: make(chan struct{}, 4)}
	var mu sync.Mutex
	now := time.Now().UTC()
	worker := &WPCoreUpdateWorker{store: store, backups: backups, sweepInterval: 5 * time.Millisecond, now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); worker.sweep(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-backups.observed:
	case <-time.After(time.Second):
		t.Fatal("first maintenance missing")
	}
	time.Sleep(35 * time.Millisecond)
	backups.mu.Lock()
	calls := backups.calls
	backups.mu.Unlock()
	if calls != 1 {
		t.Fatalf("cleanup ran on lease ticks: %d", calls)
	}
	mu.Lock()
	now = now.Add(wpUpdateMaintenanceInterval)
	mu.Unlock()
	select {
	case <-backups.observed:
	case <-time.After(time.Second):
		t.Fatal("next maintenance missing")
	}
}
