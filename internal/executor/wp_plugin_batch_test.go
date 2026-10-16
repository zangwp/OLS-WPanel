package executor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

func TestWPUpdateStoreCreatePluginBatchAndItems(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	batch, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php", "b/b.php", "c/c.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Status != "running" || batch.TotalCount != 3 || batch.CreatedBy != "alice" {
		t.Fatalf("batch=%+v", batch)
	}
	items, err := store.listBatchItems(context.Background(), batch.ID)
	if err != nil || len(items) != 3 {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	for i, it := range items {
		if it.Position != i+1 || it.Status != "pending" {
			t.Fatalf("item[%d]=%+v", i, it)
		}
	}
	if _, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"d/d.php"}, now); err == nil {
		t.Fatal("expected a second running batch for the same site to be rejected")
	}
}

func TestWPUpdateStoreCreatePluginBatchRejectsDuplicatesAndBlockedSite(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	if _, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php", "a/a.php"}, now); err == nil {
		t.Fatal("expected duplicate component keys to be rejected")
	}
	seedPluginUpdateCandidate(t, store, siteID, "sample/sample.php", "1.0.0", "1.1.0", "collection-plugin")
	if _, err := store.createPluginManualPlan(context.Background(), WPUpdatePlan{
		SiteID: siteID, ComponentKey: "sample/sample.php", CurrentVersion: "1.0.0", TargetVersion: "1.1.0",
		PackageSource: "wordpress.org", DownloadURL: "https://downloads.wordpress.org/plugin/sample.1.1.0.zip",
	}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php"}, now); err == nil {
		t.Fatal("expected batch creation to be rejected while site has a blocking task")
	}
}

// fakePluginBatchConfirmer creates real wp_update_tasks rows on ConfirmForBatch success
// so the orchestrator's blocking checks see each occupied site slot.
type fakePluginBatchConfirmer struct {
	store           *wpUpdateStore
	unavailable     map[string]bool
	previewErr      map[string]error
	previewDelay    map[string]chan struct{}
	confirmFails    map[string]bool
	confirmErr      map[string]error
	confirmed       []string
	confirmedMode   map[string]string
	confirmedSource map[string]int64
}

func (f *fakePluginBatchConfirmer) Preview(_ context.Context, siteID int, _ string, componentKey string) (models.WPPluginUpdatePreview, error) {
	if delay, ok := f.previewDelay[componentKey]; ok {
		<-delay
	}
	if err, ok := f.previewErr[componentKey]; ok {
		return models.WPPluginUpdatePreview{}, err
	}
	if f.unavailable[componentKey] {
		return models.WPPluginUpdatePreview{Available: false}, nil
	}
	return models.WPPluginUpdatePreview{Available: true, SiteID: siteID, ComponentKey: componentKey,
		CurrentVersion: "1.0.0", TargetVersion: "1.1.0", ConfirmationToken: "tok-" + componentKey}, nil
}

func (f *fakePluginBatchConfirmer) ConfirmForBatch(ctx context.Context, siteID int, _, componentKey, _, _, backupMode, batchID string, sourceID int64) (models.WPPluginUpdateTask, error) {
	if err, ok := f.confirmErr[componentKey]; ok {
		return models.WPPluginUpdateTask{}, err
	}
	if f.confirmFails[componentKey] {
		return models.WPPluginUpdateTask{}, errors.New("injected confirm failure")
	}
	id, err := newWPUpdateTaskID()
	if err != nil {
		return models.WPPluginUpdateTask{}, err
	}
	stamp := wpUpdateDBTime(time.Now().UTC())
	if _, err := f.store.db.ExecContext(ctx, `INSERT INTO wp_update_tasks
		(id,site_id,component_type,component_key,task_kind,trigger_type,status,stage,
		 current_version,target_version,package_source,download_url,database_backup_mode,database_backup_source_id,auto_rollback,batch_id,requested_at,created_at,updated_at)
		VALUES (?,?,'plugin',?,'update','manual','queued','queued','1.0.0','1.1.0','wordpress.org','https://example.com/x.zip',?,?,0,?,?,?,?)`,
		id, siteID, componentKey, backupMode, nullableBackupSource(sourceID), batchID, stamp, stamp, stamp); err != nil {
		return models.WPPluginUpdateTask{}, err
	}
	f.confirmed = append(f.confirmed, componentKey)
	if f.confirmedMode == nil {
		f.confirmedMode = map[string]string{}
	}
	if f.confirmedSource == nil {
		f.confirmedSource = map[string]int64{}
	}
	f.confirmedMode[componentKey] = backupMode
	f.confirmedSource[componentKey] = sourceID
	return models.WPPluginUpdateTask{ID: id, SiteID: siteID, ComponentKey: componentKey}, nil
}

func TestWPPluginBatchOrchestratorDispatchesSequentially(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	batch, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php", "b/b.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	confirmer := &fakePluginBatchConfirmer{store: store}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	if want := []string{"a/a.php"}; len(confirmer.confirmed) != 1 || confirmer.confirmed[0] != want[0] {
		t.Fatalf("confirmed=%v want=%v", confirmer.confirmed, want)
	}
	items, err := store.listBatchItems(context.Background(), batch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Status != "dispatched" || items[0].TaskID == "" || items[1].Status != "pending" {
		t.Fatalf("items=%+v", items)
	}
	// The first item still occupies the site slot, so the next tick must not dispatch the second.
	orchestrator.Tick(context.Background())
	if len(confirmer.confirmed) != 1 {
		t.Fatalf("confirmed=%v want only the first item dispatched while site is blocked", confirmer.confirmed)
	}
	// Simulate the worker completing the first item.
	if _, err := store.db.Exec(`UPDATE wp_update_tasks SET status='success',finished_at=?,updated_at=? WHERE id=?`,
		wpUpdateDBTime(now.Add(time.Minute)), wpUpdateDBTime(now.Add(time.Minute)), items[0].TaskID); err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	if want := []string{"a/a.php", "b/b.php"}; len(confirmer.confirmed) != 2 || confirmer.confirmed[1] != want[1] {
		t.Fatalf("confirmed=%v want=%v", confirmer.confirmed, want)
	}
	items, err = store.listBatchItems(context.Background(), batch.ID)
	if err != nil || items[1].Status != "dispatched" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	// Completing the second item should complete the batch.
	if _, err := store.db.Exec(`UPDATE wp_update_tasks SET status='success',finished_at=?,updated_at=? WHERE id=?`,
		wpUpdateDBTime(now.Add(2*time.Minute)), wpUpdateDBTime(now.Add(2*time.Minute)), items[1].TaskID); err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	finishedBatch, err := store.getBatch(context.Background(), batch.ID)
	if err != nil || finishedBatch.Status != "completed" {
		t.Fatalf("finishedBatch=%+v err=%v", finishedBatch, err)
	}
}

func insertFakeDatabaseBackup(t *testing.T, store *wpUpdateStore, taskID string) int64 {
	t.Helper()
	result, err := store.db.Exec(`INSERT INTO wp_update_task_backups(task_id,kind,file_path,file_size,sha256,protected)
		VALUES (?, 'database', ?, 100, ?, 1)`, taskID, "/tmp/"+taskID+"-db.sql.gz", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestWPPluginBatchOrchestratorReusesSharedBackupAcrossFailedItem ensures a failed item
// does not invalidate the shared backup. The batch must also remain running while that item
// awaits a decision, even after later items succeed, and complete only after it is ignored.
func TestWPPluginBatchOrchestratorReusesSharedBackupAcrossFailedItem(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	batch, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php", "b/b.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	confirmer := &fakePluginBatchConfirmer{store: store}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	items, err := store.listBatchItems(context.Background(), batch.ID)
	if err != nil || items[0].Status != "dispatched" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	if confirmer.confirmedMode["a/a.php"] != "fresh" {
		t.Fatalf("first item backup mode=%q want=fresh", confirmer.confirmedMode["a/a.php"])
	}
	backupID := insertFakeDatabaseBackup(t, store, items[0].TaskID)
	// The failed first item awaits a decision with requires_attention=1 and rollback_status=pending.
	if _, err := store.db.Exec(`UPDATE wp_update_tasks SET status='failed',rollback_status='pending',requires_attention=1,
		finished_at=?,updated_at=? WHERE id=?`, wpUpdateDBTime(now.Add(time.Minute)), wpUpdateDBTime(now.Add(time.Minute)), items[0].TaskID); err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	if confirmer.confirmedMode["b/b.php"] != "reuse" || confirmer.confirmedSource["b/b.php"] != backupID {
		t.Fatalf("second item mode=%q source=%d, want reuse of item1's backup id=%d",
			confirmer.confirmedMode["b/b.php"], confirmer.confirmedSource["b/b.php"], backupID)
	}
	batchAfterDispatch, err := store.getBatch(context.Background(), batch.ID)
	if err != nil || batchAfterDispatch.DatabaseBackupSourceID != backupID {
		t.Fatalf("batch=%+v err=%v, want database_backup_source_id=%d fixed on the batch", batchAfterDispatch, err, backupID)
	}
	items, err = store.listBatchItems(context.Background(), batch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].DatabaseBackupMode != "fresh" || items[1].DatabaseBackupMode != "reuse" {
		t.Fatalf("item backup modes=%q/%q, want fresh/reuse for accurate rollback warnings", items[0].DatabaseBackupMode, items[1].DatabaseBackupMode)
	}
	// The second item succeeds, but the first still awaits a decision, keeping the batch running.
	if _, err := store.db.Exec(`UPDATE wp_update_tasks SET status='success',finished_at=?,updated_at=? WHERE id=?`,
		wpUpdateDBTime(now.Add(2*time.Minute)), wpUpdateDBTime(now.Add(2*time.Minute)), items[1].TaskID); err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	stillRunning, err := store.getBatch(context.Background(), batch.ID)
	if err != nil || stillRunning.Status != "running" {
		t.Fatalf("batch=%+v err=%v, want still running while item1 awaits a decision", stillRunning, err)
	}
	// Ignoring the first item allows the batch to complete.
	if err := store.disposeFailedTaskIgnored(context.Background(), items[0].TaskID, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	completed, err := store.getBatch(context.Background(), batch.ID)
	if err != nil || completed.Status != "completed" {
		t.Fatalf("batch=%+v err=%v, want completed once item1 is resolved", completed, err)
	}
}

// TestWPPluginBatchOrchestratorRecoversOrphanedTaskInsteadOfDuplicating covers a crash
// after Confirm but before markBatchItemDispatched: link the existing task rather than confirm again.
func TestWPPluginBatchOrchestratorRecoversOrphanedTaskInsteadOfDuplicating(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	batch, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	orphanID := "wpu_orphan0000000000000000000000"
	stamp := wpUpdateDBTime(now)
	if _, err := store.db.Exec(`INSERT INTO wp_update_tasks
		(id,site_id,component_type,component_key,task_kind,trigger_type,status,stage,
		 current_version,target_version,package_source,download_url,auto_rollback,batch_id,requested_at,created_at,updated_at)
		VALUES (?,?,'plugin','a/a.php','update','manual','queued','queued','1.0.0','1.1.0','wordpress.org','https://example.com/x.zip',0,?,?,?,?)`,
		orphanID, siteID, batch.ID, stamp, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	confirmer := &fakePluginBatchConfirmer{store: store}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	if len(confirmer.confirmed) != 0 {
		t.Fatalf("confirmed=%v, want ConfirmForBatch not called when an orphaned task already exists", confirmer.confirmed)
	}
	items, err := store.listBatchItems(context.Background(), batch.ID)
	if err != nil || items[0].Status != "dispatched" || items[0].TaskID != orphanID {
		t.Fatalf("items=%+v err=%v, want the orphaned task backfilled", items, err)
	}
}

// TestWPPluginBatchOrchestratorIsolatesMultipleSites verifies that site slots and shared
// database backups remain independent across batches on different sites.
func TestWPPluginBatchOrchestratorIsolatesMultipleSites(t *testing.T) {
	store, siteA := newWPUpdateStoreTest(t)
	siteB := seedSecondWebsiteForBatchTest(t, store)
	now := time.Now().UTC()
	batchA, err := store.createPluginBatch(context.Background(), siteA, "alice", []string{"a/a.php", "b/b.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	batchB, err := store.createPluginBatch(context.Background(), siteB, "bob", []string{"c/c.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	confirmer := &fakePluginBatchConfirmer{store: store}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	if want := map[string]bool{"a/a.php": true, "c/c.php": true}; len(confirmer.confirmed) != 2 || !want[confirmer.confirmed[0]] || !want[confirmer.confirmed[1]] {
		t.Fatalf("confirmed=%v, want site A's first item and site B's only item dispatched independently", confirmer.confirmed)
	}
	itemsA, err := store.listBatchItems(context.Background(), batchA.ID)
	if err != nil || itemsA[0].Status != "dispatched" || itemsA[1].Status != "pending" {
		t.Fatalf("itemsA=%+v err=%v", itemsA, err)
	}
	itemsB, err := store.listBatchItems(context.Background(), batchB.ID)
	if err != nil || itemsB[0].Status != "dispatched" {
		t.Fatalf("itemsB=%+v err=%v", itemsB, err)
	}
	// Completing site B must not release site A's occupied task slot.
	if _, err := store.db.Exec(`UPDATE wp_update_tasks SET status='success',updated_at=? WHERE id=?`,
		wpUpdateDBTime(now), itemsB[0].TaskID); err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	itemsA, err = store.listBatchItems(context.Background(), batchA.ID)
	if err != nil || itemsA[1].Status != "pending" {
		t.Fatalf("itemsA=%+v err=%v, want site A's second item still pending (unaffected by site B completing)", itemsA, err)
	}
	batchAAfter, err := store.getBatch(context.Background(), batchA.ID)
	if err != nil || batchAAfter.DatabaseBackupSourceID != 0 {
		t.Fatalf("batchA=%+v err=%v, want no backup source recorded yet (site A's first item never got a backup row in this test)", batchAAfter, err)
	}
}

// TestWPPluginBatchOrchestratorSlowBatchDoesNotBlockOthers ensures the global lock
// does not cover Preview/ConfirmForBatch I/O, so a slow batch cannot delay other batches.
func TestWPPluginBatchOrchestratorSlowBatchDoesNotBlockOthers(t *testing.T) {
	store, siteA := newWPUpdateStoreTest(t)
	siteB := seedSecondWebsiteForBatchTest(t, store)
	now := time.Now().UTC()
	batchA, err := store.createPluginBatch(context.Background(), siteA, "alice", []string{"a/a.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	batchB, err := store.createPluginBatch(context.Background(), siteB, "bob", []string{"c/c.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	blockA := make(chan struct{})
	confirmer := &fakePluginBatchConfirmer{store: store, previewDelay: map[string]chan struct{}{"a/a.php": blockA}}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		orchestrator.Tick(context.Background())
	}()
	// Wait for A to block in Preview; B must complete dispatch independently.
	time.Sleep(100 * time.Millisecond)
	itemsA, err := store.listBatchItems(context.Background(), batchA.ID)
	if err != nil {
		t.Fatal(err)
	}
	itemsB, err := store.listBatchItems(context.Background(), batchB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if itemsA[0].Status != "pending" || itemsB[0].Status != "dispatched" {
		t.Fatalf("itemsA[0].status=%s itemsB[0].status=%s, want A pending and B dispatched while A is blocked", itemsA[0].Status, itemsB[0].Status)
	}
	close(blockA)
	wg.Wait()
	itemsA, err = store.listBatchItems(context.Background(), batchA.ID)
	if err != nil || itemsA[0].Status != "dispatched" {
		t.Fatalf("itemsA=%+v err=%v", itemsA, err)
	}
	itemsB, err = store.listBatchItems(context.Background(), batchB.ID)
	if err != nil || itemsB[0].Status != "dispatched" {
		t.Fatalf("itemsB=%+v err=%v", itemsB, err)
	}
}

func seedSecondWebsiteForBatchTest(t *testing.T, store *wpUpdateStore) int {
	t.Helper()
	result, err := store.db.Exec(`INSERT INTO websites
		(name,domain,status,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path,site_type)
		VALUES ('update2.example.com','update2.example.com','active','wp_update2','/tmp/www2','/tmp/log2','db2','dbuser2','/tmp/php2','/tmp/openlitespeed2','wordpress')`)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return int(id)
}

// TestWPPluginBatchOrchestratorInterruptedUnknownBlocksUntilAcknowledged ensures
// an uncertain first task blocks later items until disposeInterrupted acknowledges it.
func TestWPPluginBatchOrchestratorInterruptedUnknownBlocksUntilAcknowledged(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	batch, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php", "b/b.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	confirmer := &fakePluginBatchConfirmer{store: store}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	items, err := store.listBatchItems(context.Background(), batch.ID)
	if err != nil || items[0].Status != "dispatched" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	// Simulate an owned running task before interruptOwned, which requires running status
	// and a matching lease_owner, to produce an uncertain runner outcome.
	runningStamp := wpUpdateDBTime(now.Add(30 * time.Second))
	if _, err := store.db.Exec(`UPDATE wp_update_tasks SET status='running',lease_owner='worker-plugin',
		lease_expires_at=?,updated_at=? WHERE id=?`, runningStamp, runningStamp, items[0].TaskID); err != nil {
		t.Fatal(err)
	}
	if changed, err := store.interruptOwned(context.Background(), items[0].TaskID, "worker-plugin", "runner_supervision_uncertain", now.Add(time.Minute)); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	orchestrator.Tick(context.Background())
	if len(confirmer.confirmed) != 1 {
		t.Fatalf("confirmed=%v, want item2 not dispatched while item1 is interrupted_unknown and undisposed", confirmer.confirmed)
	}
	batchStillRunning, err := store.getBatch(context.Background(), batch.ID)
	if err != nil || batchStillRunning.Status != "running" {
		t.Fatalf("batch=%+v err=%v", batchStillRunning, err)
	}
	// Acknowledge the task, matching the batch UI's Ignore action.
	if err := store.disposeInterrupted(context.Background(), items[0].TaskID, "escalated", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	if want := []string{"a/a.php", "b/b.php"}; len(confirmer.confirmed) != 2 || confirmer.confirmed[1] != want[1] {
		t.Fatalf("confirmed=%v want=%v, item2 should dispatch once item1 is acknowledged", confirmer.confirmed, want)
	}
}

func TestWPPluginBatchOrchestratorSkipsUnavailableItemInSameTick(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	batch, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php", "b/b.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	confirmer := &fakePluginBatchConfirmer{store: store, unavailable: map[string]bool{"a/a.php": true}}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.Tick(context.Background())
	items, err := store.listBatchItems(context.Background(), batch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Status != "failed" || items[0].Message == "" {
		t.Fatalf("items[0]=%+v", items[0])
	}
	if items[1].Status != "dispatched" || items[1].TaskID == "" {
		t.Fatalf("items[1]=%+v", items[1])
	}
	if len(confirmer.confirmed) != 1 || confirmer.confirmed[0] != "b/b.php" {
		t.Fatalf("confirmed=%v", confirmer.confirmed)
	}
}

// TestWPPluginBatchOrchestratorRetriesRetryablePreviewError keeps transient upstream
// errors pending with backoff and preserves item order rather than skipping to later items.
func TestWPPluginBatchOrchestratorRetriesRetryablePreviewError(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	batch, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php", "b/b.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	confirmer := &fakePluginBatchConfirmer{
		store:      store,
		previewErr: map[string]error{"a/a.php": ErrWPPluginUpdateNotInRepository},
	}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.now = func() time.Time { return now }
	orchestrator.Tick(context.Background())

	items, err := store.listBatchItems(context.Background(), batch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Status != "pending" {
		t.Fatalf("items[0].Status=%q want pending (retryable error must not fail)", items[0].Status)
	}
	if items[0].RetryCount != 1 {
		t.Fatalf("items[0].RetryCount=%d want 1", items[0].RetryCount)
	}
	if want := wpUpdateDBTime(now.Add(30 * time.Second)); items[0].NextRetryAt != want {
		t.Fatalf("items[0].NextRetryAt=%q want %q", items[0].NextRetryAt, want)
	}
	if items[0].Message == "" {
		t.Fatalf("items[0].Message empty, want recorded failure cause")
	}
	if items[1].Status != "pending" {
		t.Fatalf("items[1].Status=%q want pending (must not skip ahead while retryable item waits)", items[1].Status)
	}
	if len(confirmer.confirmed) != 0 {
		t.Fatalf("confirmed=%v, want nothing dispatched", confirmer.confirmed)
	}
}

// TestWPPluginBatchOrchestratorWaitsDuringBackoff ensures no retry or dispatch occurs
// until next_retry_at, then retries the same item.
func TestWPPluginBatchOrchestratorWaitsDuringBackoff(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	batch, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	confirmer := &fakePluginBatchConfirmer{
		store:      store,
		previewErr: map[string]error{"a/a.php": ErrWPPluginUpdateUnavailable},
	}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.now = func() time.Time { return now }
	orchestrator.Tick(context.Background())

	items, _ := store.listBatchItems(context.Background(), batch.ID)
	if items[0].RetryCount != 1 {
		t.Fatalf("after first tick RetryCount=%d want 1", items[0].RetryCount)
	}

	// The second tick must wait while next_retry_at is still in the future.
	orchestrator.Tick(context.Background())
	items, _ = store.listBatchItems(context.Background(), batch.ID)
	if items[0].RetryCount != 1 {
		t.Fatalf("during backoff RetryCount=%d want 1 (must not retry yet)", items[0].RetryCount)
	}
	if items[0].Status != "pending" {
		t.Fatalf("during backoff Status=%q want pending", items[0].Status)
	}

	// Expire backoff and clear previewErr so the retry can succeed.
	if _, err := store.db.Exec(`UPDATE wp_update_batch_items SET next_retry_at=? WHERE batch_id=?`,
		wpUpdateDBTime(now.Add(-time.Minute)), batch.ID); err != nil {
		t.Fatal(err)
	}
	delete(confirmer.previewErr, "a/a.php")
	orchestrator.Tick(context.Background())

	items, _ = store.listBatchItems(context.Background(), batch.ID)
	if items[0].Status != "dispatched" || items[0].TaskID == "" {
		t.Fatalf("after backoff items[0]=%+v want dispatched", items[0])
	}
	if len(confirmer.confirmed) != 1 || confirmer.confirmed[0] != "a/a.php" {
		t.Fatalf("confirmed=%v want [a/a.php]", confirmer.confirmed)
	}
}

// TestWPPluginBatchOrchestratorRetriesThenSucceeds covers recovery after transient failures.
func TestWPPluginBatchOrchestratorRetriesThenSucceeds(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	batch, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	confirmer := &fakePluginBatchConfirmer{
		store:      store,
		previewErr: map[string]error{"a/a.php": ErrWPPluginUpdateBusy},
	}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.now = func() time.Time { return now }

	// The first tick starts backoff.
	orchestrator.Tick(context.Background())
	// After backoff, remove the error source so the second tick succeeds.
	if _, err := store.db.Exec(`UPDATE wp_update_batch_items SET next_retry_at=? WHERE batch_id=?`,
		wpUpdateDBTime(now.Add(-time.Minute)), batch.ID); err != nil {
		t.Fatal(err)
	}
	delete(confirmer.previewErr, "a/a.php")
	orchestrator.Tick(context.Background())

	items, _ := store.listBatchItems(context.Background(), batch.ID)
	if items[0].Status != "dispatched" || items[0].TaskID == "" {
		t.Fatalf("items[0]=%+v want dispatched after retry succeeds", items[0])
	}
	if items[0].RetryCount != 1 {
		t.Fatalf("RetryCount=%d want 1 (success does not reset retry count)", items[0].RetryCount)
	}
}

// TestWPPluginBatchOrchestratorMarksFailedAfterMaxRetries prevents persistent upstream
// failures from holding the batch indefinitely, even when the error remains retryable.
func TestWPPluginBatchOrchestratorMarksFailedAfterMaxRetries(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	batch, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	confirmer := &fakePluginBatchConfirmer{
		store:      store,
		previewErr: map[string]error{"a/a.php": ErrWPPluginUpdateNotInRepository},
	}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.now = func() time.Time { return now }

	// Exhaust three retries, expiring backoff between ticks.
	for attempt := 0; attempt < wpPluginBatchMaxDispatchRetries; attempt++ {
		orchestrator.Tick(context.Background())
		if _, err := store.db.Exec(`UPDATE wp_update_batch_items SET next_retry_at=? WHERE batch_id=?`,
			wpUpdateDBTime(now.Add(-time.Minute)), batch.ID); err != nil {
			t.Fatal(err)
		}
	}
	items, _ := store.listBatchItems(context.Background(), batch.ID)
	if items[0].RetryCount != wpPluginBatchMaxDispatchRetries {
		t.Fatalf("RetryCount=%d want %d", items[0].RetryCount, wpPluginBatchMaxDispatchRetries)
	}
	if items[0].Status != "pending" {
		t.Fatalf("Status=%q want pending (still retryable at the cap)", items[0].Status)
	}

	// The next tick must fail the item permanently after the retry limit.
	orchestrator.Tick(context.Background())
	items, _ = store.listBatchItems(context.Background(), batch.ID)
	if items[0].Status != "failed" {
		t.Fatalf("Status=%q want failed after exhausting retries", items[0].Status)
	}
	if len(confirmer.confirmed) != 0 {
		t.Fatalf("confirmed=%v, want nothing dispatched", confirmer.confirmed)
	}
}

// TestWPPluginBatchOrchestratorFailsImmediatelyOnNonRetryableError ensures permanent
// errors fail immediately and allow the next item to dispatch in the same tick.
func TestWPPluginBatchOrchestratorFailsImmediatelyOnNonRetryableError(t *testing.T) {
	store, siteID := newWPUpdateStoreTest(t)
	now := time.Now().UTC()
	batch, err := store.createPluginBatch(context.Background(), siteID, "alice", []string{"a/a.php", "b/b.php"}, now)
	if err != nil {
		t.Fatal(err)
	}
	permanent := errors.New("permanent preview failure")
	confirmer := &fakePluginBatchConfirmer{
		store:      store,
		previewErr: map[string]error{"a/a.php": permanent},
	}
	orchestrator, err := newWPPluginBatchOrchestrator(store, confirmer, &recordingInventoryRefreshRequester{})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.now = func() time.Time { return now }
	orchestrator.Tick(context.Background())

	items, err := store.listBatchItems(context.Background(), batch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Status != "failed" {
		t.Fatalf("items[0].Status=%q want failed immediately (non-retryable)", items[0].Status)
	}
	if items[0].RetryCount != 0 {
		t.Fatalf("items[0].RetryCount=%d want 0 (non-retryable must not retry)", items[0].RetryCount)
	}
	if items[1].Status != "dispatched" || items[1].TaskID == "" {
		t.Fatalf("items[1]=%+v want dispatched (same tick continues after permanent failure)", items[1])
	}
	if len(confirmer.confirmed) != 1 || confirmer.confirmed[0] != "b/b.php" {
		t.Fatalf("confirmed=%v want [b/b.php]", confirmer.confirmed)
	}
}

func TestWPPluginBatchRetryBackoff(t *testing.T) {
	cases := []struct {
		retryCount int
		want       time.Duration
	}{
		{0, 30 * time.Second},
		{1, 30 * time.Second},
		{2, 2 * time.Minute},
		{3, 5 * time.Minute},
		{4, 5 * time.Minute},
		{99, 5 * time.Minute},
	}
	for _, c := range cases {
		if got := wpPluginBatchRetryBackoff(c.retryCount); got != c.want {
			t.Fatalf("wpPluginBatchRetryBackoff(%d)=%v want %v", c.retryCount, got, c.want)
		}
	}
}

func TestIsRetryableWPPluginBatchDispatchError(t *testing.T) {
	for _, err := range []error{
		ErrWPPluginUpdateNotInRepository,
		ErrWPPluginUpdateUnavailable,
		ErrWPPluginUpdateBusy,
		ErrWPPluginUpdateSiteBusy,
	} {
		if !isRetryableWPPluginBatchDispatchError(err) {
			t.Fatalf("isRetryable(%v)=false want true", err)
		}
	}
	for _, err := range []error{
		nil,
		ErrWPPluginUpdateConflict,
		errors.New("some other error"),
	} {
		if isRetryableWPPluginBatchDispatchError(err) {
			t.Fatalf("isRetryable(%v)=true want false", err)
		}
	}
}
