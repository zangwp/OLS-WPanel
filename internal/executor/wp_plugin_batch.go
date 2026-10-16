package executor

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

// WPUpdateBatch groups sequential plugin update tasks, each with auto_rollback=0
// and batch_id referring to this record.
type WPUpdateBatch struct {
	ID                     string
	SiteID                 int
	CreatedBy              string
	Status                 string
	TotalCount             int
	DatabaseBackupSourceID int64
	CreatedAt              string
	UpdatedAt              string
}

// WPUpdateBatchItem holds a pending plugin key, then the dispatched TaskID.
// Task*/CurrentVersion/TargetVersion snapshot the task for frontend progress display.
type WPUpdateBatchItem struct {
	ID                    int64
	BatchID               string
	Position              int
	ComponentKey          string
	Status                string
	Message               string
	TaskID                string
	RetryCount            int
	NextRetryAt           string
	TaskStatus            string
	TaskStage             string
	TaskRollbackStatus    string
	DatabaseBackupMode    string
	TaskRequiresAttention bool
	TaskManualDisposition string
	CurrentVersion        string
	TargetVersion         string
	CreatedAt             string
	UpdatedAt             string
}

func newWPUpdateBatchID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "wpub_" + hex.EncodeToString(raw[:]), nil
}

// createPluginBatch preserves componentKeys dispatch order and rejects sites with a blocking
// task or running batch. ux_wp_update_batches_active_site enforces batch uniqueness.
func (s *wpUpdateStore) createPluginBatch(ctx context.Context, siteID int, createdBy string, componentKeys []string, now time.Time) (WPUpdateBatch, error) {
	if s == nil || s.db == nil || siteID <= 0 || createdBy == "" || len(componentKeys) == 0 {
		return WPUpdateBatch{}, errors.New("invalid plugin batch request")
	}
	seen := map[string]bool{}
	for _, key := range componentKeys {
		if !validWPPluginComponentKey(key) || seen[key] {
			return WPUpdateBatch{}, errors.New("invalid plugin batch component list")
		}
		seen[key] = true
	}
	blocked, err := s.siteHasBlockingTask(ctx, siteID)
	if err != nil {
		return WPUpdateBatch{}, err
	}
	if blocked {
		return WPUpdateBatch{}, errors.New("site has blocking update task")
	}
	id, err := newWPUpdateBatchID()
	if err != nil {
		return WPUpdateBatch{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WPUpdateBatch{}, err
	}
	defer tx.Rollback()
	stamp := wpUpdateDBTime(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO wp_update_batches(id,site_id,created_by,status,total_count,created_at,updated_at)
		VALUES (?,?,?,'running',?,?,?)`, id, siteID, createdBy, len(componentKeys), stamp, stamp); err != nil {
		return WPUpdateBatch{}, err
	}
	for i, key := range componentKeys {
		if _, err := tx.ExecContext(ctx, `INSERT INTO wp_update_batch_items(batch_id,position,component_key,status,created_at,updated_at)
			VALUES (?,?,?,'pending',?,?)`, id, i+1, key, stamp, stamp); err != nil {
			return WPUpdateBatch{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return WPUpdateBatch{}, err
	}
	signalWorker(wpUpdateWake)
	return s.getBatch(ctx, id)
}

func (s *wpUpdateStore) getBatch(ctx context.Context, id string) (WPUpdateBatch, error) {
	var b WPUpdateBatch
	var backupSource sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id,site_id,created_by,status,total_count,database_backup_source_id,created_at,updated_at
		FROM wp_update_batches WHERE id=?`, id).
		Scan(&b.ID, &b.SiteID, &b.CreatedBy, &b.Status, &b.TotalCount, &backupSource, &b.CreatedAt, &b.UpdatedAt)
	if backupSource.Valid {
		b.DatabaseBackupSourceID = backupSource.Int64
	}
	return b, err
}

func (s *wpUpdateStore) listBatchesForSite(ctx context.Context, siteID int) ([]WPUpdateBatch, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,site_id,created_by,status,total_count,created_at,updated_at
		FROM wp_update_batches WHERE site_id=? ORDER BY created_at DESC,rowid DESC LIMIT 50`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var batches []WPUpdateBatch
	for rows.Next() {
		var b WPUpdateBatch
		if err := rows.Scan(&b.ID, &b.SiteID, &b.CreatedBy, &b.Status, &b.TotalCount, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, err
		}
		batches = append(batches, b)
	}
	return batches, rows.Err()
}

func (s *wpUpdateStore) listBatchItems(ctx context.Context, batchID string) ([]WPUpdateBatchItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT i.id,i.batch_id,i.position,i.component_key,i.status,i.message,COALESCE(i.task_id,''),
		i.retry_count,COALESCE(i.next_retry_at,''),
		COALESCE(t.status,''),COALESCE(t.stage,''),COALESCE(t.rollback_status,''),COALESCE(t.database_backup_mode,''),COALESCE(t.requires_attention,0),COALESCE(t.manual_disposition,''),
		COALESCE(t.current_version,''),COALESCE(t.target_version,''),i.created_at,i.updated_at
		FROM wp_update_batch_items i LEFT JOIN wp_update_tasks t ON t.id=i.task_id
		WHERE i.batch_id=? ORDER BY i.position`, batchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []WPUpdateBatchItem
	for rows.Next() {
		var it WPUpdateBatchItem
		var attention int
		if err := rows.Scan(&it.ID, &it.BatchID, &it.Position, &it.ComponentKey, &it.Status, &it.Message, &it.TaskID,
			&it.RetryCount, &it.NextRetryAt,
			&it.TaskStatus, &it.TaskStage, &it.TaskRollbackStatus, &it.DatabaseBackupMode, &attention, &it.TaskManualDisposition,
			&it.CurrentVersion, &it.TargetVersion, &it.CreatedAt, &it.UpdatedAt); err != nil {
			return nil, err
		}
		it.TaskRequiresAttention = attention != 0
		items = append(items, it)
	}
	return items, rows.Err()
}

// listRunningBatches returns active batches for each orchestrator tick.
func (s *wpUpdateStore) listRunningBatches(ctx context.Context) ([]WPUpdateBatch, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,site_id,created_by,status,total_count,database_backup_source_id,created_at,updated_at
		FROM wp_update_batches WHERE status='running' ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var batches []WPUpdateBatch
	for rows.Next() {
		var b WPUpdateBatch
		var backupSource sql.NullInt64
		if err := rows.Scan(&b.ID, &b.SiteID, &b.CreatedBy, &b.Status, &b.TotalCount, &backupSource, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, err
		}
		if backupSource.Valid {
			b.DatabaseBackupSourceID = backupSource.Int64
		}
		batches = append(batches, b)
	}
	return batches, rows.Err()
}

// siteHasBlockingTask matches create*ManualPlan: preparing/queued/running tasks
// and undisposed interrupted_unknown tasks block the site.
func (s *wpUpdateStore) siteHasBlockingTask(ctx context.Context, siteID int) (bool, error) {
	var blocked int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wp_update_tasks WHERE site_id=? AND (
		status IN ('preparing','queued','running') OR
		(status='interrupted_unknown' AND manual_disposition=''))`, siteID).Scan(&blocked)
	return blocked != 0, err
}

// nextPendingBatchItem returns the earliest pending item, or sql.ErrNoRows.
// Return it even during retry backoff so advance waits instead of violating componentKeys order.
func (s *wpUpdateStore) nextPendingBatchItem(ctx context.Context, batchID string) (WPUpdateBatchItem, error) {
	var it WPUpdateBatchItem
	err := s.db.QueryRowContext(ctx, `SELECT id,batch_id,position,component_key,status,message,COALESCE(task_id,''),retry_count,COALESCE(next_retry_at,''),created_at,updated_at
		FROM wp_update_batch_items WHERE batch_id=? AND status='pending' ORDER BY position LIMIT 1`, batchID).
		Scan(&it.ID, &it.BatchID, &it.Position, &it.ComponentKey, &it.Status, &it.Message, &it.TaskID, &it.RetryCount, &it.NextRetryAt, &it.CreatedAt, &it.UpdatedAt)
	return it, err
}

func (s *wpUpdateStore) markBatchItemDispatched(ctx context.Context, itemID int64, taskID string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE wp_update_batch_items SET status='dispatched',task_id=?,updated_at=?
		WHERE id=? AND status='pending'`, taskID, wpUpdateDBTime(now), itemID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("batch item is not dispatchable")
	}
	return nil
}

func (s *wpUpdateStore) markBatchItemFailed(ctx context.Context, itemID int64, message string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE wp_update_batch_items SET status='failed',message=?,updated_at=?
		WHERE id=? AND status='pending'`, message, wpUpdateDBTime(now), itemID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("batch item is not markable as failed")
	}
	return nil
}

// retryBatchItem keeps transient Preview/ConfirmForBatch failures pending,
// recording the error and next retry time for a later tick.
func (s *wpUpdateStore) retryBatchItem(ctx context.Context, itemID int64, message string, retryCount int, nextRetryAt, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE wp_update_batch_items SET message=?,retry_count=?,next_retry_at=?,updated_at=?
		WHERE id=? AND status='pending'`, message, retryCount, wpUpdateDBTime(nextRetryAt), wpUpdateDBTime(now), itemID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("batch item is not retryable")
	}
	return nil
}

// completeBatchIfExhausted requires no pending items and truly terminal dispatched tasks.
// For failed tasks, successful rollback or explicit ignore clears requires_attention, even after a failed rollback.
// For interrupted_unknown tasks, check manual_disposition: escalation and marked_failed_no_action
// intentionally retain requires_attention for highlighting in the individual task log.
//
// Keep the batch running while any item needs a decision, so reopening progress still
// offers rollback or ignore.
func (s *wpUpdateStore) completeBatchIfExhausted(ctx context.Context, batchID string, siteID int, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var unresolved int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM wp_update_batch_items i
		LEFT JOIN wp_update_tasks t ON t.id=i.task_id
		WHERE i.batch_id=? AND (
			i.status='pending' OR
			(i.status='dispatched' AND (
				t.id IS NULL OR
				t.status IN ('preparing','queued','running') OR
				(t.status='interrupted_unknown' AND t.manual_disposition='') OR
				(t.status='failed' AND t.requires_attention=1)
			))
		)`, batchID).Scan(&unresolved); err != nil {
		return false, err
	}
	if unresolved > 0 {
		return false, nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE wp_update_batches SET status='completed',updated_at=?
		WHERE id=? AND site_id=? AND status='running'`, wpUpdateDBTime(now), batchID, siteID)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// ensureBatchDatabaseBackupSource pins the first ready backup in item order, once only.
// Later items reuse it even if its task fails or needs attention; recentDatabaseBackup would
// otherwise exclude that task and force repeated backups. Zero with no error means none is ready.
func (s *wpUpdateStore) ensureBatchDatabaseBackupSource(ctx context.Context, batchID string, now time.Time) (int64, error) {
	var existing sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT database_backup_source_id FROM wp_update_batches WHERE id=?`, batchID).Scan(&existing); err != nil {
		return 0, err
	}
	if existing.Valid && existing.Int64 > 0 {
		return existing.Int64, nil
	}
	var backupID int64
	err := s.db.QueryRowContext(ctx, `SELECT b.id FROM wp_update_batch_items i
		JOIN wp_update_task_backups b ON b.task_id=i.task_id
		WHERE i.batch_id=? AND b.kind='database' AND b.protected=1 AND b.deleted_at IS NULL
		ORDER BY i.position LIMIT 1`, batchID).Scan(&backupID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE wp_update_batches SET database_backup_source_id=?,updated_at=?
		WHERE id=? AND database_backup_source_id IS NULL`, backupID, wpUpdateDBTime(now), batchID); err != nil {
		return 0, err
	}
	return backupID, nil
}

// validateBatchDatabaseBackup checks site ownership, protection, controlled path, size, and SHA-256.
// Ignore the source task's later attention/rollback state: a pinned backup remains valid after task failure.
// The six-hour temporary-reuse window also does not limit a batch's duration.
func (s *wpUpdateStore) validateBatchDatabaseBackup(ctx context.Context, siteID int, mode string, sourceID int64, root string) error {
	if mode == "fresh" && sourceID == 0 {
		return nil
	}
	if mode != "reuse" || sourceID <= 0 {
		return errors.New("invalid database backup choice")
	}
	var path, sha string
	var size int64
	err := s.db.QueryRowContext(ctx, `SELECT b.file_path,b.file_size,b.sha256
		FROM wp_update_task_backups b JOIN wp_update_tasks t ON t.id=b.task_id
		WHERE b.id=? AND t.site_id=? AND b.kind='database' AND b.protected=1 AND b.deleted_at IS NULL`,
		sourceID, siteID).Scan(&path, &size, &sha)
	if err != nil || size <= 0 || !wpUpdateSHA256Pattern.MatchString(sha) {
		return errors.New("database backup unavailable")
	}
	if !pathWithin(filepath.Clean(root), filepath.Clean(path), false) {
		return errors.New("database backup unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return errors.New("database backup unavailable")
	}
	actual, _, err := hashRegularFile(path)
	if err != nil || actual != sha {
		return errors.New("database backup unavailable")
	}
	return nil
}

// findBatchItemExistingTask recovers a task created by ConfirmForBatch when a crash or database
// error prevented markBatchItemDispatched from linking it, avoiding duplicate task creation.
func (s *wpUpdateStore) findBatchItemExistingTask(ctx context.Context, batchID, componentKey string) (string, error) {
	var taskID string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM wp_update_tasks
		WHERE batch_id=? AND component_key=? ORDER BY created_at DESC LIMIT 1`, batchID, componentKey).Scan(&taskID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return taskID, err
}

// wpPluginBatchConfirmer is the dispatch interface implemented by WPPluginUpdateService.
type wpPluginBatchConfirmer interface {
	Preview(ctx context.Context, siteID int, username, componentKey string) (models.WPPluginUpdatePreview, error)
	ConfirmForBatch(ctx context.Context, siteID int, username, componentKey, token, target, backupMode, batchID string, databaseBackupSourceID int64) (models.WPPluginUpdateTask, error)
}

// wpPluginBatchOrchestrator dispatches each running batch's next item on worker ticks.
// The single active task per site keeps each batch sequential.
type wpPluginBatchOrchestrator struct {
	store      *wpUpdateStore
	confirmer  wpPluginBatchConfirmer
	refresh    wpInventoryRefreshRequester
	now        func() time.Time
	mu         sync.Mutex // protects batchLocks
	batchLocks map[string]*batchLock
}

type batchLock struct {
	mu  sync.Mutex
	ref int
}

func newWPPluginBatchOrchestrator(store *wpUpdateStore, confirmer wpPluginBatchConfirmer, refresh wpInventoryRefreshRequester) (*wpPluginBatchOrchestrator, error) {
	if store == nil || store.db == nil || confirmer == nil || refresh == nil {
		return nil, errors.New("invalid plugin batch orchestrator")
	}
	return &wpPluginBatchOrchestrator{
		store: store, confirmer: confirmer, refresh: refresh, now: time.Now,
		batchLocks: make(map[string]*batchLock),
	}, nil
}

// lockBatch acquires a referenced batch mutex; callers must invoke unlockBatch.
func (o *wpPluginBatchOrchestrator) lockBatch(batchID string) *batchLock {
	o.mu.Lock()
	bl, ok := o.batchLocks[batchID]
	if !ok {
		bl = &batchLock{}
		o.batchLocks[batchID] = bl
	}
	bl.ref++
	o.mu.Unlock()
	bl.mu.Lock()
	return bl
}

// unlockBatch releases the mutex and its reference.
func (o *wpPluginBatchOrchestrator) unlockBatch(bl *batchLock) {
	bl.mu.Unlock()
	o.mu.Lock()
	bl.ref--
	o.mu.Unlock()
}

// pruneBatchLocks removes unreferenced locks for finished batches to prevent leaks.
func (o *wpPluginBatchOrchestrator) pruneBatchLocks(running map[string]bool) {
	o.mu.Lock()
	for id, bl := range o.batchLocks {
		if !running[id] && bl.ref == 0 {
			delete(o.batchLocks, id)
		}
	}
	o.mu.Unlock()
}

// Tick dispatches at most one real task per unblocked batch. Permanently rejected items
// are marked failed before advancing, with bounded work to avoid unlimited processing in one tick.
//
// The worker loop and 30s sweep can call Tick concurrently. A mutex per batch prevents
// duplicate tasks while allowing other batches to advance during slow previews or downloads.
func (o *wpPluginBatchOrchestrator) Tick(ctx context.Context) {
	batches, err := o.store.listRunningBatches(ctx)
	if err != nil {
		log.Printf("批量更新编排器读取进行中批量失败: %v", err)
		return
	}
	runningIDs := make(map[string]bool, len(batches))
	for _, batch := range batches {
		runningIDs[batch.ID] = true
	}
	var wg sync.WaitGroup
	for _, batch := range batches {
		wg.Add(1)
		bl := o.lockBatch(batch.ID)
		go func(b WPUpdateBatch) {
			defer wg.Done()
			defer o.unlockBatch(bl)
			if err := o.advance(ctx, b); err != nil {
				log.Printf("批量更新编排器推进 batch=%s site=%d 失败: %v", b.ID, b.SiteID, err)
			}
		}(batch)
	}
	wg.Wait()
	o.pruneBatchLocks(runningIDs)
}

func (o *wpPluginBatchOrchestrator) advance(ctx context.Context, batch WPUpdateBatch) error {
	now := o.now().UTC()
	for {
		item, err := o.store.nextPendingBatchItem(ctx, batch.ID)
		if errors.Is(err, sql.ErrNoRows) {
			completed, completeErr := o.store.completeBatchIfExhausted(ctx, batch.ID, batch.SiteID, now)
			if completeErr != nil || !completed {
				return completeErr
			}
			refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), wpInventoryUpdateRefreshTimeout)
			refreshErr := o.refresh.Request(refreshCtx, batch.SiteID, now)
			cancel()
			if refreshErr != nil {
				log.Printf("WordPress 批量更新完成后请求组件扫描失败 batch=%s site=%d: %v", batch.ID, batch.SiteID, refreshErr)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if item.NextRetryAt != "" && item.NextRetryAt > wpUpdateDBTime(now) {
			// Wait for the first pending item's backoff to preserve componentKeys order.
			return nil
		}
		// Recover orphan tasks before checking site blockage: the orphan itself may occupy the site.
		// Checking blockage first would prevent its recovery and leave the batch stuck forever.
		if existingTaskID, err := o.store.findBatchItemExistingTask(ctx, batch.ID, item.ComponentKey); err != nil {
			return err
		} else if existingTaskID != "" {
			if err := o.store.markBatchItemDispatched(ctx, item.ID, existingTaskID, now); err != nil {
				return err
			}
			return nil
		}
		blocked, err := o.store.siteHasBlockingTask(ctx, batch.SiteID)
		if err != nil {
			return err
		}
		if blocked {
			return nil
		}
		outcome, dispatchErr := o.dispatch(ctx, batch, item, now)
		if dispatchErr != nil {
			return dispatchErr
		}
		if outcome != wpBatchDispatchFailed {
			// Stop this tick after dispatching a task or scheduling a retry.
			return nil
		}
		// A permanent pre-dispatch rejection allows the next item to be tried in the same tick.
	}
}

type wpBatchDispatchOutcome int

const (
	wpBatchDispatchFailed wpBatchDispatchOutcome = iota
	wpBatchDispatchDispatched
	wpBatchDispatchRetrying
)

// wpPluginBatchMaxDispatchRetries bounds transient Preview/ConfirmForBatch retries
// so a persistently failing plugin source cannot block the batch indefinitely.
const wpPluginBatchMaxDispatchRetries = 3

// wpPluginBatchRetryBackoff spaces repeated checks during upstream failures,
// such as api.wordpress.org outages.
func wpPluginBatchRetryBackoff(retryCount int) time.Duration {
	switch {
	case retryCount <= 1:
		return 30 * time.Second
	case retryCount == 2:
		return 2 * time.Minute
	default:
		return 5 * time.Minute
	}
}

// isRetryableWPPluginBatchDispatchError retries transient network/upstream errors.
// A failed wp_update_plugins() request must not imply permanent absence from the official repository.
// Conflicts, missing components, and invalid licenses require user action and fail immediately.
func isRetryableWPPluginBatchDispatchError(err error) bool {
	switch {
	case errors.Is(err, ErrWPPluginUpdateNotInRepository),
		errors.Is(err, ErrWPPluginUpdateUnavailable),
		errors.Is(err, ErrWPPluginUpdateBusy),
		errors.Is(err, ErrWPPluginUpdateSiteBusy):
		return true
	default:
		return false
	}
}

// dispatch creates the item's wp_update_tasks row after the caller checks that the site
// is unblocked and no orphan task can be recovered.
func (o *wpPluginBatchOrchestrator) dispatch(ctx context.Context, batch WPUpdateBatch, item WPUpdateBatchItem, now time.Time) (wpBatchDispatchOutcome, error) {
	preview, err := o.confirmer.Preview(ctx, batch.SiteID, batch.CreatedBy, item.ComponentKey)
	if err != nil || !preview.Available {
		message := "preview_unavailable"
		if err != nil {
			message = err.Error()
		}
		return o.rejectBatchItem(ctx, item, err, message, now)
	}
	// Use the pinned batch backup, not Preview's RecentDatabaseBackup, which can disappear
	// when its source task requires attention. See ensureBatchDatabaseBackupSource.
	backupSourceID, err := o.store.ensureBatchDatabaseBackupSource(ctx, batch.ID, now)
	if err != nil {
		return wpBatchDispatchFailed, err
	}
	backupMode := "fresh"
	if backupSourceID > 0 {
		backupMode = "reuse"
	}
	task, err := o.confirmer.ConfirmForBatch(ctx, batch.SiteID, batch.CreatedBy, item.ComponentKey,
		preview.ConfirmationToken, preview.TargetVersion, backupMode, batch.ID, backupSourceID)
	if err != nil {
		return o.rejectBatchItem(ctx, item, err, "confirm_failed: "+err.Error(), now)
	}
	if err := o.store.markBatchItemDispatched(ctx, item.ID, task.ID, now); err != nil {
		return wpBatchDispatchFailed, err
	}
	return wpBatchDispatchDispatched, nil
}

// rejectBatchItem backs off transient pre-dispatch failures within the retry limit;
// nonretryable errors and exhausted retries permanently fail the item.
func (o *wpPluginBatchOrchestrator) rejectBatchItem(ctx context.Context, item WPUpdateBatchItem, cause error, message string, now time.Time) (wpBatchDispatchOutcome, error) {
	if isRetryableWPPluginBatchDispatchError(cause) && item.RetryCount < wpPluginBatchMaxDispatchRetries {
		retryCount := item.RetryCount + 1
		nextRetryAt := now.Add(wpPluginBatchRetryBackoff(retryCount))
		if err := o.store.retryBatchItem(ctx, item.ID, message, retryCount, nextRetryAt, now); err != nil {
			return wpBatchDispatchFailed, err
		}
		return wpBatchDispatchRetrying, nil
	}
	if err := o.store.markBatchItemFailed(ctx, item.ID, message, now); err != nil {
		return wpBatchDispatchFailed, err
	}
	return wpBatchDispatchFailed, nil
}
