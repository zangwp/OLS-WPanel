package executor

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

// WPPluginBatchService exposes batch creation, status, rollback, and ignore to HTTP handlers.
// The background wpPluginBatchOrchestrator dispatches items through Preview/Confirm.
type WPPluginBatchService struct {
	store    *wpUpdateStore
	executor *wpPluginUpdateExecutor
	now      func() time.Time
}

func NewWPPluginBatchService(db *sql.DB, backupDir, wwwRoot string) (*WPPluginBatchService, error) {
	if db == nil || !validWPCoreUpdateRoot(backupDir) || !filepath.IsAbs(wwwRoot) {
		return nil, ErrWPPluginUpdateInvalid
	}
	store := newWPUpdateStore(db)
	root := filepath.Join(filepath.Clean(backupDir), "wp-updates")
	pluginOps, err := newDefaultWPPluginSystemOperations(store, filepath.Clean(wwwRoot))
	if err != nil {
		return nil, ErrWPPluginUpdateUnavailable
	}
	executor, err := newWPPluginUpdateExecutor(store, root, pluginOps)
	if err != nil {
		return nil, ErrWPPluginUpdateUnavailable
	}
	return &WPPluginBatchService{store: store, executor: executor, now: time.Now}, nil
}

// Create checks for blocking tasks and creates a batch for background dispatch.
func (s *WPPluginBatchService) Create(ctx context.Context, siteID int, username string, componentKeys []string) (models.WPPluginBatch, error) {
	if s == nil || siteID <= 0 || username == "" || len(componentKeys) == 0 {
		return models.WPPluginBatch{}, ErrWPPluginUpdateInvalid
	}
	batch, err := s.store.createPluginBatch(ctx, siteID, username, componentKeys, s.now().UTC())
	if err != nil {
		return models.WPPluginBatch{}, ErrWPPluginUpdateConflict
	}
	return s.batchModel(ctx, batch, true)
}

// Get returns the batch and item statuses for frontend progress polling.
func (s *WPPluginBatchService) Get(ctx context.Context, siteID int, batchID string) (models.WPPluginBatch, error) {
	if s == nil || siteID <= 0 || batchID == "" {
		return models.WPPluginBatch{}, ErrWPPluginUpdateInvalid
	}
	batch, err := s.store.getBatch(ctx, batchID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && batch.SiteID != siteID {
		return models.WPPluginBatch{}, ErrWPPluginUpdateNotFound
	}
	if err != nil {
		return models.WPPluginBatch{}, err
	}
	return s.batchModel(ctx, batch, true)
}

// ListForSite returns recent batch history without item details.
func (s *WPPluginBatchService) ListForSite(ctx context.Context, siteID int) ([]models.WPPluginBatch, error) {
	if s == nil || siteID <= 0 {
		return nil, ErrWPPluginUpdateInvalid
	}
	batches, err := s.store.listBatchesForSite(ctx, siteID)
	if err != nil {
		return nil, err
	}
	result := make([]models.WPPluginBatch, 0, len(batches))
	for _, b := range batches {
		model, err := s.batchModel(ctx, b, false)
		if err != nil {
			return nil, err
		}
		result = append(result, model)
	}
	return result, nil
}

// Rollback lets users restore failed tasks requiring attention, including retrying a failed rollback.
// Reject interrupted_unknown: restoring could overwrite an update that actually succeeded.
// Those tasks can only be acknowledged through Ignore.
func (s *WPPluginBatchService) Rollback(ctx context.Context, siteID int, taskID string) error {
	defer signalWorker(wpUpdateWake)
	task, err := s.loadBatchTaskForDecision(ctx, siteID, taskID)
	if err != nil {
		return err
	}
	if task.Status != wpUpdateFailed || !task.RequiresAttention {
		return ErrWPPluginUpdateConflict
	}
	if err := s.executor.ManualRollback(ctx, task.ID); err != nil {
		return ErrWPPluginUpdateConflict
	}
	return nil
}

// Ignore acknowledges a failed task requiring attention or an undisposed interrupted_unknown task.
// This includes failed manual rollbacks and uncertain runner outcomes, allowing later batch items
// to proceed instead of leaving the site blocked indefinitely.
func (s *WPPluginBatchService) Ignore(ctx context.Context, siteID int, taskID string) error {
	defer signalWorker(wpUpdateWake)
	task, err := s.loadBatchTaskForDecision(ctx, siteID, taskID)
	if err != nil {
		return err
	}
	switch {
	case task.Status == wpUpdateFailed && task.RequiresAttention:
		if err := s.store.disposeFailedTaskIgnored(ctx, task.ID, s.now().UTC()); err != nil {
			return ErrWPPluginUpdateConflict
		}
	case task.Status == wpUpdateInterrupted && task.ManualDisposition == "":
		if err := s.store.disposeInterrupted(ctx, task.ID, "escalated", s.now().UTC()); err != nil {
			return ErrWPPluginUpdateConflict
		}
	default:
		return ErrWPPluginUpdateConflict
	}
	return nil
}

func (s *WPPluginBatchService) loadBatchTaskForDecision(ctx context.Context, siteID int, taskID string) (WPUpdateTask, error) {
	if s == nil || siteID <= 0 || !wpUpdateTaskIDPattern.MatchString(taskID) {
		return WPUpdateTask{}, ErrWPPluginUpdateInvalid
	}
	task, err := s.store.getTask(ctx, taskID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (task.SiteID != siteID || task.BatchID == "" ||
		task.TaskKind != "update" || task.ComponentType != "plugin") {
		return WPUpdateTask{}, ErrWPPluginUpdateNotFound
	}
	if err != nil {
		return WPUpdateTask{}, err
	}
	if task.Status != wpUpdateFailed && task.Status != wpUpdateInterrupted {
		return WPUpdateTask{}, ErrWPPluginUpdateConflict
	}
	return task, nil
}

func (s *WPPluginBatchService) batchModel(ctx context.Context, batch WPUpdateBatch, includeItems bool) (models.WPPluginBatch, error) {
	created, err := parseRequiredWPInventoryTime(batch.CreatedAt)
	if err != nil {
		return models.WPPluginBatch{}, err
	}
	updated, err := parseRequiredWPInventoryTime(batch.UpdatedAt)
	if err != nil {
		return models.WPPluginBatch{}, err
	}
	model := models.WPPluginBatch{
		ID: batch.ID, SiteID: batch.SiteID, Status: batch.Status, TotalCount: batch.TotalCount,
		CreatedAt: created, UpdatedAt: updated,
	}
	if !includeItems {
		return model, nil
	}
	items, err := s.store.listBatchItems(ctx, batch.ID)
	if err != nil {
		return models.WPPluginBatch{}, err
	}
	for _, it := range items {
		model.Items = append(model.Items, models.WPPluginBatchItem{
			Position: it.Position, ComponentKey: it.ComponentKey, Status: it.Status, Message: it.Message, TaskID: it.TaskID,
			TaskStatus: it.TaskStatus, TaskStage: it.TaskStage, TaskRollbackStatus: it.TaskRollbackStatus, DatabaseBackupMode: it.DatabaseBackupMode, TaskRequiresAttention: it.TaskRequiresAttention,
			TaskManualDisposition: it.TaskManualDisposition, CurrentVersion: it.CurrentVersion, TargetVersion: it.TargetVersion,
		})
	}
	return model, nil
}
