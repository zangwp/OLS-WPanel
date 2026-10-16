package executor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"
)

const wpPluginUpdateControlTimeout = 30 * time.Second

var errUpdateTaskOwnershipLost = errors.New("update task ownership lost")

type wpPluginUpdateExecution struct {
	Task           WPUpdateTask
	WebRoot        string
	SystemUser     string
	Domain         string
	DatabaseName   string
	PHPVersion     string
	PackagePath    string
	DatabaseBackup string
	PluginBackup   string
	FileLockMode   string
	FileLockActive bool
}

// Each mutating method owns the atomic or compensating cleanup for its own
// substage. Once called, it must not leave a half-committed substage merely
// because ctx is cancelled; ownership is checked again only at boundaries.
type wpPluginUpdateOperations interface {
	// Prepare is read-only. It must not modify website files, options, locks,
	// maintenance state, or any other server state.
	Prepare(context.Context, wpPluginUpdateExecution) (bool, error)
	Unlock(context.Context, wpPluginUpdateExecution) error
	ApplyPluginUpdate(context.Context, wpPluginUpdateExecution) error
	ReactivatePlugin(context.Context, wpPluginUpdateExecution) error
	CheckTargetHealth(context.Context, wpPluginUpdateExecution, bool) error
	SetMaintenance(context.Context, wpPluginUpdateExecution, bool) error
	RestoreDatabase(context.Context, wpPluginUpdateExecution) error
	RestorePluginFiles(context.Context, wpPluginUpdateExecution) error
	CheckRollbackHealth(context.Context, wpPluginUpdateExecution) error
	RestoreFileLock(context.Context, wpPluginUpdateExecution) error
}

type wpPluginUpdateFinalizer interface {
	Finalize(context.Context, wpPluginUpdateExecution, bool) error
}

type wpPluginUpdateExecutor struct {
	store *wpUpdateStore
	root  string
	ops   wpPluginUpdateOperations
	now   func() time.Time
}

func newWPPluginUpdateExecutor(store *wpUpdateStore, artifactRoot string, ops wpPluginUpdateOperations) (*wpPluginUpdateExecutor, error) {
	if store == nil || store.db == nil || !filepath.IsAbs(artifactRoot) || ops == nil {
		return nil, errors.New("invalid plugin update executor")
	}
	return &wpPluginUpdateExecutor{store: store, root: filepath.Clean(artifactRoot), ops: ops, now: time.Now}, nil
}

func (e *wpPluginUpdateExecutor) Execute(ctx context.Context, taskID, owner string) error {
	execution, err := e.loadExecution(ctx, taskID, owner, wpUpdateRunning)
	if err != nil {
		return err
	}
	return e.execute(ctx, execution, owner)
}

func (e *wpPluginUpdateExecutor) execute(ctx context.Context, execution wpPluginUpdateExecution, owner string) error {
	taskID := execution.Task.ID
	wasActive, err := e.ops.Prepare(ctx, execution)
	if err != nil {
		if handled, interruptErr := e.interruptForSupervision(ctx, taskID, owner, err); handled {
			if interruptErr != nil {
				return interruptErr
			}
			return err
		}
		if finishErr := e.markFailure(ctx, taskID, owner, "precheck", false); finishErr != nil {
			return finishErr
		}
		return errors.New("plugin update operations precheck failed")
	}
	if err := ctx.Err(); err != nil {
		if finishErr := e.markFailure(ctx, taskID, owner, "precheck", false); finishErr != nil {
			return finishErr
		}
		return err
	}
	controlCtx, cancel := e.controlContext(ctx)
	if execution.Task.ComponentType == "theme" {
		err = e.store.recordThemePrepared(controlCtx, taskID, owner, e.now().UTC())
	} else {
		err = e.store.recordPluginPrepared(controlCtx, taskID, owner, wasActive, e.now().UTC())
	}
	cancel()
	if err != nil {
		return err
	}
	if err := e.runWriteSubstage(ctx, func(stageCtx context.Context) error { return e.ops.Unlock(stageCtx, execution) }); err != nil {
		return e.failBeforePluginWrite(ctx, execution, owner, "unlock")
	}
	if err := e.stage(ctx, taskID, owner, "unlocking", "updating_component"); err != nil {
		return err
	}
	if err := e.runWriteSubstage(ctx, func(stageCtx context.Context) error { return e.ops.ApplyPluginUpdate(stageCtx, execution) }); err != nil {
		if handled, interruptErr := e.interruptForSupervision(ctx, taskID, owner, err); handled {
			if interruptErr != nil {
				return interruptErr
			}
			return err
		}
		e.recordFailureEvent(ctx, taskID, owner, "plugin_update", "plugin_update_failed")
		return e.rollbackOrHalt(ctx, execution, owner, "plugin_update")
	}
	if wasActive {
		if err := e.stage(ctx, taskID, owner, "updating_component", "reactivating"); err != nil {
			return err
		}
		if err := e.runWriteSubstage(ctx, func(stageCtx context.Context) error { return e.ops.ReactivatePlugin(stageCtx, execution) }); err != nil {
			if handled, interruptErr := e.interruptForSupervision(ctx, taskID, owner, err); handled {
				if interruptErr != nil {
					return interruptErr
				}
				return err
			}
			e.recordFailureEvent(ctx, taskID, owner, "reactivation", "reactivation_failed")
			return e.rollbackOrHalt(ctx, execution, owner, "reactivation")
		}
		if err := e.stage(ctx, taskID, owner, "reactivating", "health_check"); err != nil {
			return err
		}
	} else if err := e.stage(ctx, taskID, owner, "updating_component", "health_check"); err != nil {
		return err
	}
	if err := e.runProbe(ctx, func(probeCtx context.Context) error { return e.ops.CheckTargetHealth(probeCtx, execution, wasActive) }); err != nil {
		if handled, interruptErr := e.interruptForSupervision(ctx, taskID, owner, err); handled {
			if interruptErr != nil {
				return interruptErr
			}
			return err
		}
		e.recordFailureEvent(ctx, taskID, owner, "health_check", pluginHealthCheckFailureCode(err))
		return e.rollbackOrHalt(ctx, execution, owner, "health_check")
	}
	if err := e.stage(ctx, taskID, owner, "health_check", "restoring_file_lock"); err != nil {
		return err
	}
	if err := e.runWriteSubstage(ctx, func(stageCtx context.Context) error { return e.ops.RestoreFileLock(stageCtx, execution) }); err != nil {
		e.recordFailureEvent(ctx, taskID, owner, "file_lock_restore", "file_lock_restore_failed")
		return e.rollbackOrHalt(ctx, execution, owner, "file_lock_restore")
	}
	if err := e.finalize(ctx, execution, false); err != nil {
		return err
	}
	controlCtx, cancel = e.controlContext(ctx)
	err = e.store.markSuccess(controlCtx, taskID, owner, e.now().UTC())
	cancel()
	if err == nil && execution.FileLockActive {
		refreshWPCodeIntegrityBaselineBestEffort(execution.Task.SiteID, "组件更新成功")
	}
	return err
}

func (e *wpPluginUpdateExecutor) runWriteSubstage(ctx context.Context, run func(context.Context) error) error {
	stageCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), wpUpdateLease)
	defer cancel()
	return run(stageCtx)
}

func (e *wpPluginUpdateExecutor) runProbe(ctx context.Context, run func(context.Context) error) error {
	probeCtx, cancel := e.controlContext(ctx)
	defer cancel()
	return run(probeCtx)
}

func (e *wpPluginUpdateExecutor) controlContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), wpPluginUpdateControlTimeout)
}

func (e *wpPluginUpdateExecutor) failBeforePluginWrite(ctx context.Context, execution wpPluginUpdateExecution, owner, failureStage string) error {
	owned, err := e.ownsRunningTask(ctx, execution.Task.ID, owner)
	if err != nil || !owned {
		if err != nil {
			return err
		}
		return errUpdateTaskOwnershipLost
	}
	restoreErr := e.runWriteSubstage(ctx, func(stageCtx context.Context) error { return e.ops.RestoreFileLock(stageCtx, execution) })
	finalizeErr := e.finalize(ctx, execution, restoreErr != nil)
	if err := e.markFailure(ctx, execution.Task.ID, owner, failureStage, restoreErr != nil); err != nil {
		return err
	}
	if restoreErr != nil {
		return errors.New("plugin update pre-write failure and file lock restoration failed")
	}
	if finalizeErr != nil {
		return finalizeErr
	}
	return fmt.Errorf("plugin update failed at %s before plugin write", failureStage)
}

// rollbackOrHalt handles update failure: auto_rollback=1 immediately rolls back;
// auto_rollback=0 finalizes the task without changes and waits for the user's decision.
func (e *wpPluginUpdateExecutor) rollbackOrHalt(ctx context.Context, execution wpPluginUpdateExecution, owner, failureStage string) error {
	if !execution.Task.AutoRollback {
		return e.haltForManualDecision(ctx, execution, owner, failureStage)
	}
	return e.rollback(ctx, execution, owner, failureStage)
}

func (e *wpPluginUpdateExecutor) rollback(ctx context.Context, execution wpPluginUpdateExecution, owner, failureStage string) error {
	log.Printf("插件更新触发自动回滚 site=%s 组件=%s task=%s 失败阶段=%s", execution.Domain, execution.Task.ComponentKey, execution.Task.ID, failureStage)
	controlCtx, cancel := e.controlContext(ctx)
	err := e.store.beginAutomaticRollback(controlCtx, execution.Task.ID, owner, failureStage, e.now().UTC())
	cancel()
	if err != nil {
		return err
	}
	succeeded, rollbackErr, ownershipErr := e.runRollbackSequence(ctx, execution, owner, wpUpdateRunning, e.interruptForSupervision)
	if ownershipErr != nil {
		return ownershipErr
	}
	controlCtx, cancel = e.controlContext(ctx)
	err = e.store.finishAutomaticRollback(controlCtx, execution.Task.ID, owner, succeeded, e.now().UTC())
	cancel()
	if err != nil {
		return err
	}
	if rollbackErr != nil {
		return errors.New("plugin update failed and automatic rollback failed")
	}
	if execution.FileLockActive {
		refreshWPCodeIntegrityBaselineBestEffort(execution.Task.SiteID, "组件更新自动回滚成功")
	}
	return fmt.Errorf("plugin update failed at %s and was rolled back", failureStage)
}

// haltForManualDecision marks auto_rollback=0 tasks failed after update/health-check failure
// and waits for rollback or ignore without automatically changing files or the database.
func (e *wpPluginUpdateExecutor) haltForManualDecision(ctx context.Context, execution wpPluginUpdateExecution, owner, failureStage string) error {
	log.Printf("插件更新失败但 auto_rollback 已关闭，等待人工决定 site=%s 组件=%s task=%s 失败阶段=%s", execution.Domain, execution.Task.ComponentKey, execution.Task.ID, failureStage)
	if err := e.finalize(ctx, execution, false); err != nil {
		return err
	}
	controlCtx, cancel := e.controlContext(ctx)
	err := e.store.haltForManualRollback(controlCtx, execution.Task.ID, owner, failureStage, e.now().UTC())
	cancel()
	if err != nil {
		return err
	}
	return fmt.Errorf("plugin update failed at %s and is awaiting a manual rollback decision", failureStage)
}

func newWPPluginManualRollbackOwner() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "manual-rollback-" + hex.EncodeToString(raw[:]), nil
}

// ManualRollback reruns the normal rollback sequence for a failed auto_rollback=0 task.
// Prepare creates a fresh PHP runner session because the original session may have been released.
func (e *wpPluginUpdateExecutor) ManualRollback(ctx context.Context, taskID string) error {
	owner, err := newWPPluginManualRollbackOwner()
	if err != nil {
		return err
	}
	if err := e.store.beginManualRollback(ctx, taskID, owner, e.now().UTC()); err != nil {
		return err
	}
	execution, err := e.loadExecution(ctx, taskID, owner, wpUpdateFailed)
	if err != nil {
		e.abandonManualRollbackCleanup(ctx, taskID, owner)
		return err
	}
	if _, err := e.ops.Prepare(ctx, execution); err != nil {
		e.abandonManualRollbackCleanup(ctx, taskID, owner)
		return errors.New("manual rollback preparation failed")
	}
	stopHeartbeat := e.startManualRollbackHeartbeat(taskID, owner)
	succeeded, rollbackErr, ownershipErr := e.runRollbackSequence(ctx, execution, owner, wpUpdateFailed, nil)
	stopHeartbeat()
	if ownershipErr != nil {
		return ownershipErr
	}
	if err := e.finishManualRollback(ctx, taskID, owner, succeeded); err != nil {
		return err
	}
	if rollbackErr != nil {
		return errors.New("manual rollback failed")
	}
	if execution.FileLockActive {
		refreshWPCodeIntegrityBaselineBestEffort(execution.Task.SiteID, "组件更新人工回滚成功")
	}
	return nil
}

// startManualRollbackHeartbeat renews the lease every wpCoreUpdateWorkerHeartbeatInterval
// and returns a function that stops and joins the heartbeat goroutine. Manual rollback runs
// synchronously, so a separate heartbeat protects even a single step lasting longer than wpUpdateLease
// from a second request claiming it. Step-boundary renewals in runRollbackStep remain in place.
func (e *wpPluginUpdateExecutor) startManualRollbackHeartbeat(taskID, owner string) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(wpCoreUpdateWorkerHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				renewed, err := e.store.renewManualRollbackClaim(context.Background(), taskID, owner, e.now().UTC())
				if err != nil || !renewed {
					return
				}
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

func (e *wpPluginUpdateExecutor) finishManualRollback(ctx context.Context, taskID, owner string, succeeded bool) error {
	controlCtx, cancel := e.controlContext(ctx)
	defer cancel()
	return e.store.finishManualRollback(controlCtx, taskID, owner, succeeded, e.now().UTC())
}

// abandonManualRollbackCleanup uses controlContext (context.WithoutCancel) to release the claim.
// loadExecution/Prepare may fail because the request was canceled; reusing that context would
// also prevent cleanup, leaving lease_owner set and blocking both rollback retries and Ignore.
func (e *wpPluginUpdateExecutor) abandonManualRollbackCleanup(ctx context.Context, taskID, owner string) {
	controlCtx, cancel := e.controlContext(ctx)
	defer cancel()
	if err := e.store.abandonManualRollback(controlCtx, taskID, owner, e.now().UTC()); err != nil {
		log.Printf("放弃人工回滚认领失败 task=%s: %v", taskID, err)
	}
}

// runRollbackSequence enables maintenance, restores the database when database_backup_mode=fresh,
// restores plugin files, disables maintenance, checks health, and restores file locks. expectedStatus selects running
// for automatic rollback or failed for manual rollback ownership checks.
// Only automatic rollback converts uncertain health checks to interrupted_unknown;
// manual rollback treats them as ordinary failures on an already terminal task.
// Return success, accumulated step errors, and an ownership error requiring immediate return.
func (e *wpPluginUpdateExecutor) runRollbackSequence(ctx context.Context, execution wpPluginUpdateExecution, owner, expectedStatus string,
	handleSupervisionUncertain func(context.Context, string, string, error) (bool, error)) (succeeded bool, rollbackErr, ownershipErr error) {
	taskID := execution.Task.ID
	if stepErr, abort := e.runRollbackStep(ctx, taskID, owner, expectedStatus, "maintenance_on",
		func(stepCtx context.Context) error { return e.ops.SetMaintenance(stepCtx, execution, true) }); abort != nil {
		return false, nil, abort
	} else if stepErr != nil {
		rollbackErr = errors.Join(rollbackErr, stepErr)
	}
	if execution.Task.DatabaseBackupMode == "fresh" {
		if stepErr, abort := e.runRollbackStep(ctx, taskID, owner, expectedStatus, "restore_database",
			func(stepCtx context.Context) error { return e.ops.RestoreDatabase(stepCtx, execution) }); abort != nil {
			return false, nil, abort
		} else if stepErr != nil {
			rollbackErr = errors.Join(rollbackErr, stepErr)
		}
	}
	if stepErr, abort := e.runRollbackStep(ctx, taskID, owner, expectedStatus, "restore_plugin_files",
		func(stepCtx context.Context) error { return e.ops.RestorePluginFiles(stepCtx, execution) }); abort != nil {
		return false, nil, abort
	} else if stepErr != nil {
		rollbackErr = errors.Join(rollbackErr, stepErr)
	}
	if rollbackErr == nil {
		if stepErr, abort := e.runRollbackStep(ctx, taskID, owner, expectedStatus, "maintenance_off",
			func(stepCtx context.Context) error { return e.ops.SetMaintenance(stepCtx, execution, false) }); abort != nil {
			return false, nil, abort
		} else if stepErr != nil {
			rollbackErr = stepErr
		} else {
			if err := e.requireOwnershipWithStatus(ctx, taskID, owner, expectedStatus); err != nil {
				return false, nil, err
			}
			if err := e.runProbe(ctx, func(probeCtx context.Context) error { return e.ops.CheckRollbackHealth(probeCtx, execution) }); err != nil {
				if handleSupervisionUncertain != nil {
					if handled, interruptErr := handleSupervisionUncertain(ctx, taskID, owner, err); handled {
						if interruptErr != nil {
							return false, nil, interruptErr
						}
						return false, nil, err
					}
				}
				e.recordFailureEventWithStatus(ctx, taskID, owner, expectedStatus, "rollback", pluginRollbackStepCode("rollback_health", err))
				rollbackErr = err
			}
		}
	}
	if stepErr, abort := e.runRollbackStep(ctx, taskID, owner, expectedStatus, "restore_file_lock",
		func(stepCtx context.Context) error { return e.ops.RestoreFileLock(stepCtx, execution) }); abort != nil {
		return false, nil, abort
	} else if stepErr != nil {
		rollbackErr = errors.Join(rollbackErr, stepErr)
	}
	succeeded = rollbackErr == nil
	if err := e.finalize(ctx, execution, !succeeded); err != nil {
		rollbackErr = errors.Join(rollbackErr, err)
		succeeded = false
	}
	return succeeded, rollbackErr, nil
}

// recordFailureEvent logs step failures for frontend export; logging errors do not stop execution.
func (e *wpPluginUpdateExecutor) recordFailureEvent(ctx context.Context, taskID, owner, stage, code string) {
	e.recordFailureEventWithStatus(ctx, taskID, owner, wpUpdateRunning, stage, code)
}

// recordFailureEventWithStatus also accepts failed status for manual rollback event recording.
func (e *wpPluginUpdateExecutor) recordFailureEventWithStatus(ctx context.Context, taskID, owner, status, stage, code string) {
	if code == "" {
		code = stage + "_failed"
	}
	if err := e.store.recordEventWithStatus(ctx, taskID, owner, status, stage, "failed", code, e.now().UTC()); err != nil {
		log.Printf("record %s failure event: %v", stage, err)
	}
}

// pluginHealthCheckFailureCode maps health-check errors to stable error codes.
func pluginHealthCheckFailureCode(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "site health probe detected fatal response"):
		return "site_fatal_error"
	case strings.Contains(msg, "site health probe failed"):
		return "site_unreachable"
	case strings.Contains(msg, "site health response invalid"):
		return "site_response_invalid"
	case strings.Contains(msg, "invalid probe domain"):
		return "invalid_probe_domain"
	case strings.Contains(msg, "plugin health plan mismatch"), strings.Contains(msg, "active expectation changed"):
		return "plugin_health_plan_mismatch"
	default:
		return "health_check_failed"
	}
}

// pluginRollbackStepCode derives an error code from the rollback step and error.
func pluginRollbackStepCode(step string, err error) string {
	if err == nil {
		return ""
	}
	base := step + "_failed"
	switch step {
	case "maintenance_on":
		base = "rollback_maintenance_failed"
	case "restore_database":
		base = "rollback_restore_database_failed"
	case "restore_plugin_files":
		base = "rollback_restore_plugin_failed"
	case "maintenance_off":
		base = "rollback_maintenance_off_failed"
	case "rollback_health":
		base = "rollback_health_check_failed"
	case "restore_file_lock":
		base = "rollback_restore_lock_failed"
	}
	msg := err.Error()
	if strings.Contains(msg, "site health") {
		return base + "_site"
	}
	return base
}

func (e *wpPluginUpdateExecutor) interruptForSupervision(ctx context.Context, taskID, owner string, cause error) (bool, error) {
	if !errors.Is(cause, errWPPluginScopeSupervisionUncertain) {
		return false, nil
	}
	controlCtx, cancel := e.controlContext(ctx)
	defer cancel()
	changed, err := e.store.interruptOwned(controlCtx, taskID, owner, "runner_supervision_uncertain", e.now().UTC())
	if err != nil {
		return true, err
	}
	if !changed {
		return true, errUpdateTaskOwnershipLost
	}
	return true, nil
}

func (e *wpPluginUpdateExecutor) finalize(ctx context.Context, execution wpPluginUpdateExecution, preserve bool) error {
	finalizer, ok := e.ops.(wpPluginUpdateFinalizer)
	if !ok {
		return nil
	}
	controlCtx, cancel := e.controlContext(ctx)
	defer cancel()
	return finalizer.Finalize(controlCtx, execution, preserve)
}

func (e *wpPluginUpdateExecutor) requireOwnership(ctx context.Context, taskID, owner string) error {
	return e.requireOwnershipWithStatus(ctx, taskID, owner, wpUpdateRunning)
}

// requireOwnershipWithStatus supports failed tasks during manual rollback.
func (e *wpPluginUpdateExecutor) requireOwnershipWithStatus(ctx context.Context, taskID, owner, status string) error {
	// Renew the manual rollback lease at each step's ownership check to prevent another
	// request from claiming it during lengthy work.
	if status == wpUpdateFailed {
		renewed, err := e.store.renewManualRollbackClaim(ctx, taskID, owner, e.now().UTC())
		if err != nil {
			return err
		}
		if !renewed {
			return errUpdateTaskOwnershipLost
		}
		return nil
	}
	owned, err := e.ownsTaskWithStatus(ctx, taskID, owner, status)
	if err != nil {
		return err
	}
	if !owned {
		return errUpdateTaskOwnershipLost
	}
	return nil
}

func (e *wpPluginUpdateExecutor) ownsRunningTask(ctx context.Context, taskID, owner string) (bool, error) {
	return e.ownsTaskWithStatus(ctx, taskID, owner, wpUpdateRunning)
}

func (e *wpPluginUpdateExecutor) ownsTaskWithStatus(ctx context.Context, taskID, owner, status string) (bool, error) {
	controlCtx, cancel := e.controlContext(ctx)
	defer cancel()
	return e.store.ownsTaskWithStatus(controlCtx, taskID, owner, status)
}

// runRollbackStep checks ownership under expectedStatus, runs a shared automatic/manual
// rollback step, and records failures. A non-nil abort means ownership failed or was lost:
// return immediately without adding it to rollback errors. Otherwise accumulate stepErr and continue.
func (e *wpPluginUpdateExecutor) runRollbackStep(ctx context.Context, taskID, owner, expectedStatus, stepName string, run func(context.Context) error) (stepErr, abort error) {
	if err := e.requireOwnershipWithStatus(ctx, taskID, owner, expectedStatus); err != nil {
		return nil, err
	}
	if err := e.runWriteSubstage(ctx, run); err != nil {
		e.recordFailureEventWithStatus(ctx, taskID, owner, expectedStatus, "rollback", pluginRollbackStepCode(stepName, err))
		return err, nil
	}
	return nil, nil
}

func (e *wpPluginUpdateExecutor) markFailure(ctx context.Context, taskID, owner, stage string, attention bool) error {
	controlCtx, cancel := e.controlContext(ctx)
	defer cancel()
	return e.store.markFailure(controlCtx, taskID, owner, stage, attention, e.now().UTC())
}

func (e *wpPluginUpdateExecutor) stage(ctx context.Context, taskID, owner, expectedStage, nextStage string) error {
	controlCtx, cancel := e.controlContext(ctx)
	err := e.store.advanceOwnedStage(controlCtx, taskID, owner, expectedStage, nextStage, e.now().UTC())
	cancel()
	if err != nil {
		return err
	}
	if ctx.Err() == nil {
		return nil
	}
	controlCtx, cancel = e.controlContext(ctx)
	_, interruptErr := e.store.interruptOwned(controlCtx, taskID, owner, "execution_cancelled", e.now().UTC())
	cancel()
	if interruptErr != nil {
		return interruptErr
	}
	return ctx.Err()
}

func (e *wpPluginUpdateExecutor) loadExecution(ctx context.Context, taskID, owner, expectedStatus string) (wpPluginUpdateExecution, error) {
	if !wpUpdateTaskIDPattern.MatchString(taskID) || owner == "" {
		return wpPluginUpdateExecution{}, errors.New("invalid plugin update execution")
	}
	task, err := e.store.getTask(ctx, taskID)
	if err != nil || task.Status != expectedStatus || task.TaskKind != "update" || task.ComponentType != "plugin" ||
		task.LeaseOwner != owner || !task.BackupReady || !validWPPluginComponentKey(task.ComponentKey) {
		return wpPluginUpdateExecution{}, errors.New("plugin update task is not executable")
	}
	taskDir := filepath.Join(e.root, taskID)
	packagePath := filepath.Join(taskDir, "package.zip")
	if task.PackageSnapshotPath != packagePath {
		return wpPluginUpdateExecution{}, errors.New("plugin update package path is not controlled")
	}
	sha, _, err := hashRegularFile(packagePath)
	if err != nil || sha != task.DownloadedSHA256 {
		return wpPluginUpdateExecution{}, errors.New("plugin update package digest mismatch")
	}
	slug := strings.Split(task.ComponentKey, "/")[0]
	if _, err := ValidateWPComponentPackage(ctx, packagePath, WPComponentPackageExpectation{
		ComponentType: "plugin", ComponentKey: task.ComponentKey, OfficialSlug: slug, TargetVersion: task.TargetVersion,
	}); err != nil {
		return wpPluginUpdateExecution{}, errors.New("plugin update package validation failed")
	}
	validatedSHA, _, err := hashRegularFile(packagePath)
	if err != nil || validatedSHA != sha {
		return wpPluginUpdateExecution{}, errors.New("plugin update package changed during validation")
	}
	var execution wpPluginUpdateExecution
	execution.Task, execution.PackagePath = task, packagePath
	var lockEnabled int
	err = e.store.db.QueryRowContext(ctx, `SELECT domain,system_user,web_root,db_name,COALESCE(NULLIF(php_version,''),'8.3'),file_lock_mode,file_lock_enabled
		FROM websites WHERE id=? AND site_type='wordpress' AND status='active'`, task.SiteID).
		Scan(&execution.Domain, &execution.SystemUser, &execution.WebRoot, &execution.DatabaseName, &execution.PHPVersion, &execution.FileLockMode, &lockEnabled)
	if err != nil || !filepath.IsAbs(execution.WebRoot) {
		return wpPluginUpdateExecution{}, errors.New("plugin update site is not executable")
	}
	execution.FileLockActive = lockEnabled != 0
	rows, err := e.store.db.QueryContext(ctx, `SELECT kind,file_path,sha256 FROM wp_update_task_backups
		WHERE task_id=? AND protected=1 AND deleted_at IS NULL AND kind IN ('database','plugin_files')`, taskID)
	if err != nil {
		return wpPluginUpdateExecution{}, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var kind, name, digest string
		if err := rows.Scan(&kind, &name, &digest); err != nil {
			return wpPluginUpdateExecution{}, err
		}
		expected := filepath.Join(taskDir, map[string]string{"database": "database.sql.gz", "plugin_files": "plugin-files.tar.gz"}[kind])
		if name != expected || seen[kind] {
			return wpPluginUpdateExecution{}, errors.New("plugin update backup path is not controlled")
		}
		actual, _, err := hashRegularFile(name)
		if err != nil || actual != digest {
			return wpPluginUpdateExecution{}, errors.New("plugin update backup digest mismatch")
		}
		if kind == "database" {
			execution.DatabaseBackup = name
		} else {
			execution.PluginBackup = name
		}
		seen[kind] = true
	}
	if err := rows.Err(); err != nil {
		return wpPluginUpdateExecution{}, err
	}
	if (task.DatabaseBackupMode == "fresh" && !seen["database"]) || !seen["plugin_files"] {
		return wpPluginUpdateExecution{}, errors.New("plugin update backups are incomplete")
	}
	return execution, nil
}
