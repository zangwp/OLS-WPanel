package executor

import (
	"context"
	"errors"
	"time"
)

var ErrSiteRestoreActive = errors.New("website already has an active restore task")

// Separate queue admission from the site-operation lock held by the worker.
// Bounded, non-blocking admission avoids adding unbounded mutex waiters when
// the serialized queue is full. All HTTP database/file restore entry points
// use this guard, including update-backup and uploaded database restores.
var siteRestoreAdmission = make(chan struct{}, 1)

// FindActiveTask returns only an ownership/status snapshot, never execution
// payloads or result channels. Completed tasks are not active operations.
func (q *TaskQueue) FindActiveTask(siteID int, taskTypes ...TaskType) (*Task, bool) {
	if q == nil || siteID <= 0 || len(taskTypes) == 0 {
		return nil, false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pruneCompletedLocked(time.Now())
	for _, task := range q.tasks {
		if task == nil || task.SiteID != siteID || (task.Status != TaskStatusWaiting && task.Status != TaskStatusRunning) {
			continue
		}
		for _, taskType := range taskTypes {
			if task.Type != taskType {
				continue
			}
			snapshot := *task
			snapshot.Payload = nil
			snapshot.ResultCh = nil
			if task.Result != nil {
				result := *task.Result
				result.Data = nil
				snapshot.Result = &result
			}
			return &snapshot, true
		}
	}
	return nil, false
}

// EnqueueSiteRestoreContext makes the active-task check and queue admission
// exclusive across both restore kinds. The request context controls admission;
// once admitted the worker owns the task independently of the HTTP connection.
func (q *TaskQueue) EnqueueSiteRestoreContext(ctx context.Context, taskType TaskType, payload interface{}) (*Task, error) {
	if q == nil || q.queue == nil {
		return nil, ErrTaskQueueUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if taskType != TaskRestoreBackup && taskType != TaskRestoreFileBackup {
		return nil, errors.New("invalid restore task type")
	}
	siteID := taskSiteID(payload)
	if siteID <= 0 {
		return nil, errors.New("invalid restore website")
	}
	select {
	case siteRestoreAdmission <- struct{}{}:
		defer func() { <-siteRestoreAdmission }()
	default:
		return nil, ErrTaskQueueFull
	}
	if _, active := q.FindActiveTask(siteID, TaskRestoreBackup, TaskRestoreFileBackup); active {
		return nil, ErrSiteRestoreActive
	}
	return q.EnqueueContext(ctx, taskType, payload)
}
