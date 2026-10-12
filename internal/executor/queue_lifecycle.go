package executor

import (
	"context"
	"log"
	"os"
	"time"
)

func (q *TaskQueue) operationLifecycle() *panelOperationLifecycle {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.lifecycle == nil {
		// Standalone queues (including tests) have their own lifecycle. The
		// production InitQueue explicitly shares the global panel barrier.
		q.lifecycle = &panelOperationLifecycle{}
	}
	return q.lifecycle
}

func (q *TaskQueue) registerLifecycleLocked(id string, release func()) {
	if q.lifecycleReleases == nil {
		q.lifecycleReleases = make(map[string]func())
	}
	if q.changed == nil {
		q.changed = make(chan struct{})
	}
	if q.closed == nil {
		q.closed = make(chan struct{})
	}
	q.lifecycleReleases[id] = release
}

func (q *TaskQueue) notifyChangedLocked() {
	if q.changed != nil {
		close(q.changed)
	}
	q.changed = make(chan struct{})
}

// Shutdown rejects new work and cancels tasks which have not begun. It never
// starts a waiting restore merely to drain a queue during process shutdown.
// Running tasks keep their original bounded execution/rollback contexts.
func (q *TaskQueue) Shutdown(ctx context.Context) error {
	if q == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	type canceled struct {
		task    *Task
		channel chan TaskResult
		release func()
	}
	var waiting []canceled
	q.mu.Lock()
	if !q.closing {
		q.closing = true
		if q.closed == nil {
			q.closed = make(chan struct{})
		}
		close(q.closed)
	}
	for id, task := range q.tasks {
		if task.Status != TaskStatusWaiting {
			continue
		}
		copy := *task
		waiting = append(waiting, canceled{&copy, task.ResultCh, q.lifecycleReleases[id]})
		delete(q.lifecycleReleases, id)
		task.Status = TaskStatusFailed
		task.UpdatedAt = time.Now()
		task.Result = &TaskResult{Message: "面板正在关闭，尚未开始的任务已取消；请在重启后重新提交"}
		task.Payload = nil
		task.ResultCh = nil
		if q.taskCount > 0 {
			q.taskCount--
		}
	}
	q.notifyChangedLocked()
	q.mu.Unlock()
	for _, item := range waiting {
		cleanupCanceledQueueTask(item.task)
		if item.release != nil {
			item.release()
		}
		deliverTaskResult(item.task.ID, item.channel, TaskResult{Message: "面板正在关闭，尚未开始的任务已取消；请在重启后重新提交"})
	}
	for {
		q.mu.Lock()
		if q.taskCount == 0 {
			q.mu.Unlock()
			q.StopCleanup()
			return nil
		}
		changed := q.changed
		q.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// These resources transfer to the queue at admission, even before execution.
// Cancellation must return the pre-held update slot and delete only the owned
// temporary upload; regular backup files are never removed here.
func cleanupCanceledQueueTask(task *Task) {
	if task == nil {
		return
	}
	if payload, ok := task.Payload.(*RestoreBackupPayload); ok && payload != nil {
		if payload.UpdateBackupPath != "" && payload.Site != nil {
			ReleaseSiteOpLock(payload.Site.ID)
		}
		if payload.RemoveFileAfter {
			if path, ok := ownedRestoreUploadPath(payload.FilePath); ok {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					log.Printf("移除已取消恢复的临时上传失败: %v", err)
				}
			}
		}
	}
}
