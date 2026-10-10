package executor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

func newRestoreAdmissionTestQueue() *TaskQueue {
	return &TaskQueue{queue: make(chan *Task, 20), tasks: make(map[string]*Task)}
}

func TestFindActiveRestoreTaskUsesOwnershipAndRedactsExecutionState(t *testing.T) {
	q := newRestoreAdmissionTestQueue()
	q.tasks["other-site"] = &Task{ID: "other-site", SiteID: 2, Type: TaskRestoreFileBackup, Status: TaskStatusRunning}
	q.tasks["finished"] = &Task{ID: "finished", SiteID: 1, Type: TaskRestoreFileBackup, Status: TaskStatusSuccess, UpdatedAt: time.Now()}
	q.tasks["unrelated"] = &Task{ID: "unrelated", SiteID: 1, Type: TaskCreateBackup, Status: TaskStatusRunning}
	q.tasks["restore"] = &Task{
		ID: "restore", SiteID: 1, Type: TaskRestoreBackup, Status: TaskStatusWaiting,
		Payload:  &RestoreBackupPayload{Site: &models.Website{ID: 1}, Filename: "private.sql.gz"},
		ResultCh: make(chan TaskResult), Result: &TaskResult{Message: "queued", Data: "private execution data"},
	}
	task, active := q.FindActiveTask(1, TaskRestoreBackup, TaskRestoreFileBackup)
	if !active || task == nil || task.ID != "restore" || task.Payload != nil || task.ResultCh != nil || task.Result.Data != nil {
		t.Fatalf("invalid active restore snapshot: active=%v task=%+v", active, task)
	}
	task.Result.Message = "changed copy"
	if q.tasks["restore"].Result.Message != "queued" {
		t.Fatal("active task snapshot mutated stored execution result")
	}
	if task, active := q.FindActiveTask(3, TaskRestoreBackup, TaskRestoreFileBackup); active || task != nil {
		t.Fatalf("another site's restore was exposed: task=%+v", task)
	}
	if task, active := (*TaskQueue)(nil).FindActiveTask(1, TaskRestoreBackup); active || task != nil {
		t.Fatal("nil queue reported an active operation")
	}
}

func TestSiteRestoreAdmissionPreventsDatabaseAndFileOverlap(t *testing.T) {
	for _, firstType := range []TaskType{TaskRestoreBackup, TaskRestoreFileBackup} {
		t.Run(string(firstType), func(t *testing.T) {
			q := newRestoreAdmissionTestQueue()
			site := &models.Website{ID: 1, Domain: "restore.example.com"}
			var firstPayload interface{} = &RestoreBackupPayload{Site: site}
			if firstType == TaskRestoreFileBackup {
				firstPayload = &RestoreFileBackupPayload{Site: site, BackupID: 9}
			}
			first, err := q.EnqueueSiteRestoreContext(context.Background(), firstType, firstPayload)
			if err != nil {
				t.Fatal(err)
			}
			for _, next := range []struct {
				kind    TaskType
				payload interface{}
			}{
				{TaskRestoreBackup, &RestoreBackupPayload{Site: site}},
				{TaskRestoreFileBackup, &RestoreFileBackupPayload{Site: site, BackupID: 10}},
			} {
				if task, err := q.EnqueueSiteRestoreContext(context.Background(), next.kind, next.payload); task != nil || !errors.Is(err, ErrSiteRestoreActive) {
					t.Fatalf("duplicate restore admitted: task=%+v err=%v", task, err)
				}
			}
			if task, err := q.EnqueueSiteRestoreContext(context.Background(), TaskRestoreFileBackup,
				&RestoreFileBackupPayload{Site: &models.Website{ID: 2}, BackupID: 1}); err != nil || task == nil {
				t.Fatalf("another site's restore was incorrectly blocked: task=%v err=%v", task, err)
			}
			q.mu.Lock()
			q.tasks[first.ID].Status = TaskStatusFailed
			q.tasks[first.ID].UpdatedAt = time.Now()
			q.mu.Unlock()
			if task, err := q.EnqueueSiteRestoreContext(context.Background(), TaskRestoreBackup, &RestoreBackupPayload{Site: site}); err != nil || task == nil {
				t.Fatalf("completed restore prevented a later retry: task=%v err=%v", task, err)
			}
		})
	}
}

func TestConcurrentSiteRestoreAdmissionCreatesOneTask(t *testing.T) {
	q := newRestoreAdmissionTestQueue()
	const requests = 20
	var wait sync.WaitGroup
	results := make(chan error, requests)
	for i := 0; i < requests; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := q.EnqueueSiteRestoreContext(context.Background(), TaskRestoreFileBackup,
				&RestoreFileBackupPayload{Site: &models.Website{ID: 1}, BackupID: 1})
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	admitted := 0
	for err := range results {
		if err == nil {
			admitted++
		} else if !errors.Is(err, ErrSiteRestoreActive) && !errors.Is(err, ErrTaskQueueFull) {
			t.Fatalf("unexpected duplicate-admission error: %v", err)
		}
	}
	if admitted != 1 || q.QueueLength() != 1 || len(q.tasks) != 1 {
		t.Fatalf("concurrent restores were duplicated: admitted=%d queue=%d tasks=%d", admitted, q.QueueLength(), len(q.tasks))
	}
}

func TestRestoreAdmissionCancellationDoesNotCancelAdmittedTask(t *testing.T) {
	q := newRestoreAdmissionTestQueue()
	payload := &RestoreFileBackupPayload{Site: &models.Website{ID: 1}, BackupID: 1}
	ctx, cancel := context.WithCancel(context.Background())
	task, err := q.EnqueueSiteRestoreContext(ctx, TaskRestoreFileBackup, payload)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if active, exists := q.FindActiveTask(1, TaskRestoreFileBackup); !exists || active.ID != task.ID {
		t.Fatal("disconnect after admission removed the worker-owned restore")
	}
	if task, err := q.EnqueueSiteRestoreContext(ctx, TaskRestoreFileBackup, payload); task != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("already-cancelled admission accepted: task=%v err=%v", task, err)
	}
	if q.QueueLength() != 1 {
		t.Fatal("cancelled duplicate changed admitted work")
	}
}
