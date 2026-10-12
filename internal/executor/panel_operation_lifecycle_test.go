package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func TestPanelUpdateAndQueueAdmissionAreAtomic(t *testing.T) {
	for i := 0; i < 100; i++ {
		lifecycle := &panelOperationLifecycle{}
		q := &TaskQueue{queue: make(chan *Task, 1), tasks: make(map[string]*Task), lifecycle: lifecycle}
		start := make(chan struct{})
		var group sync.WaitGroup
		var task *Task
		var admissionErr, updateErr error
		var releaseUpdate func()
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			task, admissionErr = q.EnqueueContext(context.Background(), TaskType("pending_restore"), nil)
		}()
		go func() { defer group.Done(); <-start; releaseUpdate, updateErr = lifecycle.beginUpdate() }()
		close(start)
		group.Wait()
		if admissionErr == nil && updateErr == nil {
			t.Fatal("update and new writer were admitted together")
		}
		if admissionErr == nil {
			if task == nil || !errors.Is(updateErr, ErrPanelOperationsBusy) {
				t.Fatalf("unexpected queued winner: %v %v", task, updateErr)
			}
		} else if updateErr == nil {
			if !errors.Is(admissionErr, ErrPanelOperationsClosed) {
				t.Fatal(admissionErr)
			}
			releaseUpdate()
		} else {
			t.Fatalf("both rejected: %v / %v", admissionErr, updateErr)
		}
		if err := q.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQueueKeepsLifecycleUntilRunningTaskFinishes(t *testing.T) {
	lifecycle := &panelOperationLifecycle{}
	entered, finish := make(chan struct{}), make(chan struct{})
	q := &TaskQueue{queue: make(chan *Task, 2), tasks: make(map[string]*Task), lifecycle: lifecycle, executeTask: func(*Task) TaskResult { close(entered); <-finish; return TaskResult{Success: true} }}
	go q.worker()
	task, err := q.EnqueueContext(context.Background(), TaskType("slow_restore"), nil)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	if release, err := lifecycle.beginUpdate(); !errors.Is(err, ErrPanelOperationsBusy) {
		if release != nil {
			release()
		}
		t.Fatalf("running restore allowed update: %v", err)
	}
	close(finish)
	<-task.ResultCh
	release, err := lifecycle.beginUpdate()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err = q.EnqueueContext(context.Background(), TaskType("new_restore"), nil); !errors.Is(err, ErrPanelOperationsClosed) {
		t.Fatalf("restart barrier did not close admission: %v", err)
	}
}

func TestFailedAdmissionReturnsLifecycleLease(t *testing.T) {
	lifecycle := &panelOperationLifecycle{}
	q := &TaskQueue{queue: make(chan *Task), tasks: make(map[string]*Task), lifecycle: lifecycle, enqueueTimeout: time.Millisecond}
	if _, err := q.EnqueueContext(context.Background(), TaskType("full"), nil); !errors.Is(err, ErrTaskQueueFull) {
		t.Fatal(err)
	}
	release, err := lifecycle.beginUpdate()
	if err != nil {
		t.Fatal(err)
	}
	release()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = q.EnqueueContext(canceled, TaskType("canceled"), nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	release, err = lifecycle.beginUpdate()
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestShutdownCannotBeReopenedByFailedUpdate(t *testing.T) {
	lifecycle := &panelOperationLifecycle{}
	release, err := lifecycle.beginUpdate()
	if err != nil {
		t.Fatal(err)
	}
	lifecycle.stopAdmission()
	release()
	release()
	if _, err = lifecycle.acquire(); !errors.Is(err, ErrPanelOperationsClosed) {
		t.Fatalf("failed update reopened shutdown admission: %v", err)
	}
	if _, err = lifecycle.beginUpdate(); !errors.Is(err, ErrPanelOperationsClosed) {
		t.Fatalf("shutdown allowed another update: %v", err)
	}
}

func TestQueueShutdownCancelsWaitingTasksWithoutStartingThem(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	var executed atomic.Int32
	q := &TaskQueue{queue: make(chan *Task, 2), tasks: make(map[string]*Task), executeTask: func(*Task) TaskResult { executed.Add(1); close(entered); <-finish; return TaskResult{Success: true} }}
	go q.worker()
	first, err := q.EnqueueContext(context.Background(), TaskType("running"), nil)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	upload, err := os.CreateTemp("", "olswpanel_upload_shutdown_*.sql")
	if err != nil {
		t.Fatal(err)
	}
	_ = upload.Close()
	defer os.Remove(upload.Name())
	second, err := q.EnqueueContext(context.Background(), TaskRestoreBackup, &RestoreBackupPayload{Site: &models.Website{ID: 42}, FilePath: upload.Name(), RemoveFileAfter: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err = q.Shutdown(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("running task was not waited for: %v", err)
	}
	if result := <-second.ResultCh; result.Success {
		t.Fatal("waiting restore reported success")
	}
	if _, err = os.Stat(upload.Name()); !os.IsNotExist(err) {
		t.Fatalf("canceled upload retained: %v", err)
	}
	if snapshot, _ := q.GetTask(second.ID); snapshot == nil || snapshot.Status != TaskStatusFailed || snapshot.Payload != nil {
		t.Fatalf("bad canceled state: %+v", snapshot)
	}
	if _, err = q.EnqueueContext(context.Background(), TaskType("new"), nil); !errors.Is(err, ErrTaskQueueUnavailable) {
		t.Fatalf("shutdown queue admitted work: %v", err)
	}
	close(finish)
	<-first.ResultCh
	if err = q.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if executed.Load() != 1 || q.QueueLength() != 0 || q.IsRunning() {
		t.Fatalf("shutdown execution/count: %d %d %v", executed.Load(), q.QueueLength(), q.IsRunning())
	}
}

func TestSiteOperationAndPanelUpdateShareLifecycle(t *testing.T) {
	old := panelOperations
	panelOperations = &panelOperationLifecycle{}
	defer func() { ReleaseSiteOpLock(700001); panelOperations = old }()
	for _, acquire := range []func(int) bool{func(id int) bool { return TryAcquireSiteOpLock(id, "test") }, TryAcquireCompanionDeployLock, func(id int) bool { return TryAcquireSiteFileOpLock(id, "test") }, tryAcquireMaintenanceOp} {
		if !acquire(700001) {
			t.Fatal("operation admission failed")
		}
		if _, err := panelOperations.beginUpdate(); !errors.Is(err, ErrPanelOperationsBusy) {
			t.Fatalf("site writer allowed update: %v", err)
		}
		ReleaseSiteOpLock(700001)
		release, err := panelOperations.beginUpdate()
		if err != nil {
			t.Fatal(err)
		}
		if acquire(700001) {
			ReleaseSiteOpLock(700001)
			t.Fatal("writer entered restart barrier")
		}
		release()
	}
}

func TestQueueShutdownReturnsInheritedSlotAndKeepsRegularBackup(t *testing.T) {
	oldLifecycle, oldDB := panelOperations, database.DB
	panelOperations, database.DB = &panelOperationLifecycle{}, nil
	defer func() { ReleaseSiteOpLock(700002); panelOperations, database.DB = oldLifecycle, oldDB }()
	if !TryAcquireSiteOpLock(700002, "update_restore") {
		t.Fatal("could not acquire inherited restore slot")
	}
	backup := filepath.Join(t.TempDir(), "selected.sql")
	if err := os.WriteFile(backup, []byte("keep original backup"), 0600); err != nil {
		t.Fatal(err)
	}
	q := &TaskQueue{queue: make(chan *Task, 1), tasks: make(map[string]*Task), lifecycle: panelOperations}
	task, err := q.EnqueueContext(context.Background(), TaskRestoreBackup, &RestoreBackupPayload{Site: &models.Website{ID: 700002}, FilePath: backup, RemoveFileAfter: true, UpdateBackupPath: backup})
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := <-task.ResultCh; result.Success {
		t.Fatal("canceled restore reported success")
	}
	if SiteOpLocked(700002) {
		t.Fatal("canceled update restore retained inherited slot")
	}
	if data, err := os.ReadFile(backup); err != nil || string(data) != "keep original backup" {
		t.Fatalf("cancellation removed regular backup: %s / %v", data, err)
	}
	release, err := panelOperations.beginUpdate()
	if err != nil {
		t.Fatalf("canceled task retained lifecycle lease: %v", err)
	}
	release()
}
