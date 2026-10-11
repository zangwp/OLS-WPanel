package handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var acquireFileMutationKernel = executor.AcquireFileBackupOperationLock

type fileMutationTarget struct {
	ID   int
	Root string
}

type fileMutationLease struct {
	kernel io.Closer
	sites  []int
	once   sync.Once
	err    error
}

func (lease *fileMutationLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.once.Do(func() {
		for i := len(lease.sites) - 1; i >= 0; i-- {
			executor.ReleaseSiteOpLock(lease.sites[i])
		}
		lease.err = lease.kernel.Close()
	})
	return lease.err
}

// Use the same kernel -> sorted site slot order as the whole-site coordinator.
// Never hold this lease while enqueueing/waiting for the executor worker: a
// backup ahead of that queued task may itself be waiting for this kernel lock.
// The file-specific site slot preserves authorized temporary maintenance edits.
func acquireFileMutation(ctx context.Context, targets ...fileMutationTarget) (io.Closer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	kernel, err := acquireFileMutationKernel(bounded)
	if err != nil {
		return nil, errors.New("备份或文件操作正在进行，暂不能写入网站文件")
	}
	lease := &fileMutationLease{kernel: kernel}
	keep := false
	defer func() {
		if !keep {
			_ = lease.Close()
		}
	}()
	ids := make([]int, 0, len(targets))
	for _, target := range targets {
		ids = append(ids, target.ID)
	}
	sort.Ints(ids)
	previous := -1
	for _, id := range ids {
		if id < 0 {
			return nil, errors.New("文件操作网站无效")
		}
		if id == previous {
			continue
		}
		previous = id
		if id == 0 {
			continue
		}
		if !executor.TryAcquireSiteFileOpLock(id, "file_mutation") {
			return nil, errors.New("网站正在执行其它维护操作，请稍后重试")
		}
		lease.sites = append(lease.sites, id)
	}
	if err = bounded.Err(); err != nil {
		return nil, err
	}
	db := database.GetDB()
	if db == nil {
		return nil, errors.New("无法核对网站维护状态，未写入文件")
	}
	for _, target := range targets {
		id := target.ID
		if id == 0 {
			var count int
			if err = db.QueryRowContext(bounded, "SELECT COUNT(*) FROM websites WHERE status='backup_maintenance'").Scan(&count); err != nil {
				return nil, errors.New("无法核对备份维护状态，未写入备份目录")
			}
			if count != 0 {
				return nil, errors.New("网站仍有整站备份维护现场，暂不能修改备份目录")
			}
			continue
		}
		var status, root string
		if err = db.QueryRowContext(bounded, "SELECT status,web_root FROM websites WHERE id=?", id).Scan(&status, &root); err != nil {
			return nil, errors.New("无法核对网站维护状态，未写入文件")
		}
		if status == "backup_maintenance" {
			return nil, errors.New("网站仍在整站备份维护中，暂不能写入文件")
		}
		if target.Root == "" || filepath.Clean(root) != filepath.Clean(target.Root) {
			return nil, errors.New("网站目录绑定已变化，未写入文件")
		}
	}
	keep = true
	return lease, nil
}

func beginFileMutation(c *gin.Context, targets ...fileMutationTarget) (io.Closer, bool) {
	lease, err := acquireFileMutation(c.Request.Context(), targets...)
	if err != nil {
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusConflict, models.ErrorResponse(err.Error()))
		return nil, false
	}
	return lease, true
}

// Ownership transfers from the admitted request to the entire background job.
// The job supplies its own bounded context; request completion must not release
// its lease or cancel an import while it is still writing the destination.
func startFileMutationWorker(lease io.Closer, work func()) {
	go func() {
		defer lease.Close()
		work()
	}()
}
