package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var enqueueFileBackupRestore = enqueueTask
var lookupBackupRestoreTask = func(taskID string) (*executor.Task, bool) {
	if executor.GlobalQueue == nil {
		return nil, false
	}
	return executor.GlobalQueue.GetTask(taskID)
}
var findActiveBackupRestore = func(siteID int) (*executor.Task, bool) {
	if executor.GlobalQueue == nil {
		return nil, false
	}
	return executor.GlobalQueue.FindActiveTask(siteID, executor.TaskRestoreBackup, executor.TaskRestoreFileBackup)
}

func (h *BackupHandler) RestoreFileBackup(c *gin.Context) {
	id, idErr := strconv.Atoi(c.Param("id"))
	bid, bidErr := strconv.Atoi(c.Param("bid"))
	if idErr != nil || bidErr != nil || id <= 0 || bid <= 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("无效的网站或备份编号"))
		return
	}
	site := getWebsiteByID(id)
	if site == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("网站不存在"))
		return
	}
	if rejectIfAIDevelopmentAccessActive(c, id) {
		return
	}

	var filename, mode string
	var recordedSize int64
	err := database.GetDB().QueryRowContext(c.Request.Context(),
		"SELECT filename, mode, file_size FROM file_backups WHERE id = ? AND site_id = ?", bid, id).Scan(&filename, &mode, &recordedSize)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, models.ErrorResponse("文件备份记录不存在"))
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("查询文件备份失败"))
		return
	}
	if mode != "full" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("该备份仅包含媒体增量，缺少可核验的完整恢复链，不能直接恢复整个网站；请使用本地全量文件备份"))
		return
	}
	if filepath.Base(filename) != filename || strings.ContainsAny(filename, `/\`) ||
		!strings.HasPrefix(filename, "file_full_") || !strings.HasSuffix(filename, ".tar.gz") {
		c.JSON(http.StatusForbidden, models.ErrorResponse("文件备份名称不合法"))
		return
	}
	filePath, ok := siteFileBackupPath(site, filename)
	if !ok {
		c.JSON(http.StatusForbidden, models.ErrorResponse("备份路径越权"))
		return
	}
	info, err := os.Lstat(filePath)
	if os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, models.ErrorResponse("本地全量备份文件不存在；若仅保存在远端，须先将完整全量包取回本地，当前不支持直接远端恢复"))
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("无法读取本地文件备份"))
		return
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || recordedSize <= 0 || info.Size() != recordedSize {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("本地全量备份文件不可用或大小不匹配，恢复未执行"))
		return
	}
	// The worker re-reads the site/record and validates the archive under its
	// operation locks. Never accept a client-provided filesystem path.
	task, queued := enqueueFileBackupRestore(c, executor.TaskRestoreFileBackup, &executor.RestoreFileBackupPayload{Site: site, BackupID: bid})
	if !queued {
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"async": true, "task_id": task.ID, "status": task.Status,
		"message": "文件恢复任务已加入队列；仅恢复网站文件，不恢复数据库",
	}))
}

func (h *BackupHandler) FileRestoreStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("无效的网站编号"))
		return
	}
	site := getWebsiteByID(id)
	if site == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("网站不存在"))
		return
	}
	if executor.GlobalQueue == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("任务队列暂不可用，无法核对文件恢复状态"))
		return
	}
	taskID := strings.TrimSpace(c.Param("task_id"))
	task, ok := lookupBackupRestoreTask(taskID)
	if !ok || task == nil || task.Type != executor.TaskRestoreFileBackup || task.SiteID != site.ID {
		c.JSON(http.StatusNotFound, models.ErrorResponse("文件恢复任务不存在"))
		return
	}
	message := "文件恢复等待中"
	success := false
	switch task.Status {
	case executor.TaskStatusWaiting:
	case executor.TaskStatusRunning:
		message = "文件恢复中"
	case executor.TaskStatusSuccess, executor.TaskStatusFailed:
		if task.Result == nil || task.Result.Success != (task.Status == executor.TaskStatusSuccess) {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("无法核对文件恢复结果，请稍后重试"))
			return
		}
		message = task.Result.Message
		success = task.Result.Success
	default:
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("无法核对文件恢复状态，请稍后重试"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"task_id": task.ID, "status": task.Status, "success": success, "message": message,
	}))
}

func (h *BackupHandler) ActiveRestore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("无效的网站编号"))
		return
	}
	if getWebsiteByID(id) == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("网站不存在"))
		return
	}
	if executor.GlobalQueue == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("任务队列暂不可用，无法核对恢复状态"))
		return
	}
	task, active := findActiveBackupRestore(id)
	if !active || task == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"active": false}))
		return
	}
	if task.SiteID != id || (task.Type != executor.TaskRestoreBackup && task.Type != executor.TaskRestoreFileBackup) ||
		(task.Status != executor.TaskStatusWaiting && task.Status != executor.TaskStatusRunning) {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("无法核对当前恢复任务"))
		return
	}
	kind, message := "db", "数据库恢复等待中"
	if task.Type == executor.TaskRestoreFileBackup {
		kind, message = "file", "文件恢复等待中"
	}
	if task.Status == executor.TaskStatusRunning {
		if kind == "file" {
			message = "文件恢复中"
		} else {
			message = "数据库恢复中"
		}
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"active": true, "kind": kind, "task_id": task.ID, "status": task.Status, "message": message,
	}))
}
