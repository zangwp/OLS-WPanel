package handlers

import (
	"context"
	"log"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var (
	enqueueSiteBackupTask        = enqueueTask
	listSiteBackupSets           = executor.ListSiteBackups
	validateSiteBackupRestore    = executor.ValidateSiteBackupRestore
	siteBackupArtifact           = executor.GetSiteBackupArtifact
	prepareSiteBackupExport      = executor.PrepareSiteBackupExport
	deleteSiteBackupSet          = executor.DeleteSiteBackup
	recoverSiteBackupMaintenance = executor.RecoverSiteBackupMaintenance
	findActiveBackupOperation    = func(siteID int) (*executor.Task, bool) {
		if executor.GlobalQueue == nil {
			return nil, false
		}
		return executor.GlobalQueue.FindActiveTask(siteID, executor.TaskCreateSiteBackup,
			executor.TaskRestoreSiteBackup, executor.TaskCreateFileBackup,
			executor.TaskRestoreBackup, executor.TaskRestoreFileBackup, executor.TaskCreateBackup)
	}
)

func backupOperationSite(c *gin.Context, requireWholeSite bool) (*models.Website, bool) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("无效的网站编号"))
		return nil, false
	}
	site := getWebsiteByID(id)
	if site == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("网站不存在"))
		return nil, false
	}
	if requireWholeSite && (site.Status != models.StatusActive || site.SiteType != "wordpress" || site.DocumentRootSubdir != "") {
		c.JSON(http.StatusConflict, models.ErrorResponse("整站备份和恢复仅支持运行中的根目录 WordPress 网站；请先处理当前维护或运行状态"))
		return nil, false
	}
	return site, true
}

func siteBackupPointID(c *gin.Context) (string, bool) {
	id := c.Param("bid")
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id || parsed == uuid.Nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("无效的整站备份编号"))
		return "", false
	}
	return id, true
}

func (h *BackupHandler) CreateSiteBackup(c *gin.Context) {
	site, ok := backupOperationSite(c, true)
	if !ok || rejectIfAIDevelopmentAccessActive(c, site.ID) {
		return
	}
	var confirmation struct {
		Maintenance            bool `json:"confirm_maintenance"`
		ExternalWritersStopped bool `json:"external_writers_stopped"`
	}
	if err := c.ShouldBindJSON(&confirmation); err != nil || !confirmation.Maintenance || !confirmation.ExternalWritersStopped {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请确认短暂网站维护，并先停止面板外的部署、脚本和数据库写入"))
		return
	}
	task, queued := enqueueSiteBackupTask(c, executor.TaskCreateSiteBackup, &executor.SiteBackupPayload{Site: site, ConfirmExternalWritersStopped: true})
	if !queued {
		return
	}
	writeBackupOperationAdmission(c, task, "site_backup")
}

func (h *BackupHandler) RestoreSiteBackup(c *gin.Context) {
	site, ok := backupOperationSite(c, true)
	if !ok || rejectIfAIDevelopmentAccessActive(c, site.ID) {
		return
	}
	id, ok := siteBackupPointID(c)
	if !ok {
		return
	}
	var confirmation struct {
		Restore                bool `json:"confirm_restore"`
		ExternalWritersStopped bool `json:"external_writers_stopped"`
	}
	if err := c.ShouldBindJSON(&confirmation); err != nil || !confirmation.Restore || !confirmation.ExternalWritersStopped {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请确认覆盖网站文件和数据库，并先停止面板外的部署、脚本和数据库写入"))
		return
	}
	// Only a database-owned website and a canonical point ID reach the worker.
	// Component hashes and the current binding are checked again under its locks.
	if err := validateSiteBackupRestore(c.Request.Context(), site, id); err != nil {
		c.JSON(http.StatusConflict, models.ErrorResponse(err.Error()))
		return
	}
	task, queued := enqueueSiteBackupTask(c, executor.TaskRestoreSiteBackup, &executor.RestoreSiteBackupPayload{Site: site, BackupID: id, ConfirmExternalWritersStopped: true})
	if !queued {
		return
	}
	writeBackupOperationAdmission(c, task, "site_restore")
}

func (h *BackupHandler) CreateFileBackup(c *gin.Context) {
	site, ok := backupOperationSite(c, false)
	if !ok || rejectIfAIDevelopmentAccessActive(c, site.ID) {
		return
	}
	if site.Status != models.StatusActive {
		c.JSON(http.StatusConflict, models.ErrorResponse("请在网站结束维护并恢复运行后创建文件备份"))
		return
	}
	task, queued := enqueueSiteBackupTask(c, executor.TaskCreateFileBackup, &executor.CreateFileBackupPayload{Site: site})
	if !queued {
		return
	}
	writeBackupOperationAdmission(c, task, "file_backup")
}

func writeBackupOperationAdmission(c *gin.Context, task *executor.Task, kind string) {
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"async": true, "kind": kind, "task_id": task.ID, "status": task.Status,
		"message": "备份操作已加入队列",
	}))
}

func (h *BackupHandler) BackupOperationStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	site, ok := backupOperationSite(c, false)
	if !ok {
		return
	}
	if executor.GlobalQueue == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("任务队列暂不可用，无法核对备份操作状态"))
		return
	}
	task, exists := lookupBackupRestoreTask(strings.TrimSpace(c.Param("task_id")))
	if !exists || task == nil || task.SiteID != site.ID || backupOperationKind(task.Type) == "" {
		c.JSON(http.StatusNotFound, models.ErrorResponse("该网站的备份操作任务不存在；请核对备份列表与网站维护状态，勿推断操作成功"))
		return
	}
	success := false
	message := "备份操作等待中"
	var resultData interface{}
	switch task.Status {
	case executor.TaskStatusWaiting:
	case executor.TaskStatusRunning:
		message = "备份操作执行中"
	case executor.TaskStatusSuccess, executor.TaskStatusFailed:
		if task.Result == nil || task.Result.Success != (task.Status == executor.TaskStatusSuccess) {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("备份操作结果尚未确认，请重新核对"))
			return
		}
		success, message, resultData = task.Result.Success, task.Result.Message, task.Result.Data
	default:
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("备份操作状态尚未确认，请重新核对"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"task_id": task.ID, "kind": backupOperationKind(task.Type), "status": task.Status,
		"success": success, "message": message, "data": resultData,
	}))
}

func backupOperationKind(kind executor.TaskType) string {
	switch kind {
	case executor.TaskCreateSiteBackup:
		return "site_backup"
	case executor.TaskRestoreSiteBackup:
		return "site_restore"
	case executor.TaskCreateFileBackup:
		return "file_backup"
	case executor.TaskRestoreBackup:
		return "db"
	case executor.TaskRestoreFileBackup:
		return "file"
	case executor.TaskCreateBackup:
		return "db_backup"
	default:
		return ""
	}
}

func (h *BackupHandler) ActiveBackupOperation(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	site, ok := backupOperationSite(c, false)
	if !ok {
		return
	}
	if executor.GlobalQueue == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("任务队列暂不可用，无法核对当前备份操作"))
		return
	}
	task, active := findActiveBackupOperation(site.ID)
	if !active || task == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"active": false}))
		return
	}
	if task.SiteID != site.ID || backupOperationKind(task.Type) == "" || (task.Status != executor.TaskStatusWaiting && task.Status != executor.TaskStatusRunning) {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("无法核对当前备份操作"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"active": true, "kind": backupOperationKind(task.Type), "task_id": task.ID,
		"status": task.Status, "message": "网站已有备份操作正在排队或运行",
	}))
}

func (h *BackupHandler) DeleteSiteBackup(c *gin.Context) {
	site, ok := backupOperationSite(c, false)
	if !ok {
		return
	}
	id, ok := siteBackupPointID(c)
	if !ok {
		return
	}
	if _, active := findActiveBackupOperation(site.ID); active {
		c.JSON(http.StatusConflict, models.ErrorResponse("网站已有备份或恢复任务，请完成后再删除整站备份"))
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	if err := deleteSiteBackupSet(ctx, site, id); err != nil {
		c.JSON(http.StatusConflict, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": "整站备份的文件和数据库已一起删除"}))
}

// Recover access only when the durable operation journal proves both components
// are safe. This is separate from a restore result and never marks it successful.
func (h *BackupHandler) RecoverSiteBackupMaintenance(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	site, ok := backupOperationSite(c, false)
	if !ok {
		return
	}
	if executor.GlobalQueue == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("任务队列暂不可用，无法核对维护恢复状态"))
		return
	}
	var confirmation struct {
		Recover bool `json:"confirm_recovery"`
	}
	if err := c.ShouldBindJSON(&confirmation); err != nil || !confirmation.Recover {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请确认核对维护日志并恢复网站访问"))
		return
	}
	if _, active := findActiveBackupOperation(site.ID); active {
		c.JSON(http.StatusConflict, models.ErrorResponse("网站仍有备份或恢复任务，请等待完成后再核对维护"))
		return
	}
	if site.Status != models.StatusBackupMaintenance {
		c.JSON(http.StatusConflict, models.ErrorResponse("网站不处于整站备份维护状态，请刷新当前状态"))
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()
	if err := recoverSiteBackupMaintenance(ctx, site); err != nil {
		c.JSON(http.StatusConflict, models.ErrorResponse(err.Error()))
		return
	}
	current := getWebsiteByID(site.ID)
	if current == nil || current.Status != models.StatusActive {
		c.JSON(http.StatusConflict, models.ErrorResponse("网站访问状态尚未确认，请重新核对维护记录"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"maintenance_recovered": true,
		"message":               "已按维护日志恢复网站访问；请检查网站，原备份或恢复任务的结果保持不变",
	}))
}

func (h *BackupHandler) DownloadSiteBackup(c *gin.Context) {
	site, ok := backupOperationSite(c, false)
	if !ok {
		return
	}
	id, ok := siteBackupPointID(c)
	if !ok {
		return
	}
	component := c.Query("component")
	if component == "bundle" {
		bundle, err := prepareSiteBackupExport(c.Request.Context(), site, id)
		if err != nil {
			c.JSON(http.StatusConflict, models.ErrorResponse(err.Error()))
			return
		}
		defer bundle.Close()
		c.Header("Cache-Control", "private, no-store")
		c.Header("Content-Type", "application/x-tar")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": bundle.Filename()}))
		c.Header("Content-Length", strconv.FormatInt(bundle.Size(), 10))
		if err := bundle.Write(c.Request.Context(), c.Writer); err != nil {
			// A fixed length makes a truncated stream an incomplete download;
			// never append JSON or a success footer to a partial archive.
			log.Printf("整站备份导出未完成 site=%d backup=%s: %v", site.ID, id, err)
			c.Abort()
		}
		return
	}
	if component != "files" && component != "database" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请选择整站备份中的文件或数据库组件"))
		return
	}
	path, name, err := siteBackupArtifact(c.Request.Context(), site, id, component)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse(err.Error()))
		return
	}
	file, err := os.Open(path)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("整站备份组件当前不可读取"))
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		c.JSON(http.StatusConflict, models.ErrorResponse("整站备份组件当前不可用"))
		return
	}
	c.Header("Cache-Control", "private, no-store")
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	http.ServeContent(c.Writer, c.Request, name, info.ModTime(), file)
}
