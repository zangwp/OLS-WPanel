package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

const testSiteBackupID = "22222222-2222-4222-8222-222222222222"

func setupSiteBackupHandlerFixture(t *testing.T) *gin.Engine {
	t.Helper()
	setupFileBackupDeleteFixture(t)
	oldQueue, oldEnqueue, oldLookup, oldActive := executor.GlobalQueue, enqueueSiteBackupTask, lookupBackupRestoreTask, findActiveBackupOperation
	oldValidate, oldArtifact, oldDelete := validateSiteBackupRestore, siteBackupArtifact, deleteSiteBackupSet
	oldRecover := recoverSiteBackupMaintenance
	executor.GlobalQueue = &executor.TaskQueue{}
	t.Cleanup(func() {
		executor.GlobalQueue, enqueueSiteBackupTask, lookupBackupRestoreTask, findActiveBackupOperation = oldQueue, oldEnqueue, oldLookup, oldActive
		validateSiteBackupRestore, siteBackupArtifact, deleteSiteBackupSet = oldValidate, oldArtifact, oldDelete
		recoverSiteBackupMaintenance = oldRecover
	})
	r := gin.New()
	h := &BackupHandler{}
	r.POST("/api/websites/:id/site-backups", h.CreateSiteBackup)
	r.POST("/api/websites/:id/site-backups/recover-maintenance", h.RecoverSiteBackupMaintenance)
	r.POST("/api/websites/:id/site-backups/:bid/restore", h.RestoreSiteBackup)
	r.DELETE("/api/websites/:id/site-backups/:bid", h.DeleteSiteBackup)
	r.GET("/api/websites/:id/site-backups/:bid/download", h.DownloadSiteBackup)
	r.POST("/api/websites/:id/file-backups", h.CreateFileBackup)
	r.GET("/api/websites/:id/backups/tasks/:task_id", h.BackupOperationStatus)
	r.GET("/api/websites/:id/backups/active-operation", h.ActiveBackupOperation)
	return r
}

func TestRecoverSiteBackupMaintenanceRequiresConfirmedIdleMaintenance(t *testing.T) {
	for _, tc := range []struct {
		name, status, body       string
		queueUnavailable, active bool
		code                     int
	}{
		{"missing confirmation", "backup_maintenance", `{}`, false, false, http.StatusBadRequest},
		{"active task", "backup_maintenance", `{"confirm_recovery":true}`, false, true, http.StatusConflict},
		{"active website", "active", `{"confirm_recovery":true}`, false, false, http.StatusConflict},
		{"paused website", "paused", `{"confirm_recovery":true}`, false, false, http.StatusConflict},
		{"unknown queue", "backup_maintenance", `{"confirm_recovery":true}`, true, false, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := setupSiteBackupHandlerFixture(t)
			if _, err := database.GetDB().Exec("UPDATE websites SET status=? WHERE id=1", tc.status); err != nil {
				t.Fatal(err)
			}
			if tc.queueUnavailable {
				executor.GlobalQueue = nil
			}
			findActiveBackupOperation = func(int) (*executor.Task, bool) { return &executor.Task{}, tc.active }
			recoverSiteBackupMaintenance = func(context.Context, *models.Website) error { t.Fatal("unsafe recovery attempted"); return nil }
			rec := siteBackupRequest(r, http.MethodPost, "/api/websites/1/site-backups/recover-maintenance", tc.body)
			if rec.Code != tc.code {
				t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("recovery result may be cached")
			}
		})
	}
}

func TestRecoverSiteBackupMaintenanceRequiresJournalAndFreshActiveStatus(t *testing.T) {
	for _, outcome := range []string{"unsafe journal", "unconfirmed status", "recovered"} {
		t.Run(outcome, func(t *testing.T) {
			r := setupSiteBackupHandlerFixture(t)
			if _, err := database.GetDB().Exec("UPDATE websites SET status='backup_maintenance' WHERE id=1"); err != nil {
				t.Fatal(err)
			}
			findActiveBackupOperation = func(int) (*executor.Task, bool) { return nil, false }
			recoverSiteBackupMaintenance = func(ctx context.Context, site *models.Website) error {
				if site.ID != 1 || site.Status != models.StatusBackupMaintenance {
					t.Fatal("wrong server binding")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded recovery")
				}
				if outcome == "unsafe journal" {
					return errors.New("partial rollback cannot safely reopen access")
				}
				if outcome == "recovered" {
					_, err := database.GetDB().Exec("UPDATE websites SET status='active' WHERE id=1")
					return err
				}
				return nil
			}
			rec := siteBackupRequest(r, http.MethodPost, "/api/websites/1/site-backups/recover-maintenance", `{"confirm_recovery":true,"site_id":2,"path":"/etc"}`)
			if outcome == "recovered" {
				if rec.Code != http.StatusOK || decodeFileRestoreData(t, rec)["maintenance_recovered"] != true {
					t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
				}
			} else if rec.Code != http.StatusConflict {
				t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func siteBackupRequest(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	r.ServeHTTP(rec, req)
	return rec
}

func TestCreateSiteBackupRequiresConfirmedManagedSite(t *testing.T) {
	for _, tc := range []struct {
		name, mutation, body string
		code                 int
	}{
		{"missing confirmation", "", `{}`, http.StatusBadRequest},
		{"external writes unconfirmed", "", `{"confirm_maintenance":true}`, http.StatusBadRequest},
		{"paused", "UPDATE websites SET status='paused' WHERE id=1", `{"confirm_maintenance":true,"external_writers_stopped":true}`, http.StatusConflict},
		{"maintenance", "UPDATE websites SET status='backup_maintenance' WHERE id=1", `{"confirm_maintenance":true,"external_writers_stopped":true}`, http.StatusConflict},
		{"static", "UPDATE websites SET site_type='static' WHERE id=1", `{"confirm_maintenance":true,"external_writers_stopped":true}`, http.StatusConflict},
		{"subdirectory", "UPDATE websites SET document_root_subdir='public' WHERE id=1", `{"confirm_maintenance":true,"external_writers_stopped":true}`, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := setupSiteBackupHandlerFixture(t)
			if tc.mutation != "" {
				if _, err := database.GetDB().Exec(tc.mutation); err != nil {
					t.Fatal(err)
				}
			}
			enqueueSiteBackupTask = func(*gin.Context, executor.TaskType, interface{}) (*executor.Task, bool) {
				t.Fatal("invalid backup was enqueued")
				return nil, false
			}
			rec := siteBackupRequest(r, http.MethodPost, "/api/websites/1/site-backups", tc.body)
			if rec.Code != tc.code {
				t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestSiteBackupAdmissionUsesServerOwnedBinding(t *testing.T) {
	r := setupSiteBackupHandlerFixture(t)
	enqueueSiteBackupTask = func(_ *gin.Context, kind executor.TaskType, payload interface{}) (*executor.Task, bool) {
		p, ok := payload.(*executor.SiteBackupPayload)
		if !ok || kind != executor.TaskCreateSiteBackup || p.Site == nil || p.Site.ID != 1 || !p.ConfirmExternalWritersStopped {
			t.Fatalf("wrong task payload: %s %+v", kind, payload)
		}
		if p.Site.WebRoot == "/etc" || p.Site.DBName == "mysql" {
			t.Fatal("trusted client binding")
		}
		return &executor.Task{ID: "owned", SiteID: 1, Type: kind, Status: executor.TaskStatusWaiting}, true
	}
	rec := siteBackupRequest(r, http.MethodPost, "/api/websites/1/site-backups", `{"confirm_maintenance":true,"external_writers_stopped":true,"site_id":8,"web_root":"/etc","db_name":"mysql"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	data := decodeFileRestoreData(t, rec)
	if data["kind"] != "site_backup" || data["task_id"] != "owned" || data["async"] != true {
		t.Fatalf("incorrect response: %+v", data)
	}
}

func TestRestoreSiteBackupRequiresOwnedCompletePointAndConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, id, body string
		unavailable    bool
		code           int
	}{
		{"malformed point", "not-a-point", `{"confirm_restore":true,"external_writers_stopped":true}`, false, http.StatusBadRequest},
		{"missing confirmation", testSiteBackupID, `{}`, false, http.StatusBadRequest},
		{"incomplete foreign or corrupt point", testSiteBackupID, `{"confirm_restore":true,"external_writers_stopped":true}`, true, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := setupSiteBackupHandlerFixture(t)
			validateSiteBackupRestore = func(_ context.Context, site *models.Website, id string) error {
				if !tc.unavailable {
					t.Fatal("unexpected restore preflight")
				}
				if site.ID != 1 || id != testSiteBackupID {
					t.Fatal("wrong preflight binding")
				}
				return errors.New("backup is not an owned complete point")
			}
			enqueueSiteBackupTask = func(*gin.Context, executor.TaskType, interface{}) (*executor.Task, bool) {
				t.Fatal("invalid restore enqueued")
				return nil, false
			}
			rec := siteBackupRequest(r, http.MethodPost, "/api/websites/1/site-backups/"+tc.id+"/restore", tc.body)
			if rec.Code != tc.code {
				t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	r := setupSiteBackupHandlerFixture(t)
	validateSiteBackupRestore = func(_ context.Context, site *models.Website, id string) error { return nil }
	enqueueSiteBackupTask = func(_ *gin.Context, kind executor.TaskType, payload interface{}) (*executor.Task, bool) {
		p, ok := payload.(*executor.RestoreSiteBackupPayload)
		if !ok || p.Site.ID != 1 || p.BackupID != testSiteBackupID || !p.ConfirmExternalWritersStopped || kind != executor.TaskRestoreSiteBackup {
			t.Fatalf("wrong restore: %+v", payload)
		}
		return &executor.Task{ID: "restore-point", Status: executor.TaskStatusWaiting}, true
	}
	rec := siteBackupRequest(r, http.MethodPost, "/api/websites/1/site-backups/"+testSiteBackupID+"/restore", `{"confirm_restore":true,"external_writers_stopped":true,"path":"/etc"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBackupOperationStatusRejectsForeignOrUnconfirmedResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		task *executor.Task
		code int
	}{
		{"foreign", &executor.Task{ID: "op", SiteID: 2, Type: executor.TaskCreateSiteBackup, Status: executor.TaskStatusRunning}, http.StatusNotFound},
		{"wrong operation", &executor.Task{ID: "op", SiteID: 1, Type: executor.TaskPauseSite, Status: executor.TaskStatusRunning}, http.StatusNotFound},
		{"missing result", &executor.Task{ID: "op", SiteID: 1, Type: executor.TaskRestoreSiteBackup, Status: executor.TaskStatusSuccess}, http.StatusInternalServerError},
		{"inconsistent result", &executor.Task{ID: "op", SiteID: 1, Type: executor.TaskRestoreSiteBackup, Status: executor.TaskStatusSuccess, Result: &executor.TaskResult{Success: false}}, http.StatusInternalServerError},
		{"unknown state", &executor.Task{ID: "op", SiteID: 1, Type: executor.TaskCreateFileBackup, Status: "unknown"}, http.StatusInternalServerError},
		{"success", &executor.Task{ID: "op", SiteID: 1, Type: executor.TaskCreateSiteBackup, Status: executor.TaskStatusSuccess, Result: &executor.TaskResult{Success: true, Message: "complete"}}, http.StatusOK},
		{"failure", &executor.Task{ID: "op", SiteID: 1, Type: executor.TaskRestoreSiteBackup, Status: executor.TaskStatusFailed, Result: &executor.TaskResult{Success: false, Message: "kept in maintenance"}}, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := setupSiteBackupHandlerFixture(t)
			lookupBackupRestoreTask = func(string) (*executor.Task, bool) { return tc.task, true }
			rec := siteBackupRequest(r, http.MethodGet, "/api/websites/1/backups/tasks/op", "")
			if rec.Code != tc.code {
				t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("task result may be cached")
			}
			if tc.code == http.StatusOK {
				data := decodeFileRestoreData(t, rec)
				if data["success"] != tc.task.Result.Success || data["kind"] != backupOperationKind(tc.task.Type) {
					t.Fatalf("incorrect result: %+v", data)
				}
			}
		})
	}
}

func TestActiveBackupOperationChecksWebsiteOwnership(t *testing.T) {
	r := setupSiteBackupHandlerFixture(t)
	findActiveBackupOperation = func(int) (*executor.Task, bool) {
		return &executor.Task{ID: "other", SiteID: 2, Type: executor.TaskCreateSiteBackup, Status: executor.TaskStatusRunning}, true
	}
	rec := siteBackupRequest(r, http.MethodGet, "/api/websites/1/backups/active-operation", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("foreign active result=%s", rec.Body.String())
	}
	findActiveBackupOperation = func(int) (*executor.Task, bool) {
		return &executor.Task{ID: "own", SiteID: 1, Type: executor.TaskRestoreFileBackup, Status: executor.TaskStatusWaiting}, true
	}
	rec = siteBackupRequest(r, http.MethodGet, "/api/websites/1/backups/active-operation", "")
	if rec.Code != http.StatusOK || decodeFileRestoreData(t, rec)["kind"] != "file" {
		t.Fatalf("old restore not represented correctly: %s", rec.Body.String())
	}
}

func TestSiteBackupDeleteBusyAndDownloadComponentAreRejected(t *testing.T) {
	r := setupSiteBackupHandlerFixture(t)
	findActiveBackupOperation = func(int) (*executor.Task, bool) { return &executor.Task{ID: "active"}, true }
	deleteSiteBackupSet = func(context.Context, *models.Website, string) error {
		t.Fatal("deleted during active operation")
		return nil
	}
	rec := siteBackupRequest(r, http.MethodDelete, "/api/websites/1/site-backups/"+testSiteBackupID, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("busy delete=%s", rec.Body.String())
	}
	siteBackupArtifact = func(context.Context, *models.Website, string, string) (string, string, error) {
		t.Fatal("invalid component reached storage")
		return "", "", nil
	}
	rec = siteBackupRequest(r, http.MethodGet, "/api/websites/1/site-backups/"+testSiteBackupID+"/download?component=../../etc/passwd", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid download=%s", rec.Body.String())
	}
}
