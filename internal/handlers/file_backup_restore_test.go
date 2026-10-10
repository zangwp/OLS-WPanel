package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
)

func setupFileBackupRestoreFixture(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	_, dir := setupFileBackupDeleteFixture(t)
	oldEnqueue, oldLookup, oldActive := enqueueFileBackupRestore, lookupBackupRestoreTask, findActiveBackupRestore
	oldQueue := executor.GlobalQueue
	executor.GlobalQueue = &executor.TaskQueue{}
	t.Cleanup(func() {
		enqueueFileBackupRestore, lookupBackupRestoreTask, findActiveBackupRestore = oldEnqueue, oldLookup, oldActive
		executor.GlobalQueue = oldQueue
	})
	router := gin.New()
	handler := &BackupHandler{}
	router.POST("/api/websites/:id/file-backups/:bid/restore", handler.RestoreFileBackup)
	router.GET("/api/websites/:id/file-backups/restore-tasks/:task_id", handler.FileRestoreStatus)
	router.GET("/api/websites/:id/backups/restore-tasks/:task_id", handler.RestoreStatus)
	router.GET("/api/websites/:id/backups/active-restore", handler.ActiveRestore)
	return router, dir
}

func decodeFileRestoreData(t *testing.T, recorder *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var response struct {
		Success bool                   `json:"success"`
		Data    map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || !response.Success || response.Data == nil {
		t.Fatalf("invalid restore response: err=%v body=%s", err, recorder.Body.String())
	}
	return response.Data
}

func TestRestoreFileBackupQueuesOnlyOwnedFullBackupID(t *testing.T) {
	router, _ := setupFileBackupRestoreFixture(t)
	enqueueFileBackupRestore = func(_ *gin.Context, kind executor.TaskType, payload interface{}) (*executor.Task, bool) {
		p, ok := payload.(*executor.RestoreFileBackupPayload)
		if kind != executor.TaskRestoreFileBackup || !ok || p.Site == nil || p.Site.ID != 1 || p.BackupID != 2 {
			t.Fatalf("wrong restore ownership or payload: kind=%s payload=%+v", kind, payload)
		}
		return &executor.Task{ID: "file-restore", Type: kind, SiteID: 1, Status: executor.TaskStatusWaiting}, true
	}
	rec := httptest.NewRecorder()
	// A forged filesystem path in the request body cannot influence the task.
	req := httptest.NewRequest(http.MethodPost, "/api/websites/1/file-backups/2/restore", strings.NewReader(`{"file_path":"/etc/passwd","site_id":99}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("restore admission status=%d body=%s", rec.Code, rec.Body.String())
	}
	data := decodeFileRestoreData(t, rec)
	if data["async"] != true || data["task_id"] != "file-restore" || data["status"] != "waiting" {
		t.Fatalf("incorrect asynchronous response: %+v", data)
	}
}

func TestRestoreFileBackupRejectsUnavailableOrUnsupportedSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
	}{
		{"legacy media increment", http.StatusBadRequest},
		{"remote only source", http.StatusNotFound},
		{"size mismatch", http.StatusBadRequest},
		{"directory source", http.StatusBadRequest},
		{"foreign site backup", http.StatusNotFound},
		{"path traversal filename", http.StatusForbidden},
		{"AI access active", http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router, dir := setupFileBackupRestoreFixture(t)
			enqueueFileBackupRestore = func(*gin.Context, executor.TaskType, interface{}) (*executor.Task, bool) {
				t.Fatal("unsupported source reached the restore queue")
				return nil, false
			}
			db := database.GetDB()
			path := filepath.Join(dir, "file_full_current.tar.gz")
			switch tc.name {
			case "legacy media increment":
				if _, err := db.Exec("UPDATE file_backups SET mode = 'incremental' WHERE id = 2"); err != nil {
					t.Fatal(err)
				}
			case "remote only source":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("UPDATE file_backups SET transport_status = 'remote_only' WHERE id = 2"); err != nil {
					t.Fatal(err)
				}
			case "size mismatch":
				if err := os.WriteFile(path, []byte("truncated"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory source":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "foreign site backup":
				if _, err := db.Exec(`INSERT INTO websites (id, name, domain, system_user, web_root, log_dir, db_name, db_user, lsphp_socket_path, ols_vhost_config_path)
					VALUES (2, 'other', 'other.example.com', 'u2', '/unused/other', '/unused/logs', 'db2', 'u2', '/p', '/n')`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("UPDATE file_backups SET site_id = 2 WHERE id = 2"); err != nil {
					t.Fatal(err)
				}
			case "path traversal filename":
				if _, err := db.Exec("UPDATE file_backups SET filename = '../file_full_current.tar.gz' WHERE id = 2"); err != nil {
					t.Fatal(err)
				}
			case "AI access active":
				if _, err := db.Exec("INSERT INTO website_ai_development_access (site_id, status, system_user, web_root, original_shell, original_home) VALUES (1, 'enabled', 'u1', '/unused', '/usr/sbin/nologin', '/unused')"); err != nil {
					t.Fatal(err)
				}
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/websites/1/file-backups/2/restore", nil))
			if rec.Code != tc.code {
				t.Fatalf("restore status=%d want=%d body=%s", rec.Code, tc.code, rec.Body.String())
			}
		})
	}
}

func TestRestoreFileBackupQueueUnavailableReportsAdmissionFailure(t *testing.T) {
	router, _ := setupFileBackupRestoreFixture(t)
	executor.GlobalQueue = nil
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/websites/1/file-backups/2/restore", nil))
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), `"async":true`) {
		t.Fatalf("unavailable queue was reported as an admitted restore: %d %s", rec.Code, rec.Body.String())
	}
}

func TestFileRestoreStatusChecksTaskOwnershipAndFinalOutcome(t *testing.T) {
	testBackupRestoreStatusForKind(t, executor.TaskRestoreFileBackup)
}

func TestDatabaseRestoreStatusChecksTaskOwnershipAndFinalOutcome(t *testing.T) {
	testBackupRestoreStatusForKind(t, executor.TaskRestoreBackup)
}

func testBackupRestoreStatusForKind(t *testing.T, kind executor.TaskType) {
	t.Helper()
	wrongKind := executor.TaskRestoreBackup
	collection := "file-backups"
	if kind == executor.TaskRestoreBackup {
		wrongKind = executor.TaskRestoreFileBackup
		collection = "backups"
	}
	for _, tc := range []struct {
		name    string
		task    *executor.Task
		code    int
		success bool
	}{
		{"pending", &executor.Task{Type: kind, SiteID: 1, Status: executor.TaskStatusWaiting}, http.StatusOK, false},
		{"running", &executor.Task{Type: kind, SiteID: 1, Status: executor.TaskStatusRunning}, http.StatusOK, false},
		{"success", &executor.Task{Type: kind, SiteID: 1, Status: executor.TaskStatusSuccess, Result: &executor.TaskResult{Success: true, Message: "restored"}}, http.StatusOK, true},
		{"failed", &executor.Task{Type: kind, SiteID: 1, Status: executor.TaskStatusFailed, Result: &executor.TaskResult{Message: "rollback completed"}}, http.StatusOK, false},
		{"wrong kind", &executor.Task{Type: wrongKind, SiteID: 1}, http.StatusNotFound, false},
		{"wrong site", &executor.Task{Type: kind, SiteID: 2}, http.StatusNotFound, false},
		{"missing final result", &executor.Task{Type: kind, SiteID: 1, Status: executor.TaskStatusSuccess}, http.StatusInternalServerError, false},
		{"success with failed result", &executor.Task{Type: kind, SiteID: 1, Status: executor.TaskStatusSuccess, Result: &executor.TaskResult{}}, http.StatusInternalServerError, false},
		{"failed with successful result", &executor.Task{Type: kind, SiteID: 1, Status: executor.TaskStatusFailed, Result: &executor.TaskResult{Success: true}}, http.StatusInternalServerError, false},
		{"unknown state", &executor.Task{Type: kind, SiteID: 1, Status: "unknown"}, http.StatusInternalServerError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := setupFileBackupRestoreFixture(t)
			tc.task.ID = "restore"
			lookupBackupRestoreTask = func(string) (*executor.Task, bool) { return tc.task, true }
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/websites/1/"+collection+"/restore-tasks/restore", nil))
			if rec.Code != tc.code || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("poll status=%d cache=%s body=%s", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
			}
			if rec.Code == http.StatusOK {
				data := decodeFileRestoreData(t, rec)
				if data["success"] != tc.success || data["status"] != string(tc.task.Status) {
					t.Fatalf("poll exposed incorrect outcome: %+v", data)
				}
			}
		})
	}
}

func TestBackupRestoreStatusUnavailableQueueFailsClosed(t *testing.T) {
	for _, collection := range []string{"backups", "file-backups"} {
		t.Run(collection, func(t *testing.T) {
			router, _ := setupFileBackupRestoreFixture(t)
			executor.GlobalQueue = nil
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/websites/1/"+collection+"/restore-tasks/restore", nil))
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("unavailable poll status=%d cache=%s body=%s", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
			}
		})
	}
}

func TestActiveRestoreRecoversBothKindsAfterPageReload(t *testing.T) {
	for _, kind := range []executor.TaskType{executor.TaskRestoreBackup, executor.TaskRestoreFileBackup} {
		t.Run(string(kind), func(t *testing.T) {
			router, _ := setupFileBackupRestoreFixture(t)
			findActiveBackupRestore = func(siteID int) (*executor.Task, bool) {
				if siteID != 1 {
					t.Fatal("lookup crossed website ownership")
				}
				return &executor.Task{ID: "active", Type: kind, SiteID: 1, Status: executor.TaskStatusRunning}, true
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/websites/1/backups/active-restore", nil))
			if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("active lookup status=%d body=%s", rec.Code, rec.Body.String())
			}
			data := decodeFileRestoreData(t, rec)
			wantKind := "db"
			if kind == executor.TaskRestoreFileBackup {
				wantKind = "file"
			}
			if data["active"] != true || data["kind"] != wantKind || data["task_id"] != "active" || data["status"] != "running" {
				t.Fatalf("invalid page-reload active receipt: %+v", data)
			}
		})
	}
}

func TestActiveRestoreDistinguishesIdleFromUnavailable(t *testing.T) {
	router, _ := setupFileBackupRestoreFixture(t)
	findActiveBackupRestore = func(int) (*executor.Task, bool) { return nil, false }
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/websites/1/backups/active-restore", nil))
	if rec.Code != http.StatusOK || decodeFileRestoreData(t, rec)["active"] != false {
		t.Fatalf("idle queue result=%d body=%s", rec.Code, rec.Body.String())
	}
	executor.GlobalQueue = nil
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/websites/1/backups/active-restore", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unavailable queue incorrectly reported idle: %d %s", rec.Code, rec.Body.String())
	}
}
