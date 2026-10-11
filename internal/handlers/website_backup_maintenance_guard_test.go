package handlers

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

func setupBackupMaintenanceGuardDB(t *testing.T) (string, string) {
	t.Helper()
	oldDB, oldConfig := database.DB, config.AppConfig
	root := t.TempDir()
	if err := database.Open(filepath.Join(root, "panel.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(); database.DB = oldDB; config.AppConfig = oldConfig })
	if err := database.RunMigrations(); err != nil {
		t.Fatal(err)
	}
	frozenRoot, activeRoot := filepath.Join(root, "frozen"), filepath.Join(root, "active")
	config.AppConfig = &config.Config{Panel: config.PanelConfig{DataDir: filepath.Join(root, "data"), BackupDir: filepath.Join(root, "backups")}}
	for _, path := range []string{frozenRoot, activeRoot, config.AppConfig.Panel.BackupDir} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for i, path := range []string{frozenRoot, activeRoot} {
		status := "active"
		if i == 0 {
			status = "backup_maintenance"
		}
		_, err := database.GetDB().Exec(`INSERT INTO websites(id,name,domain,aliases,status,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path,site_type,plugin_api_key)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, i+1, fmt.Sprintf("site%d", i+1), fmt.Sprintf("site%d.example", i+1), "", status, fmt.Sprintf("wp_site%d", i+1), path, path, fmt.Sprintf("db%d", i+1), fmt.Sprintf("user%d", i+1), path+".sock", path+".conf", "wordpress", strings.Repeat(fmt.Sprint(i+1), 40))
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := database.GetDB().Exec(`INSERT INTO cron_jobs(id,name,cron_expression,command,task_type,site_id,run_as_user) VALUES
		(1,'frozen','* * * * *','','wp_cron',1,''),
		(2,'active','* * * * *','','wp_cron',2,''),
		(3,'frozen-user','* * * * *','true','command',NULL,'wp_site1'),
		(4,'root','* * * * *','true','command',2,'root'),
		(5,'active-user','* * * * *','true','command',NULL,'wp_site2')`)
	if err != nil {
		t.Fatal(err)
	}
	return frozenRoot, activeRoot
}

func backupMaintenanceGuardRequest(t *testing.T, method, route, target, body string) (int, bool, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(WebsiteBackupMaintenanceGuard())
	reached := false
	readBody := ""
	router.Handle(method, "/private"+route, func(c *gin.Context) {
		reached = true
		if c.Request.Body != nil {
			data, _ := io.ReadAll(c.Request.Body)
			readBody = string(data)
		}
		c.Status(http.StatusNoContent)
	})
	req := httptest.NewRequest(method, "/private"+target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-OLS-WPanel-Key", strings.Repeat("1", 40))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent && reached {
		t.Fatalf("rejected request reached handler: %s", target)
	}
	return rec.Code, reached, readBody
}

func TestBackupMaintenanceGuardSiteAndSharedOperations(t *testing.T) {
	setupBackupMaintenanceGuardDB(t)
	for _, tc := range []struct {
		name, method, route, target string
		want                        int
	}{
		{"site update", "PUT", "/api/websites/:id/monitoring", "/api/websites/1/monitoring", 409},
		{"other site update", "PUT", "/api/websites/:id/monitoring", "/api/websites/2/monitoring", 204},
		{"resume", "PATCH", "/api/websites/:id/status", "/api/websites/1/status", 409},
		{"unlock", "PUT", "/api/websites/:id/maintenance", "/api/websites/1/maintenance", 409},
		{"delete website", "DELETE", "/api/websites/:id", "/api/websites/1", 409},
		{"rename domain", "PUT", "/api/websites/:id/domains", "/api/websites/1/domains", 409},
		{"ordinary DB restore", "POST", "/api/websites/:id/backups/:bid/restore", "/api/websites/1/backups/4/restore", 409},
		{"upload DB restore", "POST", "/api/websites/:id/backups/upload-restore", "/api/websites/1/backups/upload-restore", 409},
		{"file restore", "POST", "/api/websites/:id/file-backups/:bid/restore", "/api/websites/1/file-backups/4/restore", 409},
		{"whole site restore", "POST", "/api/websites/:id/site-backups/:bid/restore", "/api/websites/1/site-backups/4/restore", 409},
		{"explicit maintenance recovery", "POST", "/api/websites/:id/site-backups/recover-maintenance", "/api/websites/1/site-backups/recover-maintenance", 204},
		{"recovery only POST", "PUT", "/api/websites/:id/site-backups/recover-maintenance", "/api/websites/1/site-backups/recover-maintenance", 409},
		{"AI write", "POST", "/api/websites/:id/ai/sessions/:session_id/messages", "/api/websites/1/ai/sessions/a/messages", 409},
		{"WP update", "POST", "/api/websites/:id/wp-core-update/confirm", "/api/websites/1/wp-core-update/confirm", 409},
		{"Adminer GET", "GET", "/tools/adminer/:id", "/tools/adminer/1?sql=DELETE", 409},
		{"Adminer subpath", "POST", "/tools/adminer/:id/*path", "/tools/adminer/1/action", 409},
		{"other Adminer", "GET", "/tools/adminer/:id", "/tools/adminer/2", 204},
		{"backup status", "GET", "/api/websites/:id/backups/active-operation", "/api/websites/1/backups/active-operation", 204},
		{"backup download", "GET", "/api/websites/:id/site-backups/:bid/download", "/api/websites/1/site-backups/4/download", 204},
		{"archive delete", "DELETE", "/api/websites/:id/site-backups/:bid", "/api/websites/1/site-backups/4", 204},
		{"DB archive delete", "DELETE", "/api/websites/:id/backups/:bid", "/api/websites/1/backups/4", 204},
		{"file archive delete", "DELETE", "/api/websites/:id/file-backups/:bid", "/api/websites/1/file-backups/4", 204},
		{"other shared PHP change", "PUT", "/api/websites/:id/php-version", "/api/websites/2/php-version", 409},
		{"global backup policy", "PUT", "/api/backups/policy", "/api/backups/policy", 409},
		{"global PHP configuration", "PUT", "/api/software/php-config", "/api/software/php-config", 409},
		{"global DB restore", "POST", "/api/settings/db-backup/restore", "/api/settings/db-backup/restore", 409},
		{"service action", "POST", "/api/software/guard/action", "/api/software/guard/action", 409},
		{"CDN refresh", "POST", "/api/security/whitelist/refresh", "/api/security/whitelist/refresh", 409},
		{"logout", "POST", "/api/auth/logout", "/api/auth/logout", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := backupMaintenanceGuardRequest(t, tc.method, tc.route, tc.target, "{}")
			if code != tc.want {
				t.Fatalf("status=%d want=%d", code, tc.want)
			}
		})
	}
}

func TestBackupMaintenanceGuardFileSelectorsAndBodyReplay(t *testing.T) {
	setupBackupMaintenanceGuardDB(t)
	for _, tc := range []struct {
		name, method, route, target, body string
		want                              int
	}{
		{"query file", "DELETE", "/api/files/delete", "/api/files/delete?site_id=1&path=x", "", 409},
		{"other query file", "DELETE", "/api/files/delete", "/api/files/delete?site_id=2&path=x", "", 204},
		{"JSON file", "PUT", "/api/files/rename", "/api/files/rename", `{"site_id":1,"old_path":"x","new_name":"y"}`, 409},
		{"query cannot override JSON", "PUT", "/api/files/rename", "/api/files/rename?site_id=2", `{"site_id":1,"old_path":"x"}`, 409},
		{"JSON cannot override query", "POST", "/api/files/mkdir", "/api/files/mkdir?site_id=1&path=x", `{"site_id":2,"name":"new"}`, 409},
		{"cross site destination", "POST", "/api/files/copy", "/api/files/copy", `{"site_id":2,"dest_site_id":1,"src_path":"/","dest_path":"/","names":["x"]}`, 409},
		{"cross site source", "POST", "/api/files/move", "/api/files/move", `{"site_id":1,"dest_site_id":2,"names":["x"]}`, 409},
		{"remote download target", "POST", "/api/files/remote-import", "/api/files/remote-import", `{"site_id":1,"path":"/","url":"https://example.invalid/a"}`, 409},
		{"remote JSON cannot be masked", "POST", "/api/files/remote-import", "/api/files/remote-import?site_id=2", `{"site_id":1}`, 409},
		{"other JSON body replay", "PUT", "/api/files/rename", "/api/files/rename", `{"site_id":2,"old_path":"x","new_name":"y"}`, 204},
		{"backup directory", "DELETE", "/api/files/delete", "/api/files/delete?site_id=0&path=x", "", 204},
		{"permissions", "POST", "/api/files/fix-permissions", "/api/files/fix-permissions?site_id=1", "", 409},
		{"bad JSON", "PUT", "/api/files/rename", "/api/files/rename", `{"site_id":`, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, reached, body := backupMaintenanceGuardRequest(t, tc.method, tc.route, tc.target, tc.body)
			if code != tc.want {
				t.Fatalf("status=%d want=%d", code, tc.want)
			}
			if reached && body != tc.body {
				t.Fatalf("handler body changed: %q", body)
			}
		})
	}
}

func TestBackupMaintenanceGuardPhysicalTarget(t *testing.T) {
	frozen, active := setupBackupMaintenanceGuardDB(t)
	link := filepath.Join(active, "frozen-link")
	if err := os.Symlink(frozen, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	code, _, _ := backupMaintenanceGuardRequest(t, "DELETE", "/api/files/delete", "/api/files/delete?site_id=2&path=frozen-link/new.txt", "")
	if code != 409 {
		t.Fatalf("symlink into maintained website status=%d", code)
	}
}

func TestBackupMaintenanceGuardJSONSelectorDoesNotDependOnContentType(t *testing.T) {
	setupBackupMaintenanceGuardDB(t)
	for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded"} {
		t.Run(contentType, func(t *testing.T) {
			router := gin.New()
			router.Use(WebsiteBackupMaintenanceGuard())
			router.PUT("/api/files/rename", func(c *gin.Context) { t.Error("frozen JSON selector reached handler"); c.Status(204) })
			req := httptest.NewRequest("PUT", "/api/files/rename?site_id=2", strings.NewReader(`{"site_id":1,"old_path":"x","new_name":"y"}`))
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != 409 {
				t.Fatalf("status=%d", rec.Code)
			}
		})
	}
}

func TestBackupMaintenanceGuardCronOwnership(t *testing.T) {
	setupBackupMaintenanceGuardDB(t)
	for _, tc := range []struct {
		name, method, route, target, body string
		want                              int
	}{
		{"frozen run", "POST", "/api/cron/:id/run", "/api/cron/1/run", "", 409},
		{"active run", "POST", "/api/cron/:id/run", "/api/cron/2/run", "", 204},
		{"frozen user run", "POST", "/api/cron/:id/run", "/api/cron/3/run", "", 409},
		{"root cross site run", "POST", "/api/cron/:id/run", "/api/cron/4/run", "", 409},
		{"other user run", "POST", "/api/cron/:id/run", "/api/cron/5/run", "", 204},
		{"delete WP cron", "DELETE", "/api/cron/:id", "/api/cron/1", "", 409},
		{"change existing ownership", "PUT", "/api/cron/:id", "/api/cron/1", `{"task_type":"wp_cron","site_id":2}`, 409},
		{"change target to frozen", "PUT", "/api/cron/:id", "/api/cron/2", `{"task_type":"wp_cron","site_id":1}`, 409},
		{"create frozen WP task", "POST", "/api/cron", "/api/cron", `{"task_type":"wp_cron","site_id":1}`, 409},
		{"create other WP task", "POST", "/api/cron", "/api/cron", `{"task_type":"wp_cron","site_id":2}`, 204},
		{"create unowned command", "POST", "/api/cron", "/api/cron", `{"command":"true"}`, 409},
		{"spoof root site", "POST", "/api/cron", "/api/cron", `{"site_id":2,"task_type":"command","run_as_user":"root"}`, 409},
		{"frozen user new command", "POST", "/api/cron", "/api/cron", `{"task_type":"command","run_as_user":"wp_site1"}`, 409},
		{"other user new command", "POST", "/api/cron", "/api/cron", `{"task_type":"command","run_as_user":"wp_site2"}`, 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, body := backupMaintenanceGuardRequest(t, tc.method, tc.route, tc.target, tc.body)
			if code != tc.want {
				t.Fatalf("status=%d want=%d", code, tc.want)
			}
			if code == 204 && body != tc.body {
				t.Fatalf("body changed %q", body)
			}
		})
	}
}

func TestBackupMaintenanceGuardPluginIdentity(t *testing.T) {
	setupBackupMaintenanceGuardDB(t)
	router := gin.New()
	router.Use(WebsiteBackupMaintenanceGuard())
	router.POST("/api/sites/maintenance/:action", func(c *gin.Context) { c.Status(204) })
	for _, tc := range []struct {
		name, key, remote string
		want              int
	}{
		{"frozen identity ignores caller site", strings.Repeat("1", 40), "127.0.0.1:12345", 409},
		{"active identity", strings.Repeat("2", 40), "127.0.0.1:12345", 204},
		{"remote cannot resolve plugin", strings.Repeat("2", 40), "203.0.113.1:12345", 503},
		{"wrong key", "missing", "127.0.0.1:12345", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/sites/maintenance/unlock", strings.NewReader(`{"site_id":2,"domain":"site2.example"}`))
			req.Header.Set("X-OLS-WPanel-Key", tc.key)
			req.RemoteAddr = tc.remote
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d", rec.Code, tc.want)
			}
		})
	}
}

func TestBackupMaintenanceGuardUploadSessionAndMultipartReplay(t *testing.T) {
	setupBackupMaintenanceGuardDB(t)
	for _, id := range []int{1, 2} {
		name := fmt.Sprintf("upload%d", id)
		dir := uploadSessionDir(name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := saveUploadSession(dir, uploadSession{SiteID: id, Path: "/", Filename: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name     string
		id, want int
	}{{"frozen", 1, 409}, {"other", 2, 204}} {
		t.Run(tc.name+" complete", func(t *testing.T) {
			body := fmt.Sprintf(`{"upload_id":"upload%d","site_id":2,"path":"/"}`, tc.id)
			code, _, read := backupMaintenanceGuardRequest(t, "POST", "/api/files/upload/complete", "/api/files/upload/complete?site_id=2", body)
			if code != tc.want {
				t.Fatalf("status=%d want=%d", code, tc.want)
			}
			if code == 204 && read != body {
				t.Fatal("JSON replay changed")
			}
		})
		t.Run(tc.name+" chunk", func(t *testing.T) {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			_ = writer.WriteField("upload_id", fmt.Sprintf("upload%d", tc.id))
			_ = writer.WriteField("chunk_index", "0")
			file, err := writer.CreateFormFile("chunk", "chunk.bin")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = file.Write(bytes.Repeat([]byte("payload"), 20000))
			_ = writer.Close()
			router := gin.New()
			router.Use(WebsiteBackupMaintenanceGuard())
			router.POST("/api/files/upload/chunk", func(c *gin.Context) {
				if c.PostForm("upload_id") != fmt.Sprintf("upload%d", tc.id) {
					t.Error("multipart field not replayed")
				}
				part, err := c.FormFile("chunk")
				if err != nil || part.Size != 140000 {
					t.Errorf("multipart file replay size/error: %v / %v", part, err)
				}
				c.Status(204)
			})
			req := httptest.NewRequest("POST", "/api/files/upload/chunk?site_id=2", bytes.NewReader(body.Bytes()))
			req.Header.Set("Content-Type", writer.FormDataContentType())
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d", rec.Code, tc.want)
			}
		})
	}
}

func TestBackupMaintenanceGuardFailClosedAndStateRelease(t *testing.T) {
	setupBackupMaintenanceGuardDB(t)
	code, _, _ := backupMaintenanceGuardRequest(t, "PUT", "/api/files/rename", "/api/files/rename", strings.Repeat("x", backupMaintenanceRequestBytes+1))
	if code != 503 {
		t.Fatalf("oversized inspection status=%d", code)
	}
	if _, err := database.GetDB().Exec("UPDATE websites SET status='active' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	code, _, _ = backupMaintenanceGuardRequest(t, "PUT", "/api/websites/:id/maintenance", "/api/websites/1/maintenance", "{}")
	if code != 204 {
		t.Fatalf("released status=%d", code)
	}
	old := database.DB
	database.DB = nil
	t.Cleanup(func() { database.DB = old })
	code, _, _ = backupMaintenanceGuardRequest(t, "PUT", "/api/websites/:id/monitoring", "/api/websites/1/monitoring", "{}")
	if code != 503 {
		t.Fatalf("unreadable status=%d", code)
	}
	code, _, _ = backupMaintenanceGuardRequest(t, "GET", "/api/websites/:id/backups/active-operation", "/api/websites/1/backups/active-operation", "")
	if code != 204 {
		t.Fatalf("status GET unavailable=%d", code)
	}
}
