package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

func TestBackupListRejectsMalformedRowsAndCancelledRequests(t *testing.T) {
	setupBackupOverviewTestDB(t)
	db := database.GetDB()
	if _, err := db.Exec(`INSERT INTO websites (id,name,domain,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path)
		VALUES(1,'fixture','fixture.example.com','wp_fixture','/www/wwwroot/fixture.example.com','/www/wwwlogs/fixture.example.com','db1','wp_fixture','/p','/n')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO db_backups(site_id,filename,file_size,db_name) VALUES(1,'broken.sql.gz','invalid-size','db1')`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/backup/:id", (&BackupHandler{}).List)
	for _, cancelled := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodGet, "/backup/1", nil)
		if cancelled {
			ctx, cancel := context.WithCancel(req.Context())
			cancel()
			req = req.WithContext(ctx)
		}
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("partial/cancelled list became empty success: cancelled=%v status=%d body=%s", cancelled, recorder.Code, recorder.Body.String())
		}
	}
}

func TestBackupSettingsReadDistinguishesMissingFromFailed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupBackupOverviewTestDB(t)
	r := gin.New()
	r.GET("/settings/:id", (&BackupHandler{}).GetSettings)
	read := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/settings/1", nil))
		return w
	}
	missing := read()
	if missing.Code != http.StatusOK || missing.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing policy: status=%d cache=%q", missing.Code, missing.Header().Get("Cache-Control"))
	}
	var response struct {
		Data struct {
			Enabled   bool `json:"enabled"`
			KeepCount int  `json:"keep_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(missing.Body.Bytes(), &response); err != nil || response.Data.Enabled || response.Data.KeepCount != 7 {
		t.Fatalf("missing policy default: %s, error=%v", missing.Body.String(), err)
	}
	if _, err := database.GetDB().Exec("DROP TABLE backup_settings"); err != nil {
		t.Fatal(err)
	}
	failed := read()
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("failed query reported writable default: status=%d body=%s", failed.Code, failed.Body.String())
	}
}
