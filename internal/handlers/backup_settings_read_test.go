package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

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
