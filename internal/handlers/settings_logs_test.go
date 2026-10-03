package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

type operationLogsResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Logs       []map[string]any `json:"data"`
		Total      int              `json:"total"`
		Page       int              `json:"page"`
		PerPage    int              `json:"per_page"`
		TotalPages int              `json:"total_pages"`
	} `json:"data"`
}

func requestOperationLogs(t *testing.T, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/settings/logs?"+rawQuery, nil)
	new(SettingsHandler).GetOperationLogs(ctx)
	return recorder
}

func TestGetOperationLogsSupportsPaginationAndFilters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupBackupOverviewTestDB(t)
	db := database.GetDB()
	for i := 0; i < 15; i++ {
		status := "success"
		operation := "panel_manual_update"
		if i%3 == 0 {
			status = "failed"
			operation = "swap_apply_custom"
		}
		if _, err := db.Exec(`INSERT INTO operation_logs(operation,target,status,message) VALUES(?,?,?,?)`, operation, fmt.Sprintf("node-%02d", i), status, "test"); err != nil {
			t.Fatal(err)
		}
	}

	recorder := requestOperationLogs(t, "page=1&per_page=10")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response operationLogsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Total != 15 || response.Data.TotalPages != 2 || response.Data.PerPage != 10 || len(response.Data.Logs) != 10 {
		t.Fatalf("unexpected pagination: %+v", response.Data)
	}

	recorder = requestOperationLogs(t, "status=failed&q=swap&per_page=20")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response = operationLogsResponse{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Total != 5 || len(response.Data.Logs) != 5 {
		t.Fatalf("filtered logs=%d total=%d, want 5", len(response.Data.Logs), response.Data.Total)
	}
}

func TestGetOperationLogsRejectsInvalidFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupBackupOverviewTestDB(t)
	if recorder := requestOperationLogs(t, "status=unknown"); recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder := requestOperationLogs(t, "q=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklm"); recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
