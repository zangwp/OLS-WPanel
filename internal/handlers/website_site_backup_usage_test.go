package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// Filesystem ownership and manifest validation are tested by the executor.
// These boundaries let the HTTP contract be checked with portable local data.
func setWebsiteBackupStorageTestBoundaries(t *testing.T, points []models.SiteBackup, artifacts bool, storageErr error) {
	t.Helper()
	oldList, oldHas := listWebsiteSiteBackups, hasWebsiteSiteBackupArtifacts
	listWebsiteSiteBackups = func(context.Context, *models.Website) ([]models.SiteBackup, error) {
		return points, storageErr
	}
	hasWebsiteSiteBackupArtifacts = func(context.Context, *models.Website) (bool, error) {
		return artifacts, storageErr
	}
	t.Cleanup(func() { listWebsiteSiteBackups, hasWebsiteSiteBackupArtifacts = oldList, oldHas })
}

func TestBackupUsageIncludesWholeSiteAndRetainedOperationData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupBackupUsageTestDB(t)
	points := []models.SiteBackup{
		{ID: "complete", State: "complete", LocalExists: true, Consistency: "controlled_quiescence"},
		{ID: "incomplete", State: "incomplete"},
		{ID: "attention", State: "complete", LocalExists: true, Consistency: "controlled_quiescence", RequiresAttention: true},
		{ID: "unconfirmed", State: "complete", LocalExists: true},
	}
	setWebsiteBackupStorageTestBoundaries(t, points, true, nil)
	for _, dir := range []string{"site-sets/complete", "site-sets/incomplete", "site-sets/attention", "site-sets/unconfirmed", "site-sets/unknown", "site-operations/retained-rollback"} {
		if err := os.MkdirAll(filepath.Join(config.AppConfig.Panel.BackupDir, "example.com", filepath.FromSlash(dir)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	router := gin.New()
	router.GET("/api/websites/:id/backup-usage", (&WebsiteHandler{}).BackupUsage)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/websites/1/backup-usage", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response backupUsageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	usage := response.Data
	if !response.Success || !usage.SiteBackupChecked || !usage.SiteBackupsDeleteBlocked || usage.SiteBackupCount != 4 || usage.SiteBackupIncompleteCount != 3 || usage.SiteBackupAttentionCount != 1 || usage.SiteBackupUnrecognizedCount != 2 {
		t.Fatalf("whole-site counts/guard = %+v", usage)
	}
}

func TestWebsiteBackupUsageBlocksLifecycleForAnyWholeSiteData(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		points []models.SiteBackup
		dir    string
	}{
		{"complete", []models.SiteBackup{{ID: "set", State: "complete", LocalExists: true, Consistency: "controlled_quiescence"}}, "site-sets/set"},
		{"incomplete", []models.SiteBackup{{ID: "set", State: "incomplete"}}, "site-sets/set"},
		{"attention", []models.SiteBackup{{ID: "set", State: "complete", LocalExists: true, Consistency: "controlled_quiescence", RequiresAttention: true}}, "site-sets/set"},
		{"unrecognized", nil, "site-sets/unrecognized"},
		{"orphan-operation", nil, "site-operations/old-rollback"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			setupBackupUsageTestDB(t)
			setWebsiteBackupStorageTestBoundaries(t, fixture.points, true, nil)
			retained := filepath.Join(config.AppConfig.Panel.BackupDir, "example.com", filepath.FromSlash(fixture.dir))
			if err := os.MkdirAll(retained, 0700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(retained, "must-remain")
			if err := os.WriteFile(marker, []byte("safety copy"), 0600); err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			handler := &WebsiteHandler{}
			router.DELETE("/api/websites/:id", handler.Delete)
			router.PUT("/api/websites/:id/domains", handler.UpdateDomains)
			for _, request := range []*http.Request{
				httptest.NewRequest(http.MethodDelete, "/api/websites/1", nil),
				httptest.NewRequest(http.MethodPut, "/api/websites/1/domains", strings.NewReader(`{"new_domain":"new.example.com"}`)),
			} {
				request.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, request)
				if rec.Code != http.StatusConflict {
					t.Fatalf("%s lifecycle allowed: status=%d body=%s", request.Method, rec.Code, rec.Body.String())
				}
				var count int
				if err := database.GetDB().QueryRow(`SELECT COUNT(*) FROM websites WHERE id=1 AND domain='example.com'`).Scan(&count); err != nil || count != 1 {
					t.Fatalf("website binding changed: count=%d err=%v", count, err)
				}
				if _, err := os.Stat(marker); err != nil {
					t.Fatalf("backup data was removed: %v", err)
				}
			}
		})
	}
}

func TestWebsiteBackupUsageReadFailureNeverGrantsLifecycle(t *testing.T) {
	setupBackupUsageTestDB(t)
	setWebsiteBackupStorageTestBoundaries(t, nil, false, errors.New("fixture storage unavailable"))
	router := gin.New()
	handler := &WebsiteHandler{}
	router.GET("/api/websites/:id/backup-usage", handler.BackupUsage)
	router.DELETE("/api/websites/:id", handler.Delete)
	router.PUT("/api/websites/:id/domains", handler.UpdateDomains)
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/api/websites/1/backup-usage", nil),
		httptest.NewRequest(http.MethodDelete, "/api/websites/1", nil),
		httptest.NewRequest(http.MethodPut, "/api/websites/1/domains", strings.NewReader(`{"new_domain":"new.example.com"}`)),
	} {
		request.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, request)
		want := http.StatusConflict
		if request.Method == http.MethodGet {
			want = http.StatusInternalServerError
		}
		if rec.Code != want || strings.Contains(rec.Body.String(), `"site_backup_checked":true`) {
			t.Fatalf("%s unconfirmed response: %d %s", request.Method, rec.Code, rec.Body.String())
		}
	}
}

func TestWebsiteBackupUsageFailsClosedOnCancellationOrNonDirectory(t *testing.T) {
	setupBackupUsageTestDB(t)
	setWebsiteBackupStorageTestBoundaries(t, nil, false, nil)
	site := &models.Website{ID: 1, Domain: "example.com"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if usage, err := collectWebsiteSiteBackupUsage(ctx, site); !errors.Is(err, context.Canceled) || usage.SiteBackupChecked {
		t.Fatalf("cancelled read = %+v, %v", usage, err)
	}
	parent := filepath.Join(config.AppConfig.Panel.BackupDir, site.Domain)
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "site-operations"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if usage, err := collectWebsiteSiteBackupUsage(context.Background(), site); err == nil || usage.SiteBackupChecked {
		t.Fatalf("unsafe operation path = %+v, %v", usage, err)
	}
}
