package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

type websiteSecurityTestResponse struct {
	Success bool                         `json:"success"`
	Message string                       `json:"message"`
	Data    models.WebsiteSecurityStatus `json:"data"`
}

func requestWebsiteSecurityStatus(t *testing.T, id string) (*httptest.ResponseRecorder, websiteSecurityTestResponse) {
	t.Helper()
	router := gin.New()
	router.GET("/api/websites/:id/security-status", (&WebsiteHandler{}).SecurityStatus)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/websites/"+id+"/security-status", nil))
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("security status must not be cached: headers=%v", recorder.Header())
	}
	var result websiteSecurityTestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid security response: %s: %v", recorder.Body.String(), err)
	}
	return recorder, result
}

func setupWebsiteSecurityStatusDatabase(t *testing.T, siteType string) {
	t.Helper()
	oldDB, oldConfig := database.DB, config.AppConfig
	root := t.TempDir()
	if err := database.Open(filepath.Join(root, "panel.db")); err != nil {
		t.Fatal(err)
	}
	testDB := database.GetDB()
	t.Cleanup(func() {
		testDB.Close()
		database.DB, config.AppConfig = oldDB, oldConfig
	})
	if err := database.RunMigrations(); err != nil {
		t.Fatal(err)
	}
	config.AppConfig = &config.Config{Paths: config.PathsConfig{
		WWWRoot: filepath.Join(root, "www"), WWWLogs: filepath.Join(root, "logs"),
		OLSVHostsAvailable: filepath.Join(root, "vhosts"),
	}}
	webRoot := filepath.Join(config.AppConfig.Paths.WWWRoot, "example.com")
	logDir := filepath.Join(config.AppConfig.Paths.WWWLogs, "example.com")
	vhostPath := filepath.Join(config.AppConfig.Paths.OLSVHostsAvailable, "example.conf")
	for _, path := range []string{webRoot, logDir, filepath.Dir(vhostPath)} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(webRoot, "wp-config.php"), []byte("<?php\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// This fixture deliberately contains no security block, authentication audit
	// policy or observed requests. The real collector must not probe/reconfigure
	// a live server or infer that persisted flags are already effective.
	if err := os.WriteFile(vhostPath, []byte("# unmanaged fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := testDB.Exec(`INSERT INTO websites
		(id,name,domain,status,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path,site_type)
		VALUES (1,'example','example.com','paused','wp_example',?,?,'db_example','wp_example','/tmp/site.sock',?,?)`,
		webRoot, logDir, vhostPath, siteType)
	if err != nil {
		t.Fatal(err)
	}
}

func securityCheckForTest(t *testing.T, report models.WebsiteSecurityStatus, key string) models.WebsiteSecurityCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.Key == key {
			return check
		}
	}
	t.Fatalf("security check %q missing", key)
	return models.WebsiteSecurityCheck{}
}

func TestWebsiteSecurityStatusRejectsInvalidIDBeforeDatabaseLookup(t *testing.T) {
	oldDB := database.DB
	database.DB = nil
	t.Cleanup(func() { database.DB = oldDB })
	for _, id := range []string{"bad", "0", "-1", "9999999999999999999999999"} {
		t.Run(id, func(t *testing.T) {
			rec, body := requestWebsiteSecurityStatus(t, id)
			if rec.Code != http.StatusBadRequest || body.Success || body.Message == "" {
				t.Fatalf("invalid ID response: status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestWebsiteSecurityStatusUnavailableDatabase(t *testing.T) {
	oldDB := database.DB
	database.DB = nil
	t.Cleanup(func() { database.DB = oldDB })
	rec, body := requestWebsiteSecurityStatus(t, "1")
	if rec.Code != http.StatusServiceUnavailable || body.Success || body.Message == "" {
		t.Fatalf("missing database response: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWebsiteSecurityStatusDistinguishesNotFoundAndQueryFailure(t *testing.T) {
	setupWebsiteSecurityStatusDatabase(t, "wordpress")
	rec, body := requestWebsiteSecurityStatus(t, "999")
	if rec.Code != http.StatusNotFound || body.Success {
		t.Fatalf("missing site response: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := database.GetDB().Close(); err != nil {
		t.Fatal(err)
	}
	rec, body = requestWebsiteSecurityStatus(t, "1")
	if rec.Code != http.StatusServiceUnavailable || body.Success {
		t.Fatalf("query failure was presented as a missing site: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWebsiteSecurityStatusReportsAllChecksWithoutInventingEffectiveness(t *testing.T) {
	setupWebsiteSecurityStatusDatabase(t, "wordpress")
	for _, sql := range []string{
		`UPDATE websites SET ssl_enabled=1, monitoring_enabled=1, file_lock_enabled=1, file_lock_apply_status='ready' WHERE id=1`,
		`INSERT INTO backup_settings(site_id,enabled) VALUES(1,1)`,
		`INSERT INTO site_wp_anomaly_state(site_id,enabled) VALUES(1,1)`,
	} {
		if _, err := database.GetDB().Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	rec, body := requestWebsiteSecurityStatus(t, "1")
	if rec.Code != http.StatusOK || !body.Success || body.Data.SiteID != 1 {
		t.Fatalf("known site response: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := time.Parse(time.RFC3339, body.Data.CheckedAt); err != nil {
		t.Fatalf("invalid observation timestamp: %q", body.Data.CheckedAt)
	}
	expected := map[string]bool{}
	for _, key := range []string{"https", "login_protection", "xmlrpc", "application_passwords", "sensitive_files", "uploads_php", "file_editing", "file_lock", "debug_display", "uptime_monitor", "anomaly_monitor", "wp_updates", "backup", "sql_injection"} {
		expected[key] = true
	}
	if len(body.Data.Checks) != len(expected) {
		t.Fatalf("unexpected check count: %d", len(body.Data.Checks))
	}
	for _, check := range body.Data.Checks {
		if !expected[check.Key] {
			t.Fatalf("unexpected or duplicated check: %q", check.Key)
		}
		delete(expected, check.Key)
		if check.State == "effective" || (check.Effective != nil && *check.Effective) {
			t.Fatalf("persisted settings without runtime evidence falsely reported effective: %+v", check)
		}
	}
	for _, key := range []string{"backup", "anomaly_monitor"} {
		check := securityCheckForTest(t, body.Data, key)
		if check.State != "configured" || check.Configured == nil || !*check.Configured || check.Effective != nil {
			t.Fatalf("configured schedule must remain unverified: %+v", check)
		}
	}
}

func TestWebsiteSecurityStatusMissingPolicyRowsAreDisabled(t *testing.T) {
	setupWebsiteSecurityStatusDatabase(t, "wordpress")
	rec, body := requestWebsiteSecurityStatus(t, "1")
	if rec.Code != http.StatusOK || !body.Success {
		t.Fatalf("known site response: status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, key := range []string{"backup", "anomaly_monitor"} {
		check := securityCheckForTest(t, body.Data, key)
		if check.State != "disabled" || check.Configured == nil || *check.Configured || check.Effective != nil {
			t.Fatalf("absent policy row misclassified: %+v", check)
		}
	}
}

func TestWebsiteSecurityStatusPolicyReadFailuresRemainUnknown(t *testing.T) {
	for _, tc := range []struct{ key, table string }{
		{"backup", "backup_settings"}, {"anomaly_monitor", "site_wp_anomaly_state"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			setupWebsiteSecurityStatusDatabase(t, "wordpress")
			if _, err := database.GetDB().Exec("DROP TABLE " + tc.table); err != nil {
				t.Fatal(err)
			}
			rec, body := requestWebsiteSecurityStatus(t, "1")
			if rec.Code != http.StatusOK || !body.Success {
				t.Fatalf("partial policy read failure hid the site report: status=%d body=%s", rec.Code, rec.Body.String())
			}
			check := securityCheckForTest(t, body.Data, tc.key)
			if check.State != "unknown" || check.Configured != nil || check.Effective != nil {
				t.Fatalf("policy query error was converted into disabled/effective: %+v", check)
			}
		})
	}
}

func TestWebsiteSecurityStatusPHPDoesNotClaimWordPressProtection(t *testing.T) {
	setupWebsiteSecurityStatusDatabase(t, "php")
	// Non-WordPress sites must not query a WordPress-only policy table and
	// replace the collector's unsupported state with a database error.
	if _, err := database.GetDB().Exec("DROP TABLE site_wp_anomaly_state"); err != nil {
		t.Fatal(err)
	}
	rec, body := requestWebsiteSecurityStatus(t, "1")
	if rec.Code != http.StatusOK || !body.Success {
		t.Fatalf("PHP site response: status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, key := range []string{"login_protection", "xmlrpc", "application_passwords", "uploads_php", "file_editing", "debug_display", "anomaly_monitor", "wp_updates", "sql_injection"} {
		check := securityCheckForTest(t, body.Data, key)
		if check.State != "unsupported" || check.Configured != nil || check.Effective != nil {
			t.Fatalf("PHP site misleadingly reports WordPress-only protection: %+v", check)
		}
	}
}
