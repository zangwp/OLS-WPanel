package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

func readSettingsForTest(t *testing.T, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	handler(ctx)
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", got)
	}
	return recorder
}

func requireSettingsReadFailure(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusInternalServerError || response["success"] != false || response["data"] != nil {
		t.Fatalf("expected an error without partial data: status=%d response=%v", recorder.Code, response)
	}
	if strings.Contains(recorder.Body.String(), "private-fixture-value") {
		t.Fatal("error response disclosed partial settings")
	}
}

func TestGetAlertSettingsRejectsDatabaseReadFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		view string
	}{
		{name: "query failure"},
		{name: "scan failure", view: `CREATE VIEW security_settings AS
			SELECT 1 AS id, 'smtp_host' AS skey, 'private-fixture-value' AS svalue, '' AS description, '' AS updated_at
			UNION ALL SELECT 2, 'smtp_pass', NULL, '', ''`},
		{name: "iteration failure", view: `CREATE VIEW security_settings AS
			SELECT 1 AS id, 'smtp_host' AS skey, 'private-fixture-value' AS svalue, '' AS description, '' AS updated_at
			UNION ALL SELECT 2, 'smtp_pass', json_extract('invalid-json', '$'), '', ''`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupRemoteBackupTestDB(t)
			db := database.GetDB()
			if _, err := db.Exec(`DROP TABLE security_settings`); err != nil {
				t.Fatal(err)
			}
			if tc.view != "" {
				if _, err := db.Exec(tc.view); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "iteration failure" {
				// Confirm SQLite fails only after returning the first valid row.
				rows, err := db.Query(`SELECT * FROM security_settings`)
				if err != nil {
					t.Fatal(err)
				}
				if !rows.Next() || rows.Next() || rows.Err() == nil {
					rows.Close()
					t.Fatal("fixture did not produce a late iteration error")
				}
				rows.Close()
			}
			requireSettingsReadFailure(t, readSettingsForTest(t, new(AlertHandler).GetSettings))
		})
	}
}

func TestGetAlertSettingsAllowsEmptyConfiguration(t *testing.T) {
	setupRemoteBackupTestDB(t)
	if _, err := database.GetDB().Exec(`DELETE FROM security_settings`); err != nil {
		t.Fatal(err)
	}
	recorder := readSettingsForTest(t, new(AlertHandler).GetSettings)
	var response struct {
		Success bool              `json:"success"`
		Data    map[string]string `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || !response.Success || response.Data == nil || len(response.Data) != 0 {
		t.Fatalf("empty settings were not accepted: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestGetRemoteBackupRejectsDatabaseReadFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{name: "query failure", sql: `DROP TABLE remote_backup_settings`},
		{name: "scan failure", sql: `UPDATE remote_backup_settings SET port='invalid-port', password='private-fixture-value' WHERE id=1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupRemoteBackupTestDB(t)
			if _, err := database.GetDB().Exec(tc.sql); err != nil {
				t.Fatal(err)
			}
			requireSettingsReadFailure(t, readSettingsForTest(t, GetRemoteBackup))
		})
	}
}

func TestGetRemoteBackupInitializesMissingConfiguration(t *testing.T) {
	setupRemoteBackupTestDB(t)
	if _, err := database.GetDB().Exec(`DELETE FROM remote_backup_settings WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	recorder := readSettingsForTest(t, GetRemoteBackup)
	if recorder.Code != http.StatusOK {
		t.Fatalf("missing defaults status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Success bool `json:"success"`
		Data    struct {
			Enabled   bool   `json:"enabled"`
			Port      int    `json:"port"`
			KeepLocal bool   `json:"keep_local"`
			ServerID  string `json:"server_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.Data.Enabled || response.Data.Port != 22 || !response.Data.KeepLocal || len(response.Data.ServerID) != 12 {
		t.Fatalf("unexpected defaults: %+v", response)
	}
	var storedID string
	if err := database.GetDB().QueryRow(`SELECT server_id FROM remote_backup_settings WHERE id=1`).Scan(&storedID); err != nil || storedID != response.Data.ServerID {
		t.Fatalf("default identity was not persisted: id=%q err=%v", storedID, err)
	}
}

func TestSaveRemoteBackupReadFailureDoesNotOverwriteSecrets(t *testing.T) {
	setupRemoteBackupTestDB(t)
	db := database.GetDB()
	// Copy into a permissive table to model a damaged/legacy row with a NULL
	// password. A failed Scan must stop before the UPDATE can erase credentials.
	for _, statement := range []string{
		`ALTER TABLE remote_backup_settings RENAME TO remote_backup_fixture`,
		`CREATE TABLE remote_backup_settings AS SELECT * FROM remote_backup_fixture`,
		`UPDATE remote_backup_settings SET server_id='a83f2c91d407', password=NULL, s3_secret_key='private-fixture-value' WHERE id=1`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/settings/remote-backup", strings.NewReader(`{"enabled":false,"backup_type":"s3","connection_mode":"legacy","password":"已设置","s3_secret_key":"已设置"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	SaveRemoteBackup(ctx)
	requireSettingsReadFailure(t, recorder)
	var passwordMissing bool
	var secret string
	if err := db.QueryRow(`SELECT password IS NULL, s3_secret_key FROM remote_backup_settings WHERE id=1`).Scan(&passwordMissing, &secret); err != nil || !passwordMissing || secret != "private-fixture-value" {
		t.Fatalf("failed read changed credentials: passwordMissing=%v secretPreserved=%v err=%v", passwordMissing, secret == "private-fixture-value", err)
	}
}
