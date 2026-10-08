package handlers

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/accountsecurity"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
)

func withSystemSettingStubs(t *testing.T) {
	t.Helper()
	oldTimezone, oldHostname, oldNTP := setSystemTimezone, setSystemHostname, enableSystemNTP
	oldReadTimezone, oldReadHostname, oldReadNTP := readSystemTimezone, readSystemHostname, readSystemNTP
	t.Cleanup(func() {
		setSystemTimezone, setSystemHostname, enableSystemNTP = oldTimezone, oldHostname, oldNTP
		readSystemTimezone, readSystemHostname, readSystemNTP = oldReadTimezone, oldReadHostname, oldReadNTP
	})
}

func updateSystemSetting(t *testing.T, body string) *httptest.ResponseRecorder {
	return updateSystemSettingWithHandler(t, new(SettingsHandler), body)
}

func updateSystemSettingWithHandler(t *testing.T, handler *SettingsHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewBufferString(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	if db := database.GetDB(); db != nil {
		var username string
		if db.QueryRow("SELECT username FROM admin_users LIMIT 1").Scan(&username) == nil {
			ctx.Set("session_username", username)
			session := middleware.GlobalSessionStore.Create(username)
			ctx.Request.AddCookie(&http.Cookie{Name: "wp_session", Value: session.Token})
			t.Cleanup(func() { middleware.GlobalSessionStore.Delete(session.Token) })
			if handler.Auth == nil {
				mfa, err := accountsecurity.NewMFAService(db, filepath.Join(t.TempDir(), "account-mfa.key"))
				if err != nil {
					t.Fatal(err)
				}
				audit := accountsecurity.NewAuditService(db)
				t.Cleanup(audit.Close)
				handler.Auth = &AuthHandler{DB: db, MFA: mfa, Audit: audit}
			}
		}
	}
	handler.UpdateSettings(ctx)
	return recorder
}

func TestUpdateSettingsReportsSystemCommandFailures(t *testing.T) {
	tests := []struct {
		name string
		body string
		fail func()
	}{
		{"timezone", `{"timezone":"Asia/Shanghai"}`, func() { setSystemTimezone = func(string) error { return errors.New("failed") } }},
		{"hostname", `{"hostname":"panel-test"}`, func() { setSystemHostname = func(string) error { return errors.New("failed") } }},
		{"ntp", `{"ntp_sync":true}`, func() { enableSystemNTP = func() error { return errors.New("failed") } }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withSystemSettingStubs(t)
			test.fail()
			if recorder := updateSystemSetting(t, test.body); recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestUpdateSettingsVerifiesAppliedSystemValues(t *testing.T) {
	tests := []struct {
		name string
		body string
		stub func()
	}{
		{"timezone", `{"timezone":"Asia/Shanghai"}`, func() {
			setSystemTimezone = func(string) error { return nil }
			readSystemTimezone = func() string { return "UTC" }
		}},
		{"hostname", `{"hostname":"panel-test"}`, func() {
			setSystemHostname = func(string) error { return nil }
			readSystemHostname = func() string { return "old-host" }
		}},
		{"ntp", `{"ntp_sync":true}`, func() {
			enableSystemNTP = func() error { return nil }
			readSystemNTP = func() bool { return false }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withSystemSettingStubs(t)
			test.stub()
			if recorder := updateSystemSetting(t, test.body); recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestUpdateSettingsAcceptsVerifiedSystemValues(t *testing.T) {
	withSystemSettingStubs(t)
	setSystemTimezone = func(string) error { return nil }
	setSystemHostname = func(string) error { return nil }
	enableSystemNTP = func() error { return nil }
	readSystemTimezone = func() string { return "Asia/Shanghai" }
	readSystemHostname = func() string { return "panel-test" }
	readSystemNTP = func() bool { return true }

	recorder := updateSystemSetting(t, `{"timezone":"Asia/Shanghai","hostname":"panel-test","ntp_sync":true}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
