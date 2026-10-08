package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/accountsecurity"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
	"golang.org/x/crypto/bcrypt"
)

func settingsMFAFixture(t *testing.T) (*SettingsHandler, *gin.Engine, *middleware.Session, []string) {
	t.Helper()
	auth, router := setupMFAHandler(t)
	if _, err := auth.DB.Exec(`ALTER TABLE admin_users ADD COLUMN updated_at TEXT`); err != nil {
		t.Fatal(err)
	}
	oldDB, oldConfig := database.DB, config.AppConfig
	database.DB = auth.DB
	config.AppConfig = &config.Config{BasicAuth: config.BasicAuthConfig{Username: "gateway", PasswordHash: "old-basic-hash"}}
	t.Cleanup(func() { database.DB = oldDB; config.AppConfig = oldConfig })
	path := filepath.Join(t.TempDir(), "config.json")
	writeSettingsConfigFixture(t, path, "gateway")
	h := &SettingsHandler{Auth: auth, ConfigPath: path}
	codes := enableHandlerMFA(t, auth)
	return h, router, middleware.GlobalSessionStore.Create("admin"), codes
}

func settingsMFACall(t *testing.T, h *SettingsHandler, session *middleware.Session, body gin.H) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/settings", bytes.NewReader(raw))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.AddCookie(&http.Cookie{Name: "wp_session", Value: session.Token})
	c.Set("session_username", session.Username)
	h.UpdateSettings(c)
	return w
}

func TestSettingsMFARenamePreservesFactorAndAuditPreferences(t *testing.T) {
	h, router, session, codes := settingsMFAFixture(t)
	if _, err := h.Auth.DB.Exec(`INSERT INTO account_security_preferences(username,notifications_enabled) VALUES('admin',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Auth.Audit.Record(context.Background(), accountsecurity.Event{Username: "admin", Event: "login_success", IP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []gin.H{{"username": "renamed-admin", "old_password": "correct-password"}, {"new_password": "new-password", "old_password": "correct-password"}} {
		w := settingsMFACall(t, h, session, body)
		if w.Code != 401 {
			t.Fatalf("MFA-less change %d %s", w.Code, w.Body.String())
		}
	}
	w := settingsMFACall(t, h, session, gin.H{"username": "renamed-admin", "old_password": "correct-password", "code": codes[0]})
	if w.Code != 200 {
		t.Fatalf("rename %d %s", w.Code, w.Body.String())
	}
	if enabled, err := accountsecurity.MFAEnabled(context.Background(), h.Auth.DB, 1); err != nil || !enabled {
		t.Fatal("username change detached MFA identity")
	}
	var enabled bool
	if err := h.Auth.DB.QueryRow(`SELECT notifications_enabled FROM account_security_preferences WHERE username='renamed-admin'`).Scan(&enabled); err != nil || enabled {
		t.Fatal("rename lost notification preference")
	}
	var oldRows int
	h.Auth.DB.QueryRow(`SELECT COUNT(*) FROM account_security_events WHERE username='admin'`).Scan(&oldRows)
	if oldRows != 0 {
		t.Fatal("audit history orphaned under old username")
	}
	challenge := mfaHandlerCall(t, router, "/login", "", gin.H{"username": "renamed-admin", "password": "correct-password"})
	if challenge.Code != 200 || !strings.Contains(challenge.Body.String(), `"mfa_required":true`) {
		t.Fatalf("renamed login bypassed MFA %d %s", challenge.Code, challenge.Body.String())
	}
	if middleware.GlobalSessionStore.Get(session.Token) != nil {
		t.Fatal("renamed account retained previous session")
	}
}

func TestSettingsBasicAuthRequiresBothFactorsAndConsumesRecoveryOnce(t *testing.T) {
	h, _, session, codes := settingsMFAFixture(t)
	for _, body := range []gin.H{{"basic_auth_user": "gateway-new"}, {"basic_auth_user": "gateway-new", "old_password": "wrong", "code": codes[0]}, {"basic_auth_user": "gateway-new", "old_password": "correct-password"}} {
		w := settingsMFACall(t, h, session, body)
		if w.Code != 401 {
			t.Fatalf("BasicAuth unproved change %d %s", w.Code, w.Body.String())
		}
		if readConfigValue(h.ConfigPath, "basic_auth", "username") != "gateway" {
			t.Fatal("failed proof changed gateway")
		}
	}
	other := middleware.GlobalSessionStore.Create("admin")
	w := settingsMFACall(t, h, session, gin.H{"basic_auth_user": "gateway-new", "old_password": "correct-password", "code": codes[0]})
	if w.Code != 200 {
		t.Fatalf("gateway change %d %s", w.Code, w.Body.String())
	}
	if middleware.GlobalSessionStore.Get(other.Token) != nil || middleware.GlobalSessionStore.Get(session.Token) == nil {
		t.Fatal("gateway change session scope wrong")
	}
	w = settingsMFACall(t, h, session, gin.H{"basic_auth_user": "gateway-again", "old_password": "correct-password", "code": codes[0]})
	if w.Code != 401 || readConfigValue(h.ConfigPath, "basic_auth", "username") != "gateway-new" {
		t.Fatal("recovery code reused for second gateway change")
	}
}

func TestSettingsAuditFailureLeavesWebAndBasicCredentialsUnchanged(t *testing.T) {
	h, _, session, codes := settingsMFAFixture(t)
	if _, err := h.Auth.DB.Exec(`CREATE TRIGGER reject_credentials_audit BEFORE INSERT ON account_security_events WHEN NEW.event='credentials_changed' BEGIN SELECT RAISE(FAIL,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	w := settingsMFACall(t, h, session, gin.H{"basic_auth_user": "gateway-new", "old_password": "correct-password", "code": codes[0]})
	if w.Code < 500 {
		t.Fatalf("failed BasicAuth audit reported success: %d", w.Code)
	}
	after, _ := os.ReadFile(h.ConfigPath)
	if !bytes.Equal(before, after) || config.AppConfig.BasicAuth.Username != "gateway" {
		t.Fatal("audit failure changed gateway credentials")
	}
	w = settingsMFACall(t, h, session, gin.H{"username": "renamed-admin", "new_password": "new-password", "old_password": "correct-password", "code": codes[1]})
	if w.Code != 503 {
		t.Fatalf("failed Web account audit status %d %s", w.Code, w.Body.String())
	}
	var username, hash string
	h.Auth.DB.QueryRow(`SELECT username,password_hash FROM admin_users WHERE id=1`).Scan(&username, &hash)
	if username != "admin" || bcrypt.CompareHashAndPassword([]byte(hash), []byte("correct-password")) != nil {
		t.Fatal("audit failure changed Web credentials")
	}
	if middleware.GlobalSessionStore.Get(session.Token) == nil {
		t.Fatal("failed mutation revoked valid session")
	}
}

func TestSettingsAndMFARejectSessionRevokedAfterMiddleware(t *testing.T) {
	h, _, session, codes := settingsMFAFixture(t)
	middleware.GlobalSessionStore.Delete(session.Token)
	w := settingsMFACall(t, h, session, gin.H{"basic_auth_user": "gateway-new", "old_password": "correct-password", "code": codes[0]})
	if w.Code != 401 {
		t.Fatalf("revoked queued settings request accepted: %d", w.Code)
	}
	for _, handler := range []gin.HandlerFunc{h.Auth.MFADisable, h.Auth.MFARecoveryCodes} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		body, _ := json.Marshal(gin.H{"current_password": "correct-password", "code": codes[0]})
		c.Request = httptest.NewRequest(http.MethodPost, "/mfa", bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request.AddCookie(&http.Cookie{Name: "wp_session", Value: session.Token})
		c.Set("session_username", "admin")
		handler(c)
		if w.Code != 401 {
			t.Fatalf("revoked queued MFA request accepted: %d", w.Code)
		}
	}
	status, err := h.Auth.MFA.Status(context.Background(), 1)
	if err != nil || !status.Enabled || status.RecoveryCodesRemaining != 10 {
		t.Fatal("revoked request modified MFA")
	}
}

func TestSettingsRejectsOversizedPasswordBeforeConsumingMFA(t *testing.T) {
	h, _, session, codes := settingsMFAFixture(t)
	w := settingsMFACall(t, h, session, gin.H{"new_password": strings.Repeat("x", 73), "old_password": "correct-password", "code": codes[0]})
	if w.Code != 400 {
		t.Fatalf("overlong bcrypt input status %d", w.Code)
	}
	status, _ := h.Auth.MFA.Status(context.Background(), 1)
	if status.RecoveryCodesRemaining != 10 {
		t.Fatal("invalid password consumed MFA recovery code")
	}
}
