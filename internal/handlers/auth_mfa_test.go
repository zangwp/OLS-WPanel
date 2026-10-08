package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/accountsecurity"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func setupMFAHandler(t *testing.T) (*AuthHandler, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "panel.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err = db.Exec(`CREATE TABLE admin_users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT)`); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if _, err = db.Exec(`INSERT INTO admin_users VALUES(1,'admin',?)`, string(hash)); err != nil {
		t.Fatal(err)
	}
	if err = accountsecurity.InitMFASchema(db); err != nil {
		t.Fatal(err)
	}
	if err = accountsecurity.InitAuditSchema(db); err != nil {
		t.Fatal(err)
	}
	mfa, err := accountsecurity.NewMFAService(db, filepath.Join(dir, "account-mfa.key"))
	if err != nil {
		t.Fatal(err)
	}
	audit := accountsecurity.NewAuditService(db)
	t.Cleanup(audit.Close)
	middleware.GlobalSessionStore.DeleteAll()
	t.Cleanup(middleware.GlobalSessionStore.DeleteAll)
	h := &AuthHandler{DB: db, MFA: mfa, Audit: audit}
	r := gin.New()
	r.POST("/login", middleware.CSRF(), h.Login)
	p := r.Group("/mfa", middleware.SessionRequired(), middleware.CSRF())
	p.GET("", h.MFAStatus)
	p.POST("/setup", h.MFASetup)
	p.POST("/confirm", h.MFAConfirm)
	p.POST("/disable", h.MFADisable)
	p.POST("/recovery-codes", h.MFARecoveryCodes)
	return h, r
}

func mfaHandlerCall(t *testing.T, r http.Handler, path, session string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "test-csrf")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-csrf"})
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "wp_session", Value: session})
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func mfaTestCode(secret string) string {
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var input [8]byte
	binary.BigEndian.PutUint64(input[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, raw)
	mac.Write(input[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}

func enableHandlerMFA(t *testing.T, h *AuthHandler) []string {
	t.Helper()
	setup, err := h.MFA.Setup(context.Background(), 1, "setup-session", "admin")
	if err != nil {
		t.Fatal(err)
	}
	codes, err := h.MFA.Confirm(context.Background(), 1, "setup-session", mfaTestCode(setup.Secret), nil)
	if err != nil {
		t.Fatal(err)
	}
	return codes
}

func requireNoLoginSession(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "wp_session" && cookie.Value != "" {
			t.Fatal("unauthenticated response granted a session")
		}
	}
}

func TestLoginMFAChallengeAndOneTimeRecovery(t *testing.T) {
	h, r := setupMFAHandler(t)
	codes := enableHandlerMFA(t, h)
	challenge := mfaHandlerCall(t, r, "/login", "", gin.H{"username": "admin", "password": "correct-password"})
	if challenge.Code != 200 || !strings.Contains(challenge.Body.String(), `"mfa_required":true`) {
		t.Fatalf("challenge %d %s", challenge.Code, challenge.Body.String())
	}
	requireNoLoginSession(t, challenge)
	for _, body := range []gin.H{{"username": "admin", "password": "wrong-password", "code": codes[0]}, {"username": "admin", "password": "correct-password", "code": "invalid"}} {
		w := mfaHandlerCall(t, r, "/login", "", body)
		if w.Code != 401 {
			t.Fatalf("invalid login %d %s", w.Code, w.Body.String())
		}
		requireNoLoginSession(t, w)
	}
	w := mfaHandlerCall(t, r, "/login", "", gin.H{"username": "admin", "password": "correct-password", "code": codes[0]})
	if w.Code != 200 || len(w.Result().Cookies()) == 0 {
		t.Fatalf("valid MFA login %d %s", w.Code, w.Body.String())
	}
	w = mfaHandlerCall(t, r, "/login", "", gin.H{"username": "admin", "password": "correct-password", "code": codes[0]})
	if w.Code != 401 {
		t.Fatalf("recovery replay %d", w.Code)
	}
	requireNoLoginSession(t, w)
	var successes, failures, recoveries int
	h.DB.QueryRow(`SELECT COUNT(*) FROM account_security_events WHERE event='login_success'`).Scan(&successes)
	h.DB.QueryRow(`SELECT COUNT(*) FROM account_security_events WHERE event='login_failure'`).Scan(&failures)
	h.DB.QueryRow(`SELECT COUNT(*) FROM account_security_events WHERE event='recovery_used'`).Scan(&recoveries)
	if successes != 1 || failures != 3 || recoveries != 1 {
		t.Fatalf("audit success/failure/recovery %d/%d/%d", successes, failures, recoveries)
	}
}

func TestLoginMFAUnavailableCannotFallBackToPassword(t *testing.T) {
	h, r := setupMFAHandler(t)
	codes := enableHandlerMFA(t, h)
	h.MFA = nil
	w := mfaHandlerCall(t, r, "/login", "", gin.H{"username": "admin", "password": "correct-password", "code": codes[0]})
	if w.Code != 503 {
		t.Fatalf("nil MFA allowed password fallback: %d", w.Code)
	}
	requireNoLoginSession(t, w)
	if _, err := h.DB.Exec(`DROP TABLE account_mfa`); err != nil {
		t.Fatal(err)
	}
	w = mfaHandlerCall(t, r, "/login", "", gin.H{"username": "admin", "password": "correct-password"})
	if w.Code != 503 {
		t.Fatalf("schema error allowed password fallback: %d", w.Code)
	}
	requireNoLoginSession(t, w)
}

func TestLoginAuditFailureDoesNotGrantSession(t *testing.T) {
	h, r := setupMFAHandler(t)
	if _, err := h.DB.Exec(`CREATE TRIGGER reject_auth_audit BEFORE INSERT ON account_security_events BEGIN SELECT RAISE(FAIL,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	w := mfaHandlerCall(t, r, "/login", "", gin.H{"username": "admin", "password": "correct-password"})
	if w.Code != 503 {
		t.Fatalf("audit failure login status %d", w.Code)
	}
	requireNoLoginSession(t, w)
}

func TestMFAHandlerConfirmationBoundToSessionAndRevokesOthers(t *testing.T) {
	h, r := setupMFAHandler(t)
	owner := middleware.GlobalSessionStore.Create("admin")
	other := middleware.GlobalSessionStore.Create("admin")
	w := mfaHandlerCall(t, r, "/mfa/setup", owner.Token, gin.H{"current_password": "correct-password"})
	if w.Code != 200 {
		t.Fatalf("setup %d %s", w.Code, w.Body.String())
	}
	var setup struct {
		Data accountsecurity.MFASetup `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	code := mfaTestCode(setup.Data.Secret)
	w = mfaHandlerCall(t, r, "/mfa/confirm", other.Token, gin.H{"current_password": "correct-password", "code": code})
	if w.Code != 409 {
		t.Fatalf("cross-session confirm accepted %d %s", w.Code, w.Body.String())
	}
	if _, err := h.DB.Exec(`CREATE TRIGGER reject_mfa_audit BEFORE INSERT ON account_security_events WHEN NEW.event='mfa_enabled' BEGIN SELECT RAISE(FAIL,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	w = mfaHandlerCall(t, r, "/mfa/confirm", owner.Token, gin.H{"current_password": "correct-password", "code": code})
	if w.Code != 503 || strings.Contains(w.Body.String(), "recovery_codes") {
		t.Fatalf("audit failure returned success/codes: %d %s", w.Code, w.Body.String())
	}
	if enabled, err := accountsecurity.MFAEnabled(context.Background(), h.DB, 1); err != nil || enabled {
		t.Fatal("failed audit committed MFA enrollment")
	}
	if _, err := h.DB.Exec(`DROP TRIGGER reject_mfa_audit`); err != nil {
		t.Fatal(err)
	}
	w = mfaHandlerCall(t, r, "/mfa/confirm", owner.Token, gin.H{"current_password": "correct-password", "code": code})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "recovery_codes") {
		t.Fatalf("confirm %d %s", w.Code, w.Body.String())
	}
	if middleware.GlobalSessionStore.Get(other.Token) != nil || middleware.GlobalSessionStore.Get(owner.Token) == nil {
		t.Fatal("enrollment failed to preserve current/revoke other session")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("recovery response is cacheable")
	}
}

func TestSensitiveCredentialRequiresPasswordAndMFA(t *testing.T) {
	h, r := setupMFAHandler(t)
	codes := enableHandlerMFA(t, h)
	session := middleware.GlobalSessionStore.Create("admin")
	r.POST("/sensitive", middleware.SessionRequired(), middleware.CSRF(), func(c *gin.Context) {
		var req mfaCredentialRequest
		if c.ShouldBindJSON(&req) != nil {
			c.Status(400)
			return
		}
		if h.VerifySensitiveCredential(c, req.CurrentPassword, req.Code) {
			c.Status(204)
		}
	})
	for _, body := range []gin.H{{"current_password": "wrong", "code": codes[0]}, {"current_password": "correct-password"}} {
		w := mfaHandlerCall(t, r, "/sensitive", session.Token, body)
		if w.Code != 401 {
			t.Fatalf("sensitive accepted missing factor: %d", w.Code)
		}
	}
	w := mfaHandlerCall(t, r, "/sensitive", session.Token, gin.H{"current_password": "correct-password", "code": codes[0]})
	if w.Code != 204 {
		t.Fatalf("sensitive proof rejected: %d %s", w.Code, w.Body.String())
	}
}
