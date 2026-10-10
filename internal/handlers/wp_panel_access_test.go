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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func wpAccessHandlerFixture(t *testing.T) (*AuthHandler, *gin.Engine) {
	t.Helper()
	auth, _ := setupMFAHandler(t)
	setupWebsiteSecurityStatusDatabase(t, "wordpress")
	site := getWebsiteByID(1)
	if site == nil {
		t.Fatal("missing website fixture")
	}
	if err := os.WriteFile(filepath.Join(site.WebRoot, "wp-config.php"), []byte("<?php\n$table_prefix = 'wp_';\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetDB().Exec("UPDATE websites SET status='active',ssl_enabled=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	h := &WPPanelAccessHandler{Auth: auth}
	router := gin.New()
	p := router.Group("/api", middleware.SessionRequired(), middleware.CSRF())
	p.GET("/websites/:id/wp-panel-access", h.Status)
	p.POST("/websites/:id/wp-panel-access/login", h.Login)
	p.PUT("/websites/:id/wp-panel-access", h.Save)
	p.POST("/websites/:id/wp-panel-access/revoke", h.Revoke)
	old, oldBefore, oldAfter := inspectWPPanelAccess, inspectWPPanelAccessForSettings, inspectWPPanelAccessAfterSettings
	t.Cleanup(func() {
		inspectWPPanelAccess = old
		inspectWPPanelAccessForSettings = oldBefore
		inspectWPPanelAccessAfterSettings = oldAfter
		executor.DefaultWPPanelAccessTokens.Revoke(0, "")
	})
	return auth, router
}

func TestWPPanelAccessLoginReusesAuthenticatedSessionAndRequiresCSRFConsent(t *testing.T) {
	auth, router := wpAccessHandlerFixture(t)
	enableHandlerMFA(t, auth)
	session := middleware.GlobalSessionStore.Create("admin")
	var inspected int
	inspectWPPanelAccess = func(context.Context, *models.Website) (executor.WPPanelAccessStatus, error) {
		inspected++
		return executor.WPPanelAccessStatus{ReasonCode: "not_installed"}, nil
	}
	// A valid session already represents completed panel authentication,
	// including MFA when enabled. This request needs neither credential.
	body := gin.H{"administrator_id": 7, "confirm": true}
	if response := mfaHandlerCall(t, router, "/api/websites/1/wp-panel-access/login", "", body); response.Code != 401 {
		t.Fatalf("missing session=%d", response.Code)
	}
	revoked := middleware.GlobalSessionStore.Create("admin")
	middleware.GlobalSessionStore.Delete(revoked.Token)
	if response := mfaHandlerCall(t, router, "/api/websites/1/wp-panel-access/login", revoked.Token, body); response.Code != 401 {
		t.Fatalf("revoked session=%d", response.Code)
	}
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/websites/1/wp-panel-access/login", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "wp_session", Value: session.Token})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/api/websites/1/wp-panel-access/login", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", "different-csrf")
	r.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-csrf"})
	r.AddCookie(&http.Cookie{Name: "wp_session", Value: session.Token})
	w = httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("mismatched CSRF=%d", w.Code)
	}
	for _, invalid := range []gin.H{{"administrator_id": 7, "confirm": false}, {"administrator_id": 7}, {"confirm": true}, {"administrator_id": -1, "confirm": true}} {
		response := mfaHandlerCall(t, router, "/api/websites/1/wp-panel-access/login", session.Token, invalid)
		if response.Code != 400 {
			t.Fatalf("invalid administrator/consent=%d %s", response.Code, response.Body.String())
		}
	}
	if inspected != 0 {
		t.Fatal("unverified request reached WordPress")
	}
	response := mfaHandlerCall(t, router, "/api/websites/1/wp-panel-access/login", session.Token, body)
	if response.Code != 409 || !strings.Contains(response.Body.String(), "wp_access_not_installed") || strings.Contains(response.Body.String(), `"token"`) {
		t.Fatalf("uninstalled site authorization=%d %s", response.Code, response.Body.String())
	}
	if inspected != 1 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("uninstalled site did not preserve native installation/no-store semantics")
	}
}

func TestWPPanelAccessLoginRequiresExistingPanelAccount(t *testing.T) {
	auth, router := wpAccessHandlerFixture(t)
	session := middleware.GlobalSessionStore.Create("admin")
	if _, err := auth.DB.Exec("DELETE FROM admin_users WHERE username='admin'"); err != nil {
		t.Fatal(err)
	}
	inspectWPPanelAccess = func(context.Context, *models.Website) (executor.WPPanelAccessStatus, error) {
		t.Fatal("deleted panel account reached WordPress")
		return executor.WPPanelAccessStatus{}, nil
	}
	response := mfaHandlerCall(t, router, "/api/websites/1/wp-panel-access/login", session.Token, gin.H{"administrator_id": 7, "confirm": true})
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), `"token"`) {
		t.Fatalf("deleted account authorization=%d %s", response.Code, response.Body.String())
	}
}

func TestWPPanelAccessLoginRequiresEnabledAvailableSSOAndKnownAdministrator(t *testing.T) {
	_, router := wpAccessHandlerFixture(t)
	session := middleware.GlobalSessionStore.Create("admin")
	for _, test := range []struct {
		name      string
		status    executor.WPPanelAccessStatus
		response  int
		errorCode string
	}{
		{"disabled", executor.WPPanelAccessStatus{SSOAvailable: true}, http.StatusConflict, "sso_disabled"},
		{"unavailable bridge", executor.WPPanelAccessStatus{SSOEnabled: true, ReasonCode: "bridge_unavailable"}, http.StatusConflict, "bridge_unavailable"},
		{"HTTPS required", executor.WPPanelAccessStatus{SSOEnabled: true, ReasonCode: "https_required"}, http.StatusConflict, "https_required"},
		{"unknown administrator", executor.WPPanelAccessStatus{SSOEnabled: true, SSOAvailable: true, Administrators: []executor.WPPanelAccessAdministrator{{ID: 8, Login: "other"}}}, http.StatusBadRequest, "administrator_not_found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inspectWPPanelAccess = func(context.Context, *models.Website) (executor.WPPanelAccessStatus, error) {
				return test.status, nil
			}
			response := mfaHandlerCall(t, router, "/api/websites/1/wp-panel-access/login", session.Token, gin.H{"administrator_id": 7, "confirm": true})
			if response.Code != test.response || !strings.Contains(response.Body.String(), "wp_access_"+test.errorCode) || strings.Contains(response.Body.String(), `"token"`) {
				t.Fatalf("authorization=%d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestWPPanelAccessSaveStillRequiresPasswordAndMFA(t *testing.T) {
	auth, router := wpAccessHandlerFixture(t)
	codes := enableHandlerMFA(t, auth)
	session := middleware.GlobalSessionStore.Create("admin")
	var inspected int
	inspectWPPanelAccessForSettings = func(context.Context, *models.Website, string) (executor.WPPanelAccessStatus, error) {
		inspected++
		return executor.WPPanelAccessStatus{}, nil
	}
	call := func(body gin.H) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPut, "/api/websites/1/wp-panel-access", bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", "test-csrf")
		r.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-csrf"})
		r.AddCookie(&http.Cookie{Name: "wp_session", Value: session.Token})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	for _, test := range []struct {
		body   gin.H
		status int
	}{
		{gin.H{"sso_enabled": true, "confirm": true}, http.StatusBadRequest},
		{gin.H{"current_password": "wrong-password", "code": codes[0], "sso_enabled": true, "confirm": true}, http.StatusUnauthorized},
		{gin.H{"current_password": "correct-password", "sso_enabled": true, "confirm": true}, http.StatusUnauthorized},
		{gin.H{"current_password": "correct-password", "code": "invalid", "sso_enabled": true, "confirm": true}, http.StatusUnauthorized},
		{gin.H{"current_password": "correct-password", "code": codes[0], "sso_enabled": true, "confirm": false}, http.StatusBadRequest},
	} {
		if response := call(test.body); response.Code != test.status {
			t.Fatalf("unverified settings=%d %s", response.Code, response.Body.String())
		}
	}
	if inspected != 0 {
		t.Fatal("unverified settings request reached WordPress")
	}
	// SSO login must not consume a recovery code that is still required by
	// the separate settings operation.
	inspectWPPanelAccess = func(context.Context, *models.Website) (executor.WPPanelAccessStatus, error) {
		return executor.WPPanelAccessStatus{ReasonCode: "not_installed"}, nil
	}
	if response := mfaHandlerCall(t, router, "/api/websites/1/wp-panel-access/login", session.Token, gin.H{"administrator_id": 7, "confirm": true}); response.Code != http.StatusConflict {
		t.Fatalf("session login=%d %s", response.Code, response.Body.String())
	}
	body := gin.H{"current_password": "correct-password", "code": codes[0], "sso_enabled": true, "confirm": true}
	if response := call(body); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "wp_access_not_installed") {
		t.Fatalf("verified settings=%d %s", response.Code, response.Body.String())
	}
	if response := call(body); response.Code != http.StatusUnauthorized {
		t.Fatalf("replayed settings recovery code=%d %s", response.Code, response.Body.String())
	}
	if inspected != 1 {
		t.Fatal("settings step-up did not retain one-use MFA verification")
	}
}

func TestWPPanelAccessRequestsBoundWholeOperationBeforeEnteringPHP(t *testing.T) {
	_, router := wpAccessHandlerFixture(t)
	session := middleware.GlobalSessionStore.Create("admin")
	assertBudget := func(ctx context.Context, limit time.Duration) {
		t.Helper()
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > limit || time.Until(deadline) <= 0 {
			t.Fatalf("unbounded request reaching PHP: deadline=%v available=%t", deadline, ok)
		}
	}
	inspectWPPanelAccess = func(ctx context.Context, _ *models.Website) (executor.WPPanelAccessStatus, error) {
		assertBudget(ctx, 15*time.Second)
		return executor.WPPanelAccessStatus{ReasonCode: "not_installed"}, nil
	}
	inspectWPPanelAccessForSettings = func(ctx context.Context, _ *models.Website, _ string) (executor.WPPanelAccessStatus, error) {
		assertBudget(ctx, 25*time.Second)
		return executor.WPPanelAccessStatus{ReasonCode: "not_installed"}, nil
	}
	for _, test := range []struct {
		method, path string
		body         gin.H
		status       int
	}{
		{http.MethodGet, "/api/websites/1/wp-panel-access", nil, http.StatusOK},
		{http.MethodPost, "/api/websites/1/wp-panel-access/login", gin.H{"administrator_id": 7, "confirm": true}, http.StatusConflict},
		{http.MethodPut, "/api/websites/1/wp-panel-access", gin.H{"current_password": "correct-password", "confirm": true}, http.StatusConflict},
	} {
		body, _ := json.Marshal(test.body)
		r := httptest.NewRequest(test.method, test.path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", "test-csrf")
		r.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-csrf"})
		r.AddCookie(&http.Cookie{Name: "wp_session", Value: session.Token})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%s budget check status=%d %s", test.method, w.Code, w.Body.String())
		}
	}
}

func TestWPPanelAccessSaveRefusesExternalLoginControlWithoutMutation(t *testing.T) {
	_, router := wpAccessHandlerFixture(t)
	session := middleware.GlobalSessionStore.Create("admin")
	inspectWPPanelAccessForSettings = func(context.Context, *models.Website, string) (executor.WPPanelAccessStatus, error) {
		return executor.WPPanelAccessStatus{Installed: true, SiteURL: "https://example.com", ExternalLoginControl: true, LoginSource: "plugin", PermalinksEnabled: true}, nil
	}
	old := applyWPPanelAccessSettings
	t.Cleanup(func() { applyWPPanelAccessSettings = old })
	mutated := false
	applyWPPanelAccessSettings = func(*models.Website, executor.WPPanelAccessSettings) (func() error, error) {
		mutated = true
		return nil, nil
	}
	raw, _ := json.Marshal(gin.H{"login_suffix": "staff-signin", "sso_enabled": false, "current_password": "correct-password", "confirm": true})
	r := httptest.NewRequest(http.MethodPut, "/api/websites/1/wp-panel-access", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", "test-csrf")
	r.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-csrf"})
	r.AddCookie(&http.Cookie{Name: "wp_session", Value: session.Token})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, r)
	if response.Code != 409 || mutated || !strings.Contains(response.Body.String(), "wp_access_external_login_control") {
		t.Fatalf("external plugin settings=%d mutation=%t %s", response.Code, mutated, response.Body.String())
	}
}

func TestWPPanelAccessRedeemRejectsLoggedOutSessionAndConsumesTicket(t *testing.T) {
	_, _ = wpAccessHandlerFixture(t)
	session := middleware.GlobalSessionStore.Create("admin")
	ticket := executor.WPPanelAccessTicket{SiteID: 1, UID: 1008, AdministratorID: 7, AdministratorLogin: "admin", AdministratorProof: strings.Repeat("b", 64), SiteIdentity: "test-site", SessionToken: session.Token, PanelUsername: "admin", Generation: strings.Repeat("a", 32)}
	token, _, err := executor.DefaultWPPanelAccessTokens.Issue(ticket)
	if err != nil {
		t.Fatal(err)
	}
	middleware.GlobalSessionStore.Delete(session.Token)
	if _, err := redeemWPPanelAccessToken(context.Background(), token, 1, 1008, ticket.Generation); err == nil {
		t.Fatal("logged-out session authorized WordPress")
	}
	if _, err := executor.DefaultWPPanelAccessTokens.Consume(token, 1, 1008, ticket.Generation); err == nil {
		t.Fatal("failed authorization remained replayable")
	}
}
