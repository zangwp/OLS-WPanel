package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/accountsecurity"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
	_ "modernc.org/sqlite"
)

func sessionHandlerFixture(t *testing.T) (*AuthHandler, *gin.Engine, *middleware.Session, *middleware.Session) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := accountsecurity.InitAuditSchema(db); err != nil {
		t.Fatal(err)
	}
	audit := accountsecurity.NewAuditService(db)
	original := middleware.GlobalSessionStore
	middleware.GlobalSessionStore = &middleware.SessionStore{}
	t.Cleanup(func() { audit.Close(); db.Close(); middleware.GlobalSessionStore = original })
	current := middleware.GlobalSessionStore.Create("admin")
	foreign := middleware.GlobalSessionStore.Create("foreign")
	h := &AuthHandler{DB: db, Audit: audit}
	r := gin.New()
	r.Use(middleware.SessionRequired())
	r.GET("/sessions", h.ListSessions)
	r.DELETE("/sessions/:id", h.RevokeSession)
	r.POST("/sessions/revoke-others", h.RevokeOtherSessions)
	r.GET("/audit", h.AuditLog)
	return h, r, current, foreign
}

func sessionRequest(r http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: "wp_session", Value: token})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAuthSessionHandlersScopeIDsAndNeverReturnTokens(t *testing.T) {
	_, router, current, foreign := sessionHandlerFixture(t)
	other := middleware.GlobalSessionStore.Create("admin")
	w := sessionRequest(router, "GET", "/sessions", current.Token)
	if w.Code != 200 || strings.Contains(w.Body.String(), current.Token) || strings.Contains(w.Body.String(), other.Token) || strings.Contains(w.Body.String(), foreign.ID) {
		t.Fatalf("unsafe session list %s", w.Body.String())
	}
	if !json.Valid(w.Body.Bytes()) {
		t.Fatal("invalid response")
	}
	w = sessionRequest(router, "DELETE", "/sessions/"+foreign.ID, current.Token)
	if w.Code != 404 || middleware.GlobalSessionStore.Get(foreign.Token) == nil {
		t.Fatal("foreign session revocation permitted")
	}
	w = sessionRequest(router, "DELETE", "/sessions/"+other.ID, current.Token)
	if w.Code != 200 || middleware.GlobalSessionStore.Get(other.Token) != nil {
		t.Fatal("own other session revocation failed")
	}
	w = sessionRequest(router, "DELETE", "/sessions/"+current.ID, current.Token)
	if w.Code != 200 || middleware.GlobalSessionStore.Get(current.Token) != nil {
		t.Fatal("current revocation failed")
	}
	if len(w.Result().Cookies()) < 1 {
		t.Fatal("current session cookie not cleared")
	}
}

func TestAuthSessionAuditFailurePreventsUnrecordedRevocation(t *testing.T) {
	h, router, current, _ := sessionHandlerFixture(t)
	other := middleware.GlobalSessionStore.Create("admin")
	if _, err := h.DB.ExecContext(context.Background(), `DROP TABLE account_security_events`); err != nil {
		t.Fatal(err)
	}
	w := sessionRequest(router, "POST", "/sessions/revoke-others", current.Token)
	if w.Code != 503 || middleware.GlobalSessionStore.Get(other.Token) == nil {
		t.Fatal("unrecorded revocation reported success")
	}
	w = sessionRequest(router, "GET", "/audit", current.Token)
	if w.Code != 503 {
		t.Fatal("database error reported as empty history")
	}
}

func TestAuthSessionRevocationRechecksSessionAfterMiddleware(t *testing.T) {
	h, router, current, _ := sessionHandlerFixture(t)
	other := middleware.GlobalSessionStore.Create("admin")
	// Represent a concurrent credential change after middleware authenticated
	// this request, before the sensitive handler acquires the account lock.
	router.POST("/revoked-in-flight", func(c *gin.Context) { middleware.GlobalSessionStore.Delete(current.Token) }, h.RevokeOtherSessions)
	w := sessionRequest(router, "POST", "/revoked-in-flight", current.Token)
	if w.Code != http.StatusUnauthorized || middleware.GlobalSessionStore.Get(other.Token) == nil {
		t.Fatal("revoked request still changed other sessions")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("sensitive response is cacheable")
	}
}
