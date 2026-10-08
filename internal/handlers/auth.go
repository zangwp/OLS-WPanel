package handlers

import (
	"database/sql"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/zangwp/OLS-WPanel/internal/accountsecurity"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
	"github.com/zangwp/OLS-WPanel/internal/models"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// Keep a successful password-only login from racing enrollment and creating a
// new session after enrollment has revoked the existing unauthenticated ones.
var accountAuthenticationMu sync.Mutex

// LockAccountAuthentication serializes account credential mutations with login.
// Callers defer the returned unlock function and must not call it recursively.
func LockAccountAuthentication() func() {
	accountAuthenticationMu.Lock()
	return accountAuthenticationMu.Unlock
}

func setSessionCookie(c *gin.Context, token string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "wp_session",
		Value:    token,
		MaxAge:   maxAge,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

type AuthHandler struct {
	DB      *sql.DB
	Prefix  string
	Tracker *middleware.LoginAttemptTracker
	MFA     *accountsecurity.MFAService
	Audit   *accountsecurity.AuditService
}

func (h *AuthHandler) Login(c *gin.Context) {
	accountAuthenticationMu.Lock()
	defer accountAuthenticationMu.Unlock()
	c.Header("Cache-Control", "no-store")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if !h.recordLoginFailure(c, req.Username) {
			return
		}
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.TE(c.Request, "auth.provide_credentials")))
		return
	}

	var hash string
	var adminID int64
	err := h.DB.QueryRow(
		"SELECT id, password_hash FROM admin_users WHERE username = ?", req.Username,
	).Scan(&adminID, &hash)

	if err != nil {
		// 防止计时攻击：空跑一次校验
		bcrypt.CompareHashAndPassword([]byte("$2a$12$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa"), []byte(req.Password))
		if !h.recordLoginFailure(c, req.Username) {
			return
		}
		c.JSON(http.StatusUnauthorized, models.ErrorResponse(i18n.TE(c.Request, "auth.invalid_credentials")))
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		if !h.recordLoginFailure(c, req.Username) {
			return
		}
		c.JSON(http.StatusUnauthorized, models.ErrorResponse(i18n.TE(c.Request, "auth.invalid_credentials")))
		return
	}

	enabled, err := accountsecurity.MFAEnabled(c.Request.Context(), h.DB, adminID)
	if err != nil || (enabled && h.MFA == nil) || h.Audit == nil {
		h.mfaError(c, nil)
		return
	}
	if enabled {
		if strings.TrimSpace(req.Code) == "" {
			c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"mfa_required": true}))
			return
		}
		if _, err := h.MFA.Verify(c.Request.Context(), adminID, req.Code, h.mfaAudit(c, req.Username)); err != nil {
			if !h.recordLoginFailure(c, req.Username) {
				return
			}
			h.mfaError(c, err)
			return
		}
	}
	if _, err := h.Audit.Record(c.Request.Context(), h.securityEvent(c, req.Username, "login_success")); err != nil {
		log.Printf("account security: failed to record successful login: %v", err)
		h.mfaError(c, nil)
		return
	}

	if h.Tracker != nil {
		h.Tracker.ClearAttempts(c.ClientIP())
	}

	session := middleware.GlobalSessionStore.CreateWithMetadata(req.Username, c.ClientIP(), c.Request.UserAgent())
	setSessionCookie(c, session.Token, 1800)

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"username": req.Username,
	}))
}

func (h *AuthHandler) Logout(c *gin.Context) {
	token, err := c.Cookie("wp_session")
	if err == nil && token != "" {
		middleware.GlobalSessionStore.Delete(token)
	}
	setSessionCookie(c, "", -1)
	if h.Audit != nil {
		username, _ := c.Get("session_username")
		name, _ := username.(string)
		if _, err := h.Audit.Record(c.Request.Context(), h.securityEvent(c, name, "logout")); err != nil {
			log.Printf("account security: logout audit unavailable: %v", err)
			c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("Signed out; security audit is temporarily unavailable"))
			return
		}
	}
	c.JSON(http.StatusOK, models.SuccessResponse(nil))
}

func (h *AuthHandler) recordLoginFailure(c *gin.Context, username string) bool {
	if h.Tracker != nil {
		h.Tracker.RecordAttempt(c.ClientIP(), "web_login")
	}
	if h.Audit == nil {
		h.mfaError(c, nil)
		return false
	}
	if _, err := h.Audit.Record(c.Request.Context(), h.securityEvent(c, username, "login_failure")); err != nil {
		log.Printf("account security: failed login audit unavailable: %v", err)
		h.mfaError(c, nil)
		return false
	}
	return true
}

func (h *AuthHandler) Check(c *gin.Context) {
	username, exists := c.Get("session_username")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse(i18n.TE(c.Request, "auth.not_logged_in")))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"username": username,
	}))
}

func (h *AuthHandler) CSRFToken(c *gin.Context) {
	token := middleware.GetCSRFToken(c)
	if token == "" {
		var err error
		token, err = c.Cookie("csrf_token")
		if err != nil {
			token = ""
		}
	}
	if token == "" {
		c.JSON(http.StatusOK, models.ErrorResponse(i18n.TE(c.Request, "auth.missing_csrf")))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"token": token,
	}))
}
