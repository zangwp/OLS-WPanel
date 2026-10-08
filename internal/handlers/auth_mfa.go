package handlers

import (
	"database/sql"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/accountsecurity"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func (h *AuthHandler) securityEvent(c *gin.Context, username, event string) accountsecurity.Event {
	return accountsecurity.Event{Username: username, Event: event, IP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

func (h *AuthHandler) mfaAudit(c *gin.Context, username string) accountsecurity.MFAAudit {
	return func(tx *sql.Tx, event string) error {
		if h.Audit == nil {
			return errors.New("security audit unavailable")
		}
		_, err := h.Audit.RecordTx(c.Request.Context(), tx, h.securityEvent(c, username, event))
		return err
	}
}

func (h *AuthHandler) mfaError(c *gin.Context, err error) {
	status, code, message := http.StatusServiceUnavailable, "mfa_unavailable", "Account security is temporarily unavailable"
	switch {
	case errors.Is(err, accountsecurity.ErrInvalidCode):
		status, code, message = http.StatusUnauthorized, "mfa_invalid_code", "Verification code is invalid or already used"
	case errors.Is(err, accountsecurity.ErrInvalidPassword):
		status, code, message = http.StatusUnauthorized, "mfa_invalid_password", "Current password is incorrect"
	case errors.Is(err, accountsecurity.ErrMFARateLimited):
		status, code, message = http.StatusTooManyRequests, "mfa_rate_limited", "Too many attempts; wait five minutes before trying again"
	case errors.Is(err, accountsecurity.ErrMFAEnabled):
		status, code, message = http.StatusConflict, "mfa_already_enabled", "Two-factor authentication is already enabled"
	case errors.Is(err, accountsecurity.ErrMFADisabled):
		status, code, message = http.StatusConflict, "mfa_not_enabled", "Two-factor authentication is not enabled"
	case errors.Is(err, accountsecurity.ErrPendingExpired):
		status, code, message = http.StatusConflict, "mfa_setup_expired", "Setup expired or belongs to another session; start again"
	}
	if status == http.StatusTooManyRequests {
		c.Header("Retry-After", "300")
	}
	message = i18n.TE(c.Request, "account_security."+code)
	c.JSON(status, gin.H{"success": false, "message": message, "error_code": code})
}

func (h *AuthHandler) accountIdentity(c *gin.Context) (int64, string, string, bool) {
	value, _ := c.Get("session_username")
	username, _ := value.(string)
	token, cookieErr := c.Cookie("wp_session")
	session := middleware.GlobalSessionStore.Get(token)
	if username == "" || cookieErr != nil || session == nil || session.Username != username {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse(i18n.TE(c.Request, "auth.not_logged_in")))
		return 0, "", "", false
	}
	var id int64
	var hash string
	if err := h.DB.QueryRowContext(c.Request.Context(), `SELECT id,password_hash FROM admin_users WHERE username=?`, username).Scan(&id, &hash); err != nil {
		h.mfaError(c, nil)
		return 0, "", "", false
	}
	return id, username, hash, true
}

func (h *AuthHandler) passwordForSensitive(c *gin.Context, password string) (int64, string, bool) {
	if h.MFA == nil || h.Audit == nil {
		h.mfaError(c, nil)
		return 0, "", false
	}
	id, username, hash, ok := h.accountIdentity(c)
	if !ok {
		return 0, "", false
	}
	if err := h.MFA.CheckSensitivePassword(c.Request.Context(), id, hash, password); err != nil {
		if h.Tracker != nil {
			h.Tracker.RecordAttempt(c.ClientIP(), "web_login")
		}
		h.mfaError(c, err)
		return 0, "", false
	}
	return id, username, true
}

// VerifySensitiveCredential is shared by credential changes and session tools.
// It always rechecks the current password, and consumes an MFA/recovery code
// when enabled. A session alone cannot change account protection settings.
func (h *AuthHandler) VerifySensitiveCredential(c *gin.Context, password, code string) bool {
	id, username, ok := h.passwordForSensitive(c, password)
	if !ok {
		return false
	}
	enabled, err := accountsecurity.MFAEnabled(c.Request.Context(), h.DB, id)
	if err != nil {
		h.mfaError(c, nil)
		return false
	}
	if enabled {
		if _, err = h.MFA.Verify(c.Request.Context(), id, code, h.mfaAudit(c, username)); err != nil {
			if h.Tracker != nil {
				h.Tracker.RecordAttempt(c.ClientIP(), "web_login")
			}
			h.mfaError(c, err)
			return false
		}
		h.dispatchSecurityNotifications(c)
	}
	return true
}

func (h *AuthHandler) MFAStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if h.MFA == nil {
		h.mfaError(c, nil)
		return
	}
	id, _, _, ok := h.accountIdentity(c)
	if !ok {
		return
	}
	status, err := h.MFA.Status(c.Request.Context(), id)
	if err != nil {
		h.mfaError(c, err)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

type mfaCredentialRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,max=256"`
	Code            string `json:"code" binding:"max=128"`
}

func (h *AuthHandler) mfaRequest(c *gin.Context) (mfaCredentialRequest, int64, string, bool) {
	c.Header("Cache-Control", "no-store")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	var req mfaCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.TE(c.Request, "auth.invalid_security_request")))
		return req, 0, "", false
	}
	id, username, ok := h.passwordForSensitive(c, req.CurrentPassword)
	return req, id, username, ok
}

func (h *AuthHandler) MFASetup(c *gin.Context) {
	accountAuthenticationMu.Lock()
	defer accountAuthenticationMu.Unlock()
	_, id, username, ok := h.mfaRequest(c)
	if !ok {
		return
	}
	token, _ := c.Cookie("wp_session")
	setup, err := h.MFA.Setup(c.Request.Context(), id, token, username)
	if err != nil {
		h.mfaError(c, err)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(setup))
}

func (h *AuthHandler) MFAConfirm(c *gin.Context) {
	accountAuthenticationMu.Lock()
	defer accountAuthenticationMu.Unlock()
	req, id, username, ok := h.mfaRequest(c)
	if !ok {
		return
	}
	token, _ := c.Cookie("wp_session")
	codes, err := h.MFA.Confirm(c.Request.Context(), id, token, req.Code, h.mfaAudit(c, username))
	if err != nil {
		h.mfaMutationError(c, err)
		return
	}
	h.finishMFAMutation(c, username)
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"enabled": true, "recovery_codes": codes}))
}

func (h *AuthHandler) MFADisable(c *gin.Context) {
	accountAuthenticationMu.Lock()
	defer accountAuthenticationMu.Unlock()
	req, id, username, ok := h.mfaRequest(c)
	if !ok {
		return
	}
	if err := h.MFA.Disable(c.Request.Context(), id, req.Code, h.mfaAudit(c, username)); err != nil {
		h.mfaMutationError(c, err)
		return
	}
	h.finishMFAMutation(c, username)
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"enabled": false}))
}

func (h *AuthHandler) MFARecoveryCodes(c *gin.Context) {
	accountAuthenticationMu.Lock()
	defer accountAuthenticationMu.Unlock()
	req, id, username, ok := h.mfaRequest(c)
	if !ok {
		return
	}
	codes, err := h.MFA.Regenerate(c.Request.Context(), id, req.Code, h.mfaAudit(c, username))
	if err != nil {
		h.mfaMutationError(c, err)
		return
	}
	h.finishMFAMutation(c, username)
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"enabled": true, "recovery_codes": codes}))
}

func (h *AuthHandler) mfaMutationError(c *gin.Context, err error) {
	if errors.Is(err, accountsecurity.ErrInvalidCode) && h.Tracker != nil {
		h.Tracker.RecordAttempt(c.ClientIP(), "web_login")
	}
	h.mfaError(c, err)
}

func (h *AuthHandler) finishMFAMutation(c *gin.Context, username string) {
	token, _ := c.Cookie("wp_session")
	middleware.GlobalSessionStore.DeleteOthers(username, token)
	h.dispatchSecurityNotifications(c)
}

func (h *AuthHandler) dispatchSecurityNotifications(c *gin.Context) {
	if h.Audit != nil {
		if err := h.Audit.DispatchPending(c.Request.Context()); err != nil {
			// The state and audit already committed. Never discard the only copy
			// of freshly generated recovery codes because delivery is delayed.
			log.Printf("account security: notification delivery pending: %v", err)
		}
	}
}
