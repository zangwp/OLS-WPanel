package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/accountsecurity"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func sessionIdentity(c *gin.Context) (string, string, bool) {
	c.Header("Cache-Control", "no-store")
	username := c.GetString("session_username")
	token, err := c.Cookie("wp_session")
	if username == "" || err != nil || token == "" {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse(i18n.TE(c.Request, "auth.not_logged_in")))
		return "", "", false
	}
	session := middleware.GlobalSessionStore.Get(token)
	if session == nil || session.Username != username {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse(i18n.TE(c.Request, "auth.not_logged_in")))
		return "", "", false
	}
	return username, token, true
}

func accountSecurityUnavailable(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, models.ErrorResponse(i18n.TE(c.Request, "auth.account_security_unavailable")))
}

func requestAuditEvent(c *gin.Context, username, event string) accountsecurity.Event {
	return accountsecurity.Event{Username: username, Event: event, IP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

func (h *AuthHandler) ListSessions(c *gin.Context) {
	username, token, ok := sessionIdentity(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"sessions": middleware.GlobalSessionStore.List(username, token)}))
}

func (h *AuthHandler) RevokeSession(c *gin.Context) {
	unlock := LockAccountAuthentication()
	defer unlock()
	username, token, ok := sessionIdentity(c)
	if !ok {
		return
	}
	id := c.Param("id")
	var target *middleware.SessionSummary
	for _, session := range middleware.GlobalSessionStore.List(username, token) {
		if session.ID == id {
			copy := session
			target = &copy
			break
		}
	}
	if target == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse(i18n.TE(c.Request, "auth.session_not_found")))
		return
	}
	event := requestAuditEvent(c, username, "session_revoked")
	event.TargetID = id
	if _, err := h.Audit.Record(c.Request.Context(), event); err != nil {
		accountSecurityUnavailable(c)
		return
	}
	middleware.GlobalSessionStore.DeleteByID(username, id)
	if target.Current {
		setSessionCookie(c, "", -1)
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"revoked": true, "current": target.Current}))
}

func (h *AuthHandler) RevokeOtherSessions(c *gin.Context) {
	unlock := LockAccountAuthentication()
	defer unlock()
	username, token, ok := sessionIdentity(c)
	if !ok {
		return
	}
	if _, err := h.Audit.Record(c.Request.Context(), requestAuditEvent(c, username, "sessions_revoked")); err != nil {
		accountSecurityUnavailable(c)
		return
	}
	count := middleware.GlobalSessionStore.DeleteOthers(username, token)
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"revoked": count}))
}

func (h *AuthHandler) AuditLog(c *gin.Context) {
	username, _, ok := sessionIdentity(c)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	result, err := h.Audit.List(c.Request.Context(), username, page, pageSize)
	if err != nil {
		accountSecurityUnavailable(c)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(result))
}

func (h *AuthHandler) GetSecurityNotifications(c *gin.Context) {
	username, _, ok := sessionIdentity(c)
	if !ok {
		return
	}
	enabled, err := h.Audit.NotificationsEnabled(c.Request.Context(), username)
	if err != nil {
		accountSecurityUnavailable(c)
		return
	}
	smtp, webhook, err := executor.AccountSecurityNotificationChannels(c.Request.Context(), h.DB)
	if err != nil {
		accountSecurityUnavailable(c)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"enabled": enabled, "smtp_configured": smtp, "webhook_configured": webhook}))
}

func (h *AuthHandler) SetSecurityNotifications(c *gin.Context) {
	unlock := LockAccountAuthentication()
	defer unlock()
	username, _, ok := sessionIdentity(c)
	if !ok {
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.TE(c.Request, "auth.invalid_security_request")))
		return
	}
	if err := h.Audit.SetNotificationsEnabled(c.Request.Context(), username, *req.Enabled, requestAuditEvent(c, username, "notifications_changed")); err != nil {
		accountSecurityUnavailable(c)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"enabled": *req.Enabled}))
}
