package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// All public methods belong to the existing SessionRequired + CSRF protected
// router group. The broker below is reachable only through a private Unix socket.
type WPPanelAccessHandler struct{ Auth *AuthHandler }

var inspectWPPanelAccess = executor.InspectWPPanelAccess
var inspectWPPanelAccessForSettings = executor.InspectWPPanelAccessForSettings
var inspectWPPanelAccessAfterSettings = executor.InspectWPPanelAccessAfterSettings
var applyWPPanelAccessSettings = executor.ApplyWPPanelAccessSettings

func wpPanelAccessResponseError(c *gin.Context, status int, err error) {
	code := executor.WPPanelAccessErrorCode(err)
	known := map[string]bool{"site_unavailable": true, "not_installed": true, "multisite_unsupported": true, "database_mismatch": true, "runtime_unavailable": true, "settings_unavailable": true, "invalid_login_url": true, "invalid_site_url": true, "invalid_suffix": true, "suffix_conflict": true, "unmanaged_bridge": true, "https_required": true, "external_login_control": true, "authentication_plugin": true, "curl_unavailable": true, "broker_unavailable": true, "sso_disabled": true, "bridge_unavailable": true, "administrator_not_found": true, "permalinks_required": true, "confirmation_required": true, "rollback_failed": true, "too_many_administrators": true}
	known["route_unavailable"] = true
	if !known[code] {
		code = "operation_failed"
	}
	c.JSON(status, gin.H{"success": false, "message": i18n.TE(c.Request, "wp_access.error_"+code), "error_code": "wp_access_" + code})
}

func wpPanelAccessNoStore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("Referrer-Policy", "no-referrer")
}

func wpPanelAccessSession(c *gin.Context) (*middleware.Session, bool) {
	token, err := c.Cookie("wp_session")
	if err != nil {
		return nil, false
	}
	session := middleware.GlobalSessionStore.Get(token)
	return session, session != nil && session.Username != "" && session.Username == c.GetString("session_username")
}

func (h *WPPanelAccessHandler) Status(c *gin.Context) {
	wpPanelAccessNoStore(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	c.Request = c.Request.WithContext(ctx)
	site := prepareWPAdministratorSite(c)
	if site == nil {
		return
	}
	if !executor.TryAcquireSiteOpLock(site.ID, "wp_panel_access_inspect") {
		wpPanelAccessResponseError(c, http.StatusConflict, &executor.WPPanelAccessError{Code: "site_unavailable"})
		return
	}
	defer executor.ReleaseSiteOpLock(site.ID)
	status, err := inspectWPPanelAccess(c.Request.Context(), site)
	if err != nil {
		wpPanelAccessResponseError(c, http.StatusUnprocessableEntity, err)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

type wpPanelAccessSaveRequest struct {
	ManualLoginURL  string `json:"manual_login_url" binding:"max=2048"`
	LoginSuffix     string `json:"login_suffix" binding:"max=64"`
	SSOEnabled      bool   `json:"sso_enabled"`
	Confirm         bool   `json:"confirm"`
	CurrentPassword string `json:"current_password" binding:"required,max=256"`
	Code            string `json:"code" binding:"max=128"`
}

func (h *WPPanelAccessHandler) Save(c *gin.Context) {
	wpPanelAccessNoStore(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	c.Request = c.Request.WithContext(ctx)
	site := prepareWPAdministratorSite(c)
	if site == nil {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	var req wpPanelAccessSaveRequest
	if err := c.ShouldBindJSON(&req); err != nil || !req.Confirm {
		wpPanelAccessResponseError(c, http.StatusBadRequest, &executor.WPPanelAccessError{Code: "confirmation_required"})
		return
	}
	if h.Auth == nil {
		wpPanelAccessResponseError(c, http.StatusServiceUnavailable, &executor.WPPanelAccessError{Code: "site_unavailable"})
		return
	}
	if _, ok := wpPanelAccessSession(c); !ok {
		wpPanelAccessResponseError(c, http.StatusUnauthorized, &executor.WPPanelAccessError{Code: "site_unavailable"})
		return
	}
	if !h.Auth.VerifySensitiveCredential(c, req.CurrentPassword, req.Code) {
		return
	}
	req.CurrentPassword = ""
	req.Code = ""
	if !executor.TryAcquireSiteOpLock(site.ID, "wp_panel_access_settings") {
		wpPanelAccessResponseError(c, http.StatusConflict, &executor.WPPanelAccessError{Code: "site_unavailable"})
		return
	}
	defer executor.ReleaseSiteOpLock(site.ID)
	site = prepareWPAdministratorSite(c)
	if site == nil {
		return
	}
	if site.FileLockEnabled {
		c.JSON(http.StatusLocked, models.ErrorResponse(fileLockBlockedMessage))
		return
	}
	if locked, err := executor.SiteMigrationLocked(c.Request.Context(), site.ID, site.Domain); err != nil || locked {
		wpPanelAccessResponseError(c, http.StatusConflict, &executor.WPPanelAccessError{Code: "site_unavailable"})
		return
	}
	before, err := inspectWPPanelAccessForSettings(c.Request.Context(), site, req.LoginSuffix)
	if err != nil {
		wpPanelAccessResponseError(c, http.StatusUnprocessableEntity, err)
		return
	}
	if !before.Installed {
		wpPanelAccessResponseError(c, http.StatusConflict, &executor.WPPanelAccessError{Code: "not_installed"})
		return
	}
	if err := executor.ValidateWPPanelAccessSuffix(req.LoginSuffix); err != nil {
		wpPanelAccessResponseError(c, http.StatusBadRequest, err)
		return
	}
	manualURL, err := executor.ValidateWPPanelAccessURL(site, before.InstallationPath, strings.TrimSpace(req.ManualLoginURL))
	if err != nil {
		wpPanelAccessResponseError(c, http.StatusBadRequest, err)
		return
	}
	if req.LoginSuffix != "" && (before.ExternalLoginControl || before.LoginSource == "plugin") {
		wpPanelAccessResponseError(c, http.StatusConflict, &executor.WPPanelAccessError{Code: "external_login_control"})
		return
	}
	if req.LoginSuffix != "" && !before.PermalinksEnabled {
		wpPanelAccessResponseError(c, http.StatusConflict, &executor.WPPanelAccessError{Code: "permalinks_required"})
		return
	}
	if req.SSOEnabled {
		code := ""
		switch {
		case !site.SSLEnabled || !strings.HasPrefix(before.SiteURL, "https://"):
			code = "https_required"
		case before.ExternalLoginControl:
			code = "external_login_control"
		case len(before.AuthenticationPlugins) != 0:
			code = "authentication_plugin"
		case !before.CurlUnixAvailable:
			code = "curl_unavailable"
		case !executor.WPPanelAccessBrokerAvailable():
			code = "broker_unavailable"
		case len(before.Administrators) == 0:
			code = "administrator_not_found"
		}
		if code != "" {
			wpPanelAccessResponseError(c, http.StatusConflict, &executor.WPPanelAccessError{Code: code})
			return
		}
	}
	rollback, err := applyWPPanelAccessSettings(site, executor.WPPanelAccessSettings{ManualLoginURL: manualURL, LoginSuffix: req.LoginSuffix, SSOEnabled: req.SSOEnabled, InstallationPath: before.InstallationPath})
	if err == nil {
		var after executor.WPPanelAccessStatus
		after, err = inspectWPPanelAccessAfterSettings(c.Request.Context(), site)
		if err == nil && (after.ManualLoginURL != manualURL || after.LoginSuffix != req.LoginSuffix || after.SSOEnabled != req.SSOEnabled || (req.SSOEnabled && !after.SSOAvailable) || (req.LoginSuffix != "" && (!after.BridgeInstalled || after.ExternalLoginControl || !strings.HasSuffix(strings.TrimSuffix(after.DetectedLoginURL, "/"), "/"+req.LoginSuffix)))) {
			err = &executor.WPPanelAccessError{Code: "bridge_unavailable"}
		}
		if err == nil && req.LoginSuffix != "" {
			settings, readErr := executor.ReadWPPanelAccessSettings(site)
			if readErr != nil {
				err = readErr
			} else {
				err = executor.VerifyWPPanelAccessLoginRoute(c.Request.Context(), site, settings)
			}
		}
		if err == nil {
			recordHandlerOperationLog("wp_panel_access_settings", site.Domain, "success", fmt.Sprintf("panel_user=%s; sso=%t; custom_login=%t", c.GetString("session_username"), req.SSOEnabled, req.LoginSuffix != ""))
			c.JSON(http.StatusOK, models.SuccessResponse(after))
			return
		}
	}
	if rollback != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			err = &executor.WPPanelAccessError{Code: "rollback_failed"}
		}
	}
	executor.DefaultWPPanelAccessTokens.Revoke(site.ID, "")
	recordHandlerOperationLog("wp_panel_access_settings", site.Domain, "failed", "error_code="+executor.WPPanelAccessErrorCode(err))
	wpPanelAccessResponseError(c, http.StatusUnprocessableEntity, err)
}

type wpPanelAccessLoginRequest struct {
	AdministratorID int  `json:"administrator_id" binding:"required,min=1"`
	Confirm         bool `json:"confirm"`
}

func (h *WPPanelAccessHandler) Login(c *gin.Context) {
	wpPanelAccessNoStore(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	c.Request = c.Request.WithContext(ctx)
	site := prepareWPAdministratorSite(c)
	if site == nil {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2048)
	var req wpPanelAccessLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil || !req.Confirm {
		wpPanelAccessResponseError(c, http.StatusBadRequest, &executor.WPPanelAccessError{Code: "confirmation_required"})
		return
	}
	session, ok := wpPanelAccessSession(c)
	if !ok || h.Auth == nil {
		wpPanelAccessResponseError(c, http.StatusUnauthorized, &executor.WPPanelAccessError{Code: "site_unavailable"})
		return
	}
	// The panel session was created only after password and any enabled MFA
	// verification. Reuse it for an already-enabled SSO bridge, while still
	// requiring the panel account to exist. Settings changes retain step-up.
	if _, _, _, ok := h.Auth.accountIdentity(c); !ok {
		return
	}
	if !executor.TryAcquireSiteOpLock(site.ID, "wp_panel_access_login") {
		wpPanelAccessResponseError(c, http.StatusConflict, &executor.WPPanelAccessError{Code: "site_unavailable"})
		return
	}
	defer executor.ReleaseSiteOpLock(site.ID)
	site = prepareWPAdministratorSite(c)
	if site == nil {
		return
	}
	if locked, err := executor.SiteMigrationLocked(c.Request.Context(), site.ID, site.Domain); err != nil || locked {
		wpPanelAccessResponseError(c, http.StatusConflict, &executor.WPPanelAccessError{Code: "site_unavailable"})
		return
	}
	status, err := inspectWPPanelAccess(c.Request.Context(), site)
	if err != nil {
		wpPanelAccessResponseError(c, http.StatusUnprocessableEntity, err)
		return
	}
	if !status.SSOAvailable {
		wpPanelAccessResponseError(c, http.StatusConflict, &executor.WPPanelAccessError{Code: status.ReasonCode})
		return
	}
	if !status.SSOEnabled {
		wpPanelAccessResponseError(c, http.StatusConflict, &executor.WPPanelAccessError{Code: "sso_disabled"})
		return
	}
	var administrator executor.WPPanelAccessAdministrator
	for _, user := range status.Administrators {
		if user.ID == req.AdministratorID {
			administrator = user
			break
		}
	}
	if administrator.ID == 0 {
		wpPanelAccessResponseError(c, http.StatusBadRequest, &executor.WPPanelAccessError{Code: "administrator_not_found"})
		return
	}
	settings, err := executor.ReadWPPanelAccessSettings(site)
	if err != nil {
		wpPanelAccessResponseError(c, http.StatusUnprocessableEntity, err)
		return
	}
	uid, err := executor.WPPanelAccessUID(site)
	if err != nil {
		wpPanelAccessResponseError(c, http.StatusUnprocessableEntity, err)
		return
	}
	token, expires, err := executor.DefaultWPPanelAccessTokens.Issue(executor.WPPanelAccessTicket{SiteID: site.ID, SiteIdentity: executor.WPPanelAccessSiteIdentity(site), UID: uid, AdministratorID: administrator.ID, AdministratorLogin: administrator.Login, AdministratorProof: status.AdministratorProofs[administrator.ID], Generation: settings.Generation, SessionToken: session.Token, PanelUsername: session.Username})
	if err != nil {
		wpPanelAccessResponseError(c, http.StatusServiceUnavailable, err)
		return
	}
	// This is always the core index, never the manual override or plugin URL.
	actionURL := "https://" + site.Domain + status.InstallationPath + "/index.php"
	recordHandlerOperationLog("wp_panel_access_login", site.Domain, "success", fmt.Sprintf("stage=authorized; panel_user=%s; administrator_id=%d; expires_in=60", session.Username, administrator.ID))
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"action_url": actionURL, "token": token, "generation": settings.Generation, "expires_at": expires, "expires_in": 60}))
}

func (h *WPPanelAccessHandler) Revoke(c *gin.Context) {
	wpPanelAccessNoStore(c)
	site := prepareWPAdministratorSite(c)
	if site == nil {
		return
	}
	session, ok := wpPanelAccessSession(c)
	if !ok {
		wpPanelAccessResponseError(c, http.StatusUnauthorized, &executor.WPPanelAccessError{Code: "site_unavailable"})
		return
	}
	executor.DefaultWPPanelAccessTokens.Revoke(site.ID, session.Token)
	recordHandlerOperationLog("wp_panel_access_login", site.Domain, "success", "stage=revoked; panel_user="+session.Username)
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"revoked": true}))
}

func StartWPPanelAccessBroker(ctx context.Context) (io.Closer, error) {
	return executor.StartWPPanelAccessBroker(ctx, redeemWPPanelAccessToken)
}

func redeemWPPanelAccessToken(ctx context.Context, token string, siteID, uid int, generation string) (executor.WPPanelAccessGrant, error) {
	ticket, err := executor.DefaultWPPanelAccessTokens.Consume(token, siteID, uid, generation)
	if err != nil {
		return executor.WPPanelAccessGrant{}, err
	}
	if ctx.Err() != nil {
		return executor.WPPanelAccessGrant{}, ctx.Err()
	}
	session := middleware.GlobalSessionStore.Get(ticket.SessionToken)
	if session == nil || session.Username != ticket.PanelUsername {
		return executor.WPPanelAccessGrant{}, errors.New("WordPress login authorization unavailable")
	}
	if !executor.TryAcquireSiteOpLock(siteID, "wp_panel_access_redeem") {
		return executor.WPPanelAccessGrant{}, errors.New("WordPress login authorization unavailable")
	}
	defer executor.ReleaseSiteOpLock(siteID)
	site := getWebsiteByID(siteID)
	if site == nil || site.SiteType != "wordpress" || site.Status != models.StatusActive || !site.SSLEnabled || executor.WPPanelAccessSiteIdentity(site) != ticket.SiteIdentity {
		return executor.WPPanelAccessGrant{}, errors.New("WordPress login authorization unavailable")
	}
	if locked, err := executor.SiteMigrationLocked(ctx, site.ID, site.Domain); err != nil || locked {
		return executor.WPPanelAccessGrant{}, errors.New("WordPress login authorization unavailable")
	}
	currentUID, err := executor.WPPanelAccessUID(site)
	if err != nil || currentUID != uid {
		return executor.WPPanelAccessGrant{}, errors.New("WordPress login authorization unavailable")
	}
	settings, err := executor.ReadWPPanelAccessSettings(site)
	if err != nil || !settings.SSOEnabled || settings.Generation != generation || !executor.WPPanelAccessPluginMatches(site, settings) {
		return executor.WPPanelAccessGrant{}, errors.New("WordPress login authorization unavailable")
	}
	recordHandlerOperationLog("wp_panel_access_login", site.Domain, "success", fmt.Sprintf("stage=redeemed; panel_user=%s; administrator_id=%d", ticket.PanelUsername, ticket.AdministratorID))
	return executor.WPPanelAccessGrant{AdministratorID: ticket.AdministratorID, AdministratorLogin: ticket.AdministratorLogin, AdministratorProof: ticket.AdministratorProof, Domain: site.Domain, InstallationPath: settings.InstallationPath, Generation: generation}, nil
}
