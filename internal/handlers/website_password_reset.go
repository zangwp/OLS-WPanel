package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// SetPasswordResetMode applies allow/all/admin protection through a managed
// mu-plugin in wp-content/mu-plugins; the database records the current mode.
func (h *WebsiteHandler) SetPasswordResetMode(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.TE(c.Request, "website.invalid_site_id")))
		return
	}
	site := getWebsiteByID(id)
	if site == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse(i18n.TE(c.Request, "website.not_found")))
		return
	}
	if site.SiteType != "wordpress" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.TE(c.Request, "website.password_reset_wordpress_only")))
		return
	}
	if site.FileLockEnabled {
		c.JSON(http.StatusLocked, models.ErrorResponse(fileLockBlockedMessage))
		return
	}

	var req struct {
		Mode string `json:"mode"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.TE(c.Request, "common.invalid_params")))
		return
	}
	mode, err := executor.ValidatePasswordResetMode(req.Mode)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.TE(c.Request, "website.password_reset_invalid_mode")))
		return
	}
	if !executor.TryAcquireSiteOpLock(id, "wp_password_reset") {
		c.JSON(http.StatusConflict, models.ErrorResponse(i18n.TE(c.Request, "maintenance.operation_unavailable")))
		return
	}
	defer executor.ReleaseSiteOpLock(id)
	site = getWebsiteByID(id)
	if site == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse(i18n.TE(c.Request, "website.not_found")))
		return
	}
	if site.FileLockEnabled {
		c.JSON(http.StatusLocked, models.ErrorResponse(fileLockBlockedMessage))
		return
	}
	if locked, lockErr := executor.SiteMigrationLocked(c.Request.Context(), site.ID, site.Domain); lockErr != nil || locked {
		c.JSON(http.StatusConflict, models.ErrorResponse(i18n.TE(c.Request, "maintenance.operation_unavailable")))
		return
	}

	// Re-read the committed mode under the lock. The earlier site snapshot may be
	// stale after a concurrent request; rollback must match the current database state.
	var prevMode string
	if err := database.GetDB().QueryRow(
		"SELECT COALESCE(password_reset_mode, 'allow') FROM websites WHERE id = ?", id,
	).Scan(&prevMode); err != nil {
		recordHandlerOperationLog("wp_password_reset", site.Domain, "failed", err.Error())
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.TE(c.Request, "website.password_reset_save_failed")))
		return
	}
	if mode == prevMode {
		matches, matchErr := executor.WPPasswordResetModeMatches(site.WebRoot, mode)
		if matchErr == nil && matches {
			c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": i18n.TE(c.Request, "website.password_reset_saved"), "password_reset_mode": mode}))
			return
		}
	}

	// rollbackToPrev restores the mu-plugin to the committed database mode.
	rollbackToPrev := func(reason string) bool {
		if rbErr := executor.ApplyWPPasswordResetMode(site.WebRoot, site.SystemUser, prevMode); rbErr != nil {
			recordHandlerOperationLog("wp_password_reset", site.Domain, "failed",
				fmt.Sprintf("%s; rollback also failed: %v", reason, rbErr))
			return false
		} else {
			recordHandlerOperationLog("wp_password_reset", site.Domain, "failed", reason)
			return true
		}
	}

	if err := executor.ApplyWPPasswordResetMode(site.WebRoot, site.SystemUser, mode); err != nil {
		// Apply may write the new mode before failing (for example, on chown).
		// Restore the committed mode so disk and database stay consistent.
		if !rollbackToPrev(fmt.Sprintf("apply failed: %v", err)) {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("保存失败且恢复原策略也失败，请立即检查密码找回策略文件"))
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.TE(c.Request, "website.password_reset_save_failed")))
		return
	}

	if _, err := database.GetDB().Exec(
		"UPDATE websites SET password_reset_mode = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		mode, id,
	); err != nil {
		// Roll back the mu-plugin if the database write fails.
		if !rollbackToPrev(fmt.Sprintf("save failed: %v", err)) {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("数据库保存失败且恢复原策略也失败，请立即检查密码找回策略文件"))
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.TE(c.Request, "website.password_reset_save_failed")))
		return
	}

	recordHandlerOperationLog("wp_password_reset", site.Domain, "success", "密码找回保护="+mode)
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"message":             i18n.TE(c.Request, "website.password_reset_saved"),
		"password_reset_mode": mode,
	}))
}
