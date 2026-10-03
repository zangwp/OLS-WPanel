package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/database"
	"github.com/zangwp/OLS-WPanel/executor"
	"github.com/zangwp/OLS-WPanel/models"
)

func (h *WebsiteHandler) SSLRenewal(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid website ID"))
		return
	}
	site := getWebsiteByID(id)
	if site == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("Website not found"))
		return
	}
	if c.Request.Method == http.MethodPut {
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if c.ShouldBindJSON(&req) != nil || req.Enabled == nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("enabled is required"))
			return
		}
		if !executor.TryAcquireSiteOpLock(id, "ssl_renewal_settings") {
			c.JSON(http.StatusConflict, models.ErrorResponse("Website maintenance is in progress"))
			return
		}
		defer executor.ReleaseSiteOpLock(id)
		site = getWebsiteByID(id)
		if site == nil || !site.SSLEnabled || site.SSLCertSource != "auto" {
			c.JSON(http.StatusConflict, models.ErrorResponse("Automatic renewal requires an automatically issued certificate"))
			return
		}
		if _, err := database.GetDB().Exec(`INSERT INTO site_ssl_renewal(site_id,enabled) VALUES(?,?) ON CONFLICT(site_id) DO UPDATE SET enabled=excluded.enabled`, id, *req.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("Cannot save renewal setting"))
			return
		}
	}
	enabled, err := database.SiteSSLRenewalEnabled(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Cannot read renewal setting"))
		return
	}
	var lastAttempt, lastStatus string
	if err := database.GetDB().QueryRow(`SELECT COALESCE((SELECT last_attempt FROM site_ssl_renewal WHERE site_id=?),''),COALESCE((SELECT last_status FROM site_ssl_renewal WHERE site_id=?),'')`, id, id).Scan(&lastAttempt, &lastStatus); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Cannot read renewal history"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"enabled": enabled, "eligible": site.SSLEnabled && site.SSLCertSource == "auto", "last_attempt": lastAttempt, "last_status": lastStatus}))
}
