package handlers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/config"
	"github.com/zangwp/OLS-WPanel/executor"
	"github.com/zangwp/OLS-WPanel/models"
)

func (h *WebsiteHandler) MigrateLiteSpeedCacheSettings(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid site"))
		return
	}
	if !executor.TryAcquireSiteOpLock(id, "cache_settings_migration") {
		c.JSON(http.StatusConflict, models.ErrorResponse("Site operation is busy"))
		return
	}
	defer executor.ReleaseSiteOpLock(id)
	site := getWebsiteByID(id)
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Minute)
	defer cancel()
	if err := executor.MigrateLiteSpeedCacheSettings(ctx, config.AppConfig, site); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"migrated": true}))
}
