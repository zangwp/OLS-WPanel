package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func (h *WebsiteHandler) SecurityStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("无效的网站ID"))
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Second)
	defer cancel()
	db := database.GetDB()
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("暂时无法检查网站安全状态"))
		return
	}
	site, err := scanWebsite(db.QueryRowContext(ctx, "SELECT "+websiteCols+" FROM websites WHERE id=?", id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, models.ErrorResponse("网站不存在"))
		return
	}
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse("暂时无法检查网站安全状态"))
		return
	}
	report := executor.CollectWebsiteSecurityStatus(ctx, site)
	setSetting := func(key, query string) {
		var enabled int
		err := db.QueryRowContext(ctx, query, id).Scan(&enabled)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			executor.SetWebsiteSecurityCheck(&report, key, "unknown", nil, nil)
			return
		}
		configured := enabled == 1
		state := "disabled"
		if configured {
			state = "configured"
		}
		executor.SetWebsiteSecurityCheck(&report, key, state, &configured, nil)
	}
	setSetting("backup", "SELECT enabled FROM backup_settings WHERE site_id=?")
	if site.SiteType == "wordpress" {
		setSetting("anomaly_monitor", "SELECT enabled FROM site_wp_anomaly_state WHERE site_id=?")
	}
	c.JSON(http.StatusOK, models.SuccessResponse(report))
}
