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

func (h *WebsiteHandler) RetireOptimizer(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("无效的网站 ID"))
		return
	}
	site := getWebsiteByID(id)
	if site == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("网站不存在"))
		return
	}
	if !executor.TryAcquireSiteOpLock(id, "optimizer_retire") {
		c.JSON(http.StatusConflict, models.ErrorResponse("网站正在执行其他操作，请稍后重试"))
		return
	}
	defer executor.ReleaseSiteOpLock(id)
	site = getWebsiteByID(id)
	if site == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse("网站不存在"))
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()
	archive, err := executor.RetireOptimizerOwned(ctx, config.AppConfig, site)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"archive": archive}))
}
