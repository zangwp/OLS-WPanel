package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// ImageOptimizerHandler validates and exposes batch image optimization jobs
// managed by executor/image_batch_*. The WordPress plugin authenticates through
// pluginSiteByDomain using loopback access and the site API key. The panel has no
// equivalent entry point; progress is shown in WordPress.
type ImageOptimizerHandler struct{}

func (h *ImageOptimizerHandler) PluginStart(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Domain == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("参数错误"))
		return
	}
	site, ok := (&CacheHelperHandler{}).pluginSiteByDomain(req.Domain, c)
	if !ok {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("API Key 无效"))
		return
	}

	jobID, err := executor.StartImageOptimizationJob(site.ID)
	if err != nil {
		if !executor.ImageBatchBinariesReady() {
			c.JSON(http.StatusConflict, models.ErrorResponse("服务器尚未就绪，请稍后重试"))
			return
		}
		if status, statusErr := executor.GetImageOptimizationJobStatus(site.ID); statusErr == nil && status != nil &&
			(status.Status == "queued" || status.Status == "running") {
			// Match the untagged ImageOptimizationJobStatus field names returned by PluginStatus;
			// plugin JavaScript reads capitalized keys such as data.data.Status.
			c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"ID": status.ID, "Status": status.Status}))
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("创建任务失败"))
		return
	}
	c.JSON(http.StatusAccepted, models.SuccessResponse(gin.H{"ID": jobID, "Status": "queued"}))
}

func (h *ImageOptimizerHandler) PluginStatus(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("参数错误"))
		return
	}
	site, ok := (&CacheHelperHandler{}).pluginSiteByDomain(domain, c)
	if !ok {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("API Key 无效"))
		return
	}

	// Lifetime savings and the current job are independent; query both even if one fails.
	lifetimeSaved, err := executor.GetImageOptimizationLifetimeSavedBytes(site.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("查询失败"))
		return
	}

	status, err := executor.GetImageOptimizationJobStatus(site.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("查询失败"))
		return
	}
	if status == nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"Status": "none", "LifetimeBytesSaved": lifetimeSaved}))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(struct {
		*executor.ImageOptimizationJobStatus
		LifetimeBytesSaved int64
	}{status, lifetimeSaved}))
}

func (h *ImageOptimizerHandler) PluginStop(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Domain == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("参数错误"))
		return
	}
	site, ok := (&CacheHelperHandler{}).pluginSiteByDomain(req.Domain, c)
	if !ok {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse("API Key 无效"))
		return
	}
	if err := executor.StopImageOptimizationJob(site.ID); err != nil {
		c.JSON(http.StatusConflict, models.ErrorResponse("没有正在进行的任务"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"status": "stopping"}))
}
