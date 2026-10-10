package handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/cloudflaresecurity"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var newCloudflareSecurityService = cloudflaresecurity.NewService

func cloudflareSecurityID(c *gin.Context) (int, bool) {
	c.Header("Cache-Control", "no-store")
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "无效的网站 ID", "error_code": "cloudflare_security_invalid"})
		return 0, false
	}
	return id, true
}
func cloudflareSecurityError(c *gin.Context, err error) {
	status, code := http.StatusBadRequest, "cloudflare_security_failed"
	if errors.Is(err, cloudflaresecurity.ErrNotFound) {
		status, code = http.StatusNotFound, "cloudflare_security_not_found"
	}
	c.JSON(status, gin.H{"success": false, "message": err.Error(), "error_code": code})
}
func (h *WebsiteHandler) GetCloudflareSecurity(c *gin.Context) {
	id, ok := cloudflareSecurityID(c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	result, err := newCloudflareSecurityService(database.GetDB()).Get(ctx, id)
	if err != nil {
		cloudflareSecurityError(c, err)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(result))
}
func (h *WebsiteHandler) SaveCloudflareSecurity(c *gin.Context) {
	id, ok := cloudflareSecurityID(c)
	if !ok {
		return
	}
	var input cloudflaresecurity.Update
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Cloudflare 设置格式错误", "error_code": "cloudflare_security_invalid"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	result, err := newCloudflareSecurityService(database.GetDB()).Save(ctx, id, input)
	if err != nil {
		cloudflareSecurityError(c, err)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(result))
}
func (h *WebsiteHandler) TestCloudflareSecurity(c *gin.Context) {
	id, ok := cloudflareSecurityID(c)
	if !ok {
		return
	}
	var input cloudflaresecurity.Update
	var candidate *cloudflaresecurity.Update
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	if err := c.ShouldBindJSON(&input); err == nil {
		candidate = &input
	} else if !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Cloudflare 设置格式错误", "error_code": "cloudflare_security_invalid"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	result, err := newCloudflareSecurityService(database.GetDB()).TestUpdate(ctx, id, candidate)
	if err != nil {
		cloudflareSecurityError(c, err)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(result))
}
func (h *WebsiteHandler) SyncCloudflareSecurity(c *gin.Context) {
	id, ok := cloudflareSecurityID(c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	// A deleted site may still have a remote rule pending cleanup; only the
	// background reconciler can operate on that orphan.
	service := newCloudflareSecurityService(database.GetDB())
	if _, err := service.Get(ctx, id); err != nil {
		cloudflareSecurityError(c, err)
		return
	}
	result, err := service.Sync(ctx, id)
	if err != nil {
		cloudflareSecurityError(c, err)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(result))
}
