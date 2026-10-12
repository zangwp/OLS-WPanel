package handlers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/microcosm-cc/bluemonday"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/models"

	"github.com/gin-gonic/gin"
)

var (
	announcementCache     string
	announcementFetchedAt time.Time
	announcementMu        sync.RWMutex
	announcementPolicy    = func() *bluemonday.Policy {
		p := bluemonday.UGCPolicy()
		p.AllowAttrs("src", "alt", "width", "height").OnElements("img")
		p.AllowAttrs("target").OnElements("a")
		return p
	}()
)

type DashboardHandler struct {
	resourcesOnce sync.Once
	resources     *siteResourceCache
}

func (h *DashboardHandler) GetStats(c *gin.Context) {
	stats := collectCurrentStats()

	c.JSON(http.StatusOK, models.SuccessResponse(stats))
}

func (h *DashboardHandler) GetMetrics(c *gin.Context) {
	var query models.MetricsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("参数错误: range 必须是 24h、7d 或 15d"))
		return
	}

	history, err := queryMetrics(c.Request.Context(), database.GetDB(), query.Range, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.TE(c.Request, "dashboard.history_load_failed")))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(history))
}

func collectCurrentStats() *models.SystemStats {
	stats := &models.SystemStats{}

	cpu, _ := readCPUPercent()
	memTotal, memUsed, memPercent := readMemoryStats()
	swapTotal, swapUsed := readSwapStats()
	diskTotal, diskUsed := readDiskStats()
	load1, load5, load15 := readLoadAvg()
	uptime := readUptime()

	stats.CPUPercent = cpu
	stats.MemoryPercent = memPercent
	stats.MemoryUsedBytes = memUsed
	stats.MemoryTotalBytes = memTotal
	stats.SwapUsedBytes = swapUsed
	stats.SwapTotalBytes = swapTotal
	stats.DiskTotalBytes = diskTotal
	stats.DiskUsedBytes = diskUsed
	stats.LoadAvg1 = load1
	stats.LoadAvg5 = load5
	stats.LoadAvg15 = load15
	stats.Uptime = uptime

	return stats
}

func formatMetricLabel(ts time.Time, r string) string {
	format := "15:04"
	if r == "7d" {
		format = "01-02 15:04"
	} else if r == "15d" {
		format = "01-02"
	}
	return ts.Local().Format(format)
}

func GetAnnouncement(c *gin.Context) {
	announcementMu.RLock()
	if announcementCache != "" && time.Since(announcementFetchedAt) < 30*time.Minute {
		cache := announcementCache
		announcementMu.RUnlock()
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"content": cache}))
		return
	}
	announcementMu.RUnlock()

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(config.AnnouncementURL)
	if err != nil {
		announcementMu.RLock()
		cache := announcementCache
		announcementMu.RUnlock()
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"content": cache}))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		announcementMu.RLock()
		cache := announcementCache
		announcementMu.RUnlock()
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"content": cache}))
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		announcementMu.RLock()
		cache := announcementCache
		announcementMu.RUnlock()
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"content": cache}))
		return
	}

	announcementMu.Lock()
	announcementCache = announcementPolicy.Sanitize(strings.TrimSpace(string(body)))
	announcementFetchedAt = time.Now()
	cache := announcementCache
	announcementMu.Unlock()

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"content": cache}))
}

func (h *DashboardHandler) GetSiteResources(c *gin.Context) {
	fresh := c.Query("fresh")
	if fresh != "" && fresh != "0" && fresh != "1" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("参数错误: fresh 必须是 0 或 1"))
		return
	}
	h.resourcesOnce.Do(func() {
		if h.resources == nil {
			h.resources = newSiteResourceCache(func(ctx context.Context) ([]siteResource, error) {
				return sampleSiteResources(ctx, database.GetDB(), readSiteProcessOutput)
			})
		}
	})
	snapshot, cached, err := h.resources.get(c.Request.Context(), fresh == "1")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.TE(c.Request, "dashboard.site_resources_load_failed")))
		return
	}
	// Keep data as the existing array; snapshot metadata is additive.
	c.JSON(http.StatusOK, gin.H{
		"success": true, "data": snapshot.Sites,
		"sampled_at": snapshot.SampledAt.Format(time.RFC3339Nano),
		"cached":     cached, "cache_ttl_seconds": int(siteResourceCacheTTL.Seconds()),
	})
}
