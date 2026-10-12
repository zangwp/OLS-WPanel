package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/models"

	"github.com/gin-gonic/gin"
)

type UpdateHandler struct {
	CurrentVersion string
	ConfigPath     string
	Config         *config.Config
}

var panelReleaseCheckCache readCache[*executor.GithubRelease]

func getGithubProxy() string {
	var v string
	database.GetDB().QueryRow("SELECT svalue FROM security_settings WHERE skey = 'github_proxy'").Scan(&v)
	return v
}

func (h *UpdateHandler) Check(c *gin.Context) {
	proxy := getGithubProxy()
	latest, err := panelReleaseCheckCache.get(c.Request.Context(), proxy, c.Query("fresh") == "1", 5*time.Minute, 20*time.Second,
		func(ctx context.Context) (*executor.GithubRelease, error) {
			return executor.FetchLatestPanelReleaseContext(ctx, proxy)
		})
	if err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"current_version": h.CurrentVersion,
			"latest_version":  "",
			"has_update":      false,
			"error":           i18n.TE(c.Request, "settings.update_check_failed"),
		}))
		return
	}

	hasUpdate := executor.CompareVersions(latest.TagName, h.CurrentVersion) > 0
	notes := latest.Body
	if idx := strings.Index(notes, "**Full Changelog**"); idx >= 0 {
		notes = strings.TrimSpace(notes[:idx])
	}
	if notes == "" {
		notes = "（无更新说明）"
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"current_version": h.CurrentVersion,
		"latest_version":  latest.TagName,
		"release_notes":   notes,
		"has_update":      hasUpdate,
	}))
}

func (h *UpdateHandler) Status(c *gin.Context) {
	c.JSON(http.StatusOK, models.SuccessResponse(executor.SnapshotPanelUpdateStatus()))
}

func (h *UpdateHandler) Update(c *gin.Context) {
	latest, err := executor.ExecutePanelUpdate(executor.PanelUpdateOptions{
		Trigger:        "manual",
		CurrentVersion: h.CurrentVersion,
		Proxy:          getGithubProxy(),
		ConfigPath:     h.ConfigPath,
		Config:         h.Config,
		UseWatchdog:    true,
	})
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, executor.ErrPanelOperationsBusy) || errors.Is(err, executor.ErrPanelOperationsClosed) || strings.Contains(err.Error(), "已有更新任务") {
			code = http.StatusConflict
		} else if strings.Contains(err.Error(), "已经是最新版本") || strings.Contains(err.Error(), "仅支持 Linux") {
			code = http.StatusBadRequest
		}
		c.JSON(code, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"message": fmt.Sprintf("正在更新到 %s，面板即将重启并执行健康检查...", latest.TagName),
	}))
}
