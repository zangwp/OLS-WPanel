package executor

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/zangwp/OLS-WPanel/config"
	"github.com/zangwp/OLS-WPanel/database"
	"github.com/zangwp/OLS-WPanel/models"
)

var nginxCustomDir = "/www/ols-wpanel/nginx-custom"

var (
	persistAccessLogMode = saveAccessLogMode
	applyAccessLogNginx  = func(engine *TemplateEngine, content, targetPath, enabledPath string) error {
		return engine.ApplyNginxConfig(content, targetPath, enabledPath)
	}
	persistDocumentRoot    = saveDocumentRoot
	applyDocumentRootNginx = func(engine *TemplateEngine, content, targetPath, enabledPath string) error {
		return engine.ApplyNginxConfig(content, targetPath, enabledPath)
	}
)

func executeSaveNginxCustom(task *Task) TaskResult {
	if _, ok := task.Payload.(*SaveNginxCustomPayload); !ok {
		return TaskResult{Success: false, Message: "任务参数类型错误"}
	}
	return TaskResult{Success: false, Message: "OpenLiteSpeed v1.0.0 不支持旧版 Nginx 自定义配置"}
}

func executeSetAccessLogMode(task *Task) TaskResult {
	payload, ok := task.Payload.(*SetAccessLogModePayload)
	if !ok {
		return TaskResult{Success: false, Message: "任务参数类型错误"}
	}

	site := payload.Site
	if site == nil {
		return TaskResult{Success: false, Message: "网站不存在"}
	}
	if blocked := rejectPausedSiteConfiguration(site.ID); blocked != nil {
		return *blocked
	}
	cfg := config.AppConfig

	engine := NewTemplateEngine(cfg.Panel.BackupDir)
	nginxData, err := nginxDataFromSiteChecked(site)
	if err != nil {
		return taskFailure("CDN 真实 IP 配置无效", err)
	}
	nginxData.AccessLogMode = payload.Mode

	nginxConfig, err := engine.RenderNginxConfig(nginxData)
	if err != nil {
		log.Printf("渲染 Nginx 配置失败: %v", err)
		return taskFailure("渲染 Nginx 配置失败", err)
	}

	if err := persistAccessLogMode(site.ID, payload.Mode); err != nil {
		return taskFailure("保存访问日志模式失败", err)
	}

	if err := applyAccessLogNginx(engine, nginxConfig, site.NginxConfPath,
		nginxEnabledPath(cfg, site.NginxConfPath, site.Domain)); err != nil {
		log.Printf("应用 Nginx 配置失败: %v", err)
		if restoreErr := persistAccessLogMode(site.ID, site.AccessLogMode); restoreErr != nil {
			return TaskResult{Success: false, Message: "应用 Nginx 配置失败，访问日志状态恢复失败，请人工检查"}
		}
		return taskFailure("应用 Nginx 配置失败", err)
	}

	// Clear log file when turning off
	if payload.Mode == "off" {
		logFile := filepath.Join(site.LogDir, "access.log")
		os.WriteFile(logFile, []byte{}, 0644)
	}

	modeLabels := map[string]string{
		"off":        "访问日志已关闭",
		"error_only": "访问日志已设为仅记录异常",
		"full":       "访问日志已设为全部记录",
	}
	msg := modeLabels[payload.Mode]
	if msg == "" {
		msg = "访问日志模式已更新"
	}
	return TaskResult{Success: true, Message: msg}
}

func saveAccessLogMode(siteID int, mode string) error {
	result, err := database.GetDB().Exec(
		"UPDATE websites SET access_log_mode = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", mode, siteID,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errors.New("网站访问日志状态未更新")
	}
	return nil
}

func executeSetCDNRealIP(task *Task) TaskResult {
	payload, ok := task.Payload.(*SetCDNRealIPPayload)
	if !ok {
		return TaskResult{Success: false, Message: "任务参数类型错误"}
	}
	site := payload.Site
	if site == nil {
		return TaskResult{Success: false, Message: "网站不存在"}
	}
	if blocked := rejectPausedSiteConfiguration(site.ID); blocked != nil {
		return *blocked
	}

	var groups []models.CDNRealIPGroup
	var err error
	if payload.Enabled {
		groups, err = GetEnabledCDNRealIPGroupsByIDs(payload.GroupIDs)
		if err != nil {
			return TaskResult{Success: false, Message: err.Error()}
		}
		if len(groups) == 0 {
			return TaskResult{Success: false, Message: "启用 CDN 真实 IP 时至少选择一个配置组"}
		}
	}

	siteCopy := *site
	siteCopy.CDNRealIPEnabled = payload.Enabled
	siteCopy.CDNRealIPGroups = groups
	if _, err := ResolveCDNRealIPRuntime(&siteCopy); err != nil {
		return TaskResult{Success: false, Message: err.Error()}
	}

	cfg := config.AppConfig
	engine := NewTemplateEngine(cfg.Panel.BackupDir)
	nginxData, err := nginxDataFromSiteChecked(&siteCopy)
	if err != nil {
		return TaskResult{Success: false, Message: err.Error()}
	}
	nginxConfig, err := engine.RenderNginxConfig(nginxData)
	if err != nil {
		log.Printf("渲染 Nginx 配置失败: %v", err)
		return taskFailure("渲染 Nginx 配置失败", err)
	}

	oldEnabled := site.CDNRealIPEnabled
	oldGroupIDs := cdnRealIPGroupIDs(site.CDNRealIPGroups)
	oldNginxData, oldDataErr := nginxDataFromSiteChecked(site)
	var oldNginxConfig string
	var oldRenderErr error
	if oldDataErr == nil {
		oldNginxConfig, oldRenderErr = engine.RenderNginxConfig(oldNginxData)
	} else {
		oldRenderErr = oldDataErr
	}
	if err := SaveWebsiteCDNRealIPSettings(site.ID, payload.Enabled, payload.GroupIDs); err != nil {
		return taskFailure("保存 CDN 真实 IP 设置失败", err)
	}
	if err := ApplyOLSTrustedProxyList(); err != nil {
		_ = SaveWebsiteCDNRealIPSettings(site.ID, oldEnabled, oldGroupIDs)
		_ = ApplyOLSTrustedProxyList()
		return taskFailure("CDN 真实 IP 已回滚，OpenLiteSpeed 可信代理配置失败", err)
	}
	if err := engine.ApplyNginxConfig(nginxConfig, site.NginxConfPath,
		nginxEnabledPath(cfg, site.NginxConfPath, site.Domain)); err != nil {
		log.Printf("应用 Nginx 配置失败: %v", err)
		_ = SaveWebsiteCDNRealIPSettings(site.ID, oldEnabled, oldGroupIDs)
		_ = ApplyOLSTrustedProxyList()
		return taskFailure("应用 Nginx 配置失败", err)
	}
	if err := ApplyFail2banSettings(); err != nil {
		_ = SaveWebsiteCDNRealIPSettings(site.ID, oldEnabled, oldGroupIDs)
		_ = ApplyOLSTrustedProxyList()
		if oldRenderErr == nil {
			_ = engine.ApplyNginxConfig(oldNginxConfig, site.NginxConfPath,
				nginxEnabledPath(cfg, site.NginxConfPath, site.Domain))
		}
		return taskFailure("CDN 真实 IP 已回滚，Fail2ban 白名单应用失败", err)
	}

	return TaskResult{Success: true, Message: "CDN 真实 IP 设置已保存并生效"}
}

func cdnRealIPGroupIDs(groups []models.CDNRealIPGroup) []int {
	ids := make([]int, 0, len(groups))
	for _, group := range groups {
		ids = append(ids, group.ID)
	}
	return ids
}

func boolToDBInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func executeSetDocumentRoot(task *Task) TaskResult {
	payload, ok := task.Payload.(*SetDocumentRootPayload)
	if !ok {
		return TaskResult{Success: false, Message: "任务参数类型错误"}
	}
	site := payload.Site
	if site == nil {
		return TaskResult{Success: false, Message: "网站不存在"}
	}
	if blocked, err := database.IsAIDevelopmentAccessBlocking(context.Background(), database.GetDB(), int64(site.ID)); err != nil {
		return TaskResult{Success: false, Message: "检查 AI 开发授权失败"}
	} else if blocked {
		return TaskResult{Success: false, Message: "该网站已开启 AI 开发访问，请先关闭授权"}
	}
	if locked, err := SiteMigrationLocked(context.Background(), site.ID, site.Domain); err != nil {
		return TaskResult{Success: false, Message: "检查站点迁移锁失败"}
	} else if locked {
		return TaskResult{Success: false, Message: "网站正在迁移维护中"}
	}
	if blocked := rejectPausedSiteConfiguration(site.ID); blocked != nil {
		return *blocked
	}
	if site.SiteType != "php" {
		return TaskResult{Success: false, Message: "只有通用 PHP 网站支持修改 Web 入口目录"}
	}

	documentRootSubdir, err := NormalizeDocumentRootSubdir(site.SiteType, payload.DocumentRootSubdir)
	if err != nil {
		return TaskResult{Success: false, Message: err.Error()}
	}
	if _, err := EnsureEffectiveDocumentRoot(site.WebRoot, site.SiteType, documentRootSubdir, site.SystemUser); err != nil {
		return taskFailure("准备Web入口目录失败", err)
	}

	siteCopy := *site
	siteCopy.DocumentRootSubdir = documentRootSubdir
	nginxData, err := nginxDataFromSiteChecked(&siteCopy)
	if err != nil {
		return taskFailure("CDN 真实 IP 配置无效", err)
	}

	cfg := config.AppConfig
	engine := NewTemplateEngine(cfg.Panel.BackupDir)
	nginxConfig, err := engine.RenderNginxConfig(nginxData)
	if err != nil {
		log.Printf("渲染 Nginx 配置失败: %v", err)
		return taskFailure("渲染 Nginx 配置失败", err)
	}
	if err := persistDocumentRoot(site.ID, documentRootSubdir); err != nil {
		return taskFailure("保存 Web 入口目录失败", err)
	}
	if err := applyDocumentRootNginx(engine, nginxConfig, site.NginxConfPath,
		nginxEnabledPath(cfg, site.NginxConfPath, site.Domain)); err != nil {
		log.Printf("应用 Nginx 配置失败: %v", err)
		if restoreErr := persistDocumentRoot(site.ID, site.DocumentRootSubdir); restoreErr != nil {
			return TaskResult{Success: false, Message: "应用 Nginx 配置失败，Web 入口目录状态恢复失败，请人工检查"}
		}
		return taskFailure("应用 Nginx 配置失败", err)
	}

	if documentRootSubdir == "" {
		return TaskResult{Success: true, Message: "Web 入口目录已切换为项目根"}
	}
	return TaskResult{Success: true, Message: "Web 入口目录已切换为 public"}
}

func saveDocumentRoot(siteID int, subdir string) error {
	result, err := database.GetDB().Exec(
		"UPDATE websites SET document_root_subdir = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", subdir, siteID,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errors.New("网站 Web 入口目录状态未更新")
	}
	return nil
}
