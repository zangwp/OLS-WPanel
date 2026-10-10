package executor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var (
	persistAccessLogMode   = saveAccessLogMode
	applyAccessLogOLSVHost = func(engine *TemplateEngine, content, targetPath, enabledPath string) error {
		return engine.ApplyOLSVHostConfig(content, targetPath, enabledPath)
	}
	persistDocumentRoot       = saveDocumentRoot
	applyDocumentRootOLSVHost = func(engine *TemplateEngine, content, targetPath, enabledPath string) error {
		return engine.ApplyOLSVHostConfig(content, targetPath, enabledPath)
	}
	applyCDNRealIPTrustedProxies = ApplyOLSTrustedProxyList
	applyCDNRealIPFail2ban       = ApplyFail2banSettings
	applyCDNRealIPOLSVHost       = func(engine *TemplateEngine, content, targetPath, enabledPath string) error {
		return engine.ApplyOLSVHostConfig(content, targetPath, enabledPath)
	}
)

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
	vhostData, err := olsVHostDataFromSiteChecked(site)
	if err != nil {
		return taskFailure("CDN 真实 IP 配置无效", err)
	}
	vhostData.AccessLogMode = payload.Mode

	vhostConfig, err := engine.RenderOLSVHostConfig(vhostData)
	if err != nil {
		log.Printf("渲染 OpenLiteSpeed 虚拟主机配置失败: %v", err)
		return taskFailure("渲染 OpenLiteSpeed 虚拟主机配置失败", err)
	}

	if err := persistAccessLogMode(site.ID, payload.Mode); err != nil {
		return taskFailure("保存访问日志模式失败", err)
	}

	if err := applyAccessLogOLSVHost(engine, vhostConfig, site.OLSVHostConfigPath,
		olsVHostEnabledPath(cfg, site.OLSVHostConfigPath, site.Domain)); err != nil {
		log.Printf("应用 OpenLiteSpeed 虚拟主机配置失败: %v", err)
		if restoreErr := persistAccessLogMode(site.ID, site.AccessLogMode); restoreErr != nil {
			return TaskResult{Success: false, Message: "应用 OpenLiteSpeed 配置失败，访问日志状态恢复失败，请人工检查"}
		}
		return taskFailure("应用 OpenLiteSpeed 配置失败", err)
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
	vhostData, err := olsVHostDataFromSiteChecked(&siteCopy)
	if err != nil {
		return TaskResult{Success: false, Message: err.Error()}
	}
	vhostConfig, err := engine.RenderOLSVHostConfig(vhostData)
	if err != nil {
		log.Printf("渲染 OpenLiteSpeed 虚拟主机配置失败: %v", err)
		return taskFailure("渲染 OpenLiteSpeed 虚拟主机配置失败", err)
	}

	oldEnabled := site.CDNRealIPEnabled
	oldGroupIDs := cdnRealIPGroupIDs(site.CDNRealIPGroups)
	oldVHostData, oldDataErr := olsVHostDataFromSiteChecked(site)
	var oldVHostConfig string
	var oldRenderErr error
	if oldDataErr == nil {
		oldVHostConfig, oldRenderErr = engine.RenderOLSVHostConfig(oldVHostData)
	} else {
		oldRenderErr = oldDataErr
	}
	restore := func(action string, cause error, restoreVHost bool) TaskResult {
		var recoveryErrors []error
		if err := SaveWebsiteCDNRealIPSettings(site.ID, oldEnabled, oldGroupIDs); err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("恢复 CDN 数据库设置失败: %w", err), errors.New("可信代理 ACL 无法恢复：数据库设置尚未恢复"))
		} else if err := applyCDNRealIPTrustedProxies(); err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("恢复 OpenLiteSpeed 可信代理 ACL 失败: %w", err))
		}
		if restoreVHost {
			if oldRenderErr != nil {
				recoveryErrors = append(recoveryErrors, fmt.Errorf("恢复原虚拟主机配置无法生成: %w", oldRenderErr))
			} else if err := applyCDNRealIPOLSVHost(engine, oldVHostConfig, site.OLSVHostConfigPath,
				olsVHostEnabledPath(cfg, site.OLSVHostConfigPath, site.Domain)); err != nil {
				recoveryErrors = append(recoveryErrors, fmt.Errorf("恢复原 OpenLiteSpeed 虚拟主机配置失败: %w", err))
			}
		}
		if len(recoveryErrors) != 0 {
			return taskFailure(action+"，CDN 状态恢复未完成，请人工检查", errors.Join(append([]error{fmt.Errorf("原始错误: %w", cause)}, recoveryErrors...)...))
		}
		return taskFailure(action+"，CDN 数据库设置与可信代理 ACL 已恢复", cause)
	}
	if err := SaveWebsiteCDNRealIPSettings(site.ID, payload.Enabled, payload.GroupIDs); err != nil {
		return taskFailure("保存 CDN 真实 IP 设置失败", err)
	}
	if err := applyCDNRealIPTrustedProxies(); err != nil {
		return restore("OpenLiteSpeed 可信代理配置失败", err, false)
	}
	if err := applyCDNRealIPOLSVHost(engine, vhostConfig, site.OLSVHostConfigPath,
		olsVHostEnabledPath(cfg, site.OLSVHostConfigPath, site.Domain)); err != nil {
		log.Printf("应用 OpenLiteSpeed 虚拟主机配置失败: %v", err)
		return restore("应用 OpenLiteSpeed 虚拟主机配置失败", err, false)
	}
	if err := applyCDNRealIPFail2ban(); err != nil {
		return restore("Fail2ban 白名单应用失败", err, true)
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
	vhostData, err := olsVHostDataFromSiteChecked(&siteCopy)
	if err != nil {
		return taskFailure("CDN 真实 IP 配置无效", err)
	}

	cfg := config.AppConfig
	engine := NewTemplateEngine(cfg.Panel.BackupDir)
	vhostConfig, err := engine.RenderOLSVHostConfig(vhostData)
	if err != nil {
		log.Printf("渲染 OpenLiteSpeed 虚拟主机配置失败: %v", err)
		return taskFailure("渲染 OpenLiteSpeed 虚拟主机配置失败", err)
	}
	if err := persistDocumentRoot(site.ID, documentRootSubdir); err != nil {
		return taskFailure("保存 Web 入口目录失败", err)
	}
	if err := applyDocumentRootOLSVHost(engine, vhostConfig, site.OLSVHostConfigPath,
		olsVHostEnabledPath(cfg, site.OLSVHostConfigPath, site.Domain)); err != nil {
		log.Printf("应用 OpenLiteSpeed 虚拟主机配置失败: %v", err)
		if restoreErr := persistDocumentRoot(site.ID, site.DocumentRootSubdir); restoreErr != nil {
			return TaskResult{Success: false, Message: "应用 OpenLiteSpeed 虚拟主机配置失败，Web 入口目录状态恢复失败，请人工检查"}
		}
		return taskFailure("应用 OpenLiteSpeed 虚拟主机配置失败", err)
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
