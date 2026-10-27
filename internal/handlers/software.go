package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/models"

	"github.com/gin-gonic/gin"
)

type SoftwareHandler struct {
	Config *config.Config
}

var softwareGuardSnapshot = executor.GetGuardStatus
var softwareSetServiceState = executor.SetServiceState
var softwareClearOPcache = executor.ClearOPcache
var softwareInstallPHPRuntime = executor.InstallLSPHPRuntime
var softwareInstallDevelopmentTool = executor.InstallDevelopmentTool
var softwareRecordInstallOperation = recordHandlerOperationLog

var runSoftwareShellCommand = func(command string) ([]byte, error) {
	return exec.Command("bash", "-c", command).CombinedOutput()
}

type guardResponse struct {
	Name         string `json:"name"`
	Service      string `json:"service"`
	Version      string `json:"version"`
	Running      bool   `json:"running"`
	Paused       bool   `json:"paused"`
	Restarts     int    `json:"restarts"`
	LastIncident string `json:"last_incident"`
}

type softwareItem struct {
	Name             string           `json:"name"`
	Version          string           `json:"version"`
	Status           string           `json:"status"`
	Configs          []softwareConfig `json:"configs"`
	Details          []softwareDetail `json:"details"`
	VersionPolicy    string           `json:"version_policy"`
	CandidateVersion string           `json:"candidate_version,omitempty"`
	UpdateAvailable  bool             `json:"update_available"`
	ConfigPath       string           `json:"-"`
}

type softwareDetail struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Tone  string `json:"tone"`
}

type softwareConfig struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Value   string   `json:"value"`
	Hint    string   `json:"hint"`
	Options []string `json:"options,omitempty"` // kept for backward compat, no longer used in UI
}

func softwareLang(c *gin.Context) string {
	return i18n.LangFromRequest(c.Request)
}

func (h *SoftwareHandler) List(c *gin.Context) {
	h.invalidateCompletedSystemUpdate()
	lang := softwareLang(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	fresh := c.Query("fresh") == "1"
	loaders := []func() softwareItem{
		func() softwareItem { return getPHPInfo(ctx, lang, fresh) },
		func() softwareItem { return getOpenLiteSpeedInfo(ctx, lang, fresh) },
		func() softwareItem { return getMariaDBInfo(ctx, lang, fresh) },
		func() softwareItem { return getRedisInfo(ctx, lang, fresh) },
		func() softwareItem { return getSystemPackageInfo(ctx, lang, "nftables", "nftables", fresh) },
		func() softwareItem { return getSystemPackageInfo(ctx, lang, "Fail2ban", "fail2ban", fresh) },
	}
	packages := []string{"lsphp" + strings.ReplaceAll(executor.PrimaryLSPHPVersion(), ".", ""), "openlitespeed", "mariadb-server", "redis-server", "nftables", "fail2ban"}
	items := make([]softwareItem, len(loaders))
	var loading sync.WaitGroup
	for i, load := range loaders {
		loading.Add(1)
		go func(index int, load func() softwareItem) {
			defer loading.Done()
			items[index] = load()
			if index == 0 {
				items[index].Configs = append(items[index].Configs, softwareConfig{Key: "max_input_time", Label: i18n.T(lang, "software.max_input_time_label"), Hint: i18n.T(lang, "software.max_input_time_hint")})
			}
			populateConfigValues(&items[index])
			applyPackageUpdateInfo(ctx, fresh, &items[index], packages[index])
		}(i, load)
	}
	loading.Wait()
	c.JSON(http.StatusOK, models.SuccessResponse(items))
}

func (h *SoftwareHandler) DevelopmentTools(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	c.JSON(http.StatusOK, models.SuccessResponse(executor.DevelopmentToolsStatus(ctx)))
}

func (h *SoftwareHandler) PHPRuntimes(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	c.JSON(http.StatusOK, models.SuccessResponse(executor.ListLSPHPRuntimesContext(ctx)))
}

func (h *SoftwareHandler) InstallPHPRuntime(c *gin.Context) {
	lang := softwareLang(c)
	var req struct {
		Version string `json:"version"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "common.invalid_params")))
		return
	}
	req.Version = strings.TrimSpace(req.Version)
	if req.Version == "" {
		req.Version = executor.DefaultLSPHPVersion
	}
	if req.Version != "8.3" && req.Version != "8.4" && req.Version != "8.5" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "common.invalid_params")))
		return
	}
	// Package installation must not be aborted halfway through dpkg work merely
	// because the browser navigates away. The handler still waits for a bounded
	// result, while the server-owned context lets apt finish consistently.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	runtime, err := softwareInstallPHPRuntime(ctx, req.Version)
	if err != nil {
		detail := executor.SoftwareInstallErrorDetail(err)
		log.Printf("安装 LSPHP 失败 version=%s: %s", req.Version, detail)
		softwareRecordInstallOperation("php_runtime_install", "LSPHP "+req.Version, "failed", detail)
		key := "software.php_runtime_install_failed"
		if errors.Is(err, executor.ErrLSPHPRuntimeNotReady) {
			key = "software.php_runtime_not_ready"
		}
		if errors.Is(err, executor.ErrPackagePlanChangesInstalled) {
			key = "software.php_runtime_package_plan_blocked"
		}
		if errors.Is(err, executor.ErrLSPHPPackageVersionMismatch) {
			key = "software.php_runtime_package_version_mismatch"
		}
		softwareReadCache.invalidate()
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, key)))
		return
	}
	softwareReadCache.invalidate()
	softwareRecordInstallOperation("php_runtime_install", "LSPHP "+runtime.Version, "success", "PHP runtime and extensions verified")
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"runtime": runtime,
		"message": i18n.T(lang, "software.php_runtime_installed", i18n.P{"version": runtime.Version}),
	}))
}

func (h *SoftwareHandler) InstallDevelopmentTool(c *gin.Context) {
	lang := softwareLang(c)
	var req struct {
		ID string `json:"id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || (req.ID != "wp-cli" && req.ID != "nodejs") {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "common.invalid_params")))
		return
	}
	// A browser closing must not interrupt a Node.js package transaction.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := softwareInstallDevelopmentTool(ctx, req.ID); err != nil {
		softwareReadCache.invalidate()
		detail := executor.SoftwareInstallErrorDetail(err)
		log.Printf("安装开发工具失败 tool=%s: %s", req.ID, detail)
		softwareRecordInstallOperation("development_tool_install", req.ID, "failed", detail)
		if errors.Is(err, executor.ErrWPCLIProxyDownloadFailed) {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.wp_cli_proxy_download_failed")))
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.development_tool_install_failed")))
		return
	}
	softwareReadCache.invalidate()
	softwareRecordInstallOperation("development_tool_install", req.ID, "success", "Development tool installed and verified")
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": i18n.T(lang, "software.development_tool_installed")}))
}

var configDefaults = map[string]string{
	"memory_limit":            "256M",
	"upload_max_filesize":     "64M",
	"post_max_size":           "64M",
	"max_execution_time":      "300",
	"max_input_time":          "300",
	"max_input_vars":          "10000",
	"client_max_body_size":    "1m",
	"innodb_buffer_pool_size": "128M",
	"maxmemory":               "0",
}

// adaptiveConfigFallback recalculates hardware-dependent OPcache values if the
// runtime configuration is missing. Use the same formulas as Recommend so the
// displayed values agree with recalculated recommendations.
func adaptiveConfigFallback(key string) string {
	switch key {
	case "opcache.memory_consumption":
		return strconv.Itoa(executor.RecommendOPcacheMemoryConsumptionMB(executor.CollectSystemFacts()))
	case "opcache.max_accelerated_files":
		return strconv.Itoa(executor.RecommendOPcacheMaxAcceleratedFiles(executor.CollectSystemFacts()))
	default:
		return ""
	}
}

func populateConfigValues(item *softwareItem) {
	data, err := os.ReadFile(item.ConfigPath)
	content := ""
	if err == nil {
		content = string(data)
	}
	for i := range item.Configs {
		key := item.Configs[i].Key
		val := findPHPIniValue(content, key)
		if val == "" {
			val = executor.FindRedisConfigValue(content, key)
		}
		if val != "" {
			item.Configs[i].Value = val
		} else if adaptive := adaptiveConfigFallback(key); adaptive != "" {
			item.Configs[i].Value = adaptive
		} else if def, ok := configDefaults[key]; ok {
			item.Configs[i].Value = def
		}
	}
}

var softwareLogPaths = map[string]string{
	"OpenLiteSpeed": "/usr/local/lsws/logs/error.log",
	"PHP":           "/usr/local/lsws/logs/stderr.log",
	"MariaDB":       "/var/log/mysql/error.log",
	"Redis":         "/var/log/redis/redis-server.log",
}

func (h *SoftwareHandler) ViewLog(c *gin.Context) {
	lang := softwareLang(c)
	name := c.Query("name")
	path, ok := softwareLogPaths[name]
	if !ok {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "software.unknown_software")))
		return
	}
	lines := 200
	if n, err := strconv.Atoi(c.DefaultQuery("lines", "200")); err == nil && n > 0 && n <= 500 {
		lines = n
	}
	content := tailFile(path, lines)
	if content == "" {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"content": i18n.T(lang, "software.log_empty_or_unreadable")}))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"content": content}))
}

func (h *SoftwareHandler) ClearLog(c *gin.Context) {
	lang := softwareLang(c)
	name := c.Query("name")
	path, ok := softwareLogPaths[name]
	if !ok {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "software.unknown_software")))
		return
	}
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		log.Printf("清空软件日志失败 name=%s: %v", name, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.clear_failed")))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": i18n.T(lang, "software.log_cleared", i18n.P{"name": name})}))
}

func (h *SoftwareHandler) GetGuardStatus(c *gin.Context) {
	h.invalidateCompletedSystemUpdate()
	svcs := softwareGuardSnapshot()
	result := make([]guardResponse, len(svcs))
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	fresh := c.Query("fresh") == "1"
	var loading sync.WaitGroup
	for i, s := range svcs {
		result[i] = guardResponse{
			Name:         s.Name,
			Service:      s.ServiceName,
			Running:      s.Running,
			Paused:       s.Paused,
			Restarts:     s.Restarts,
			LastIncident: s.LastIncident,
		}
		loading.Add(1)
		go func(index int, service string) {
			defer loading.Done()
			result[index].Version = softwareServiceVersion(ctx, fresh, service)
		}(i, s.ServiceName)
	}
	loading.Wait()
	c.JSON(http.StatusOK, models.SuccessResponse(result))
}

func (h *SoftwareHandler) GuardAction(c *gin.Context) {
	lang := softwareLang(c)
	var req struct {
		Service string `json:"service"`
		Action  string `json:"action"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "common.invalid_params")))
		return
	}
	if req.Action != "start" && req.Action != "stop" && req.Action != "restart" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "software.invalid_action")))
		return
	}
	if err := softwareSetServiceState(req.Service, req.Action); err != nil {
		if errors.Is(err, executor.ErrUnknownGuardService) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "software.unknown_software")))
			return
		}
		log.Printf("守护操作失败 service=%s action=%s: %v", req.Service, req.Action, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.operation_failed_with_error", i18n.P{"error": err.Error()})))
		return
	}
	softwareReadCache.invalidate()
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": i18n.T(lang, "software.action_success", i18n.P{"service": req.Service, "action": req.Action})}))
}

var softConfigAllowed = map[string]map[string]bool{
	"PHP": {
		"memory_limit": true, "upload_max_filesize": true, "post_max_size": true,
		"max_execution_time": true, "max_input_time": true, "max_input_vars": true,
		"opcache.memory_consumption": true, "opcache.max_accelerated_files": true,
	},
	"MariaDB": {"innodb_buffer_pool_size": true},
	"Redis":   {"maxmemory": true},
}

var (
	softwarePHPRuntimeConfigPath         = executor.PHPRuntimeConfigPath
	softwareRegenerateAllSitesOLSConfigs = executor.RegenerateAllSitesOLSConfigs
)

var (
	phpSizeValueRe = regexp.MustCompile(`^[0-9]+[KMGkmg]?$`)
	phpIntValueRe  = regexp.MustCompile(`^[0-9]+$`)
)

func validateSoftwareConfigValue(lang, name, key, value string) string {
	if name != "PHP" {
		return ""
	}
	switch key {
	case "memory_limit", "upload_max_filesize", "post_max_size":
		if !phpSizeValueRe.MatchString(value) {
			return i18n.T(lang, "software.php_size_invalid")
		}
	case "max_execution_time", "max_input_time", "max_input_vars",
		"opcache.memory_consumption", "opcache.max_accelerated_files":
		if !phpIntValueRe.MatchString(value) {
			return i18n.T(lang, "software.php_int_invalid")
		}
	}
	return ""
}

func phpConfigRequiresVHostRegeneration(key string) bool {
	switch key {
	case "memory_limit", "upload_max_filesize", "post_max_size", "max_execution_time", "max_input_time":
		return true
	default:
		return false
	}
}

func (h *SoftwareHandler) SaveConfig(c *gin.Context) {
	softwareConfigMu.Lock()
	defer softwareConfigMu.Unlock()
	lang := softwareLang(c)
	var req struct {
		Name  string `json:"name"`
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "common.invalid_params")))
		return
	}

	var configPath, serviceName, checkCmd, reloadCmd string

	switch req.Name {
	case "PHP":
		configPath = softwarePHPRuntimeConfigPath()
		serviceName = "lshttpd"
		checkCmd = executor.OpenLiteSpeedBinaryPath() + " -t"
		reloadCmd = "systemctl restart lshttpd"
	case "MariaDB":
		configPath = "/etc/mysql/mariadb.conf.d/99-olswpanel.cnf"
		serviceName = "mariadb"
		reloadCmd = "systemctl restart mariadb"
	case "Redis":
		configPath = "/etc/redis/redis.conf"
		serviceName = "redis-server"
		reloadCmd = "systemctl restart redis-server"
	default:
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "software.unknown_software")))
		return
	}

	// Validate key against per-service allowlist
	if allowed, ok := softConfigAllowed[req.Name]; !ok || !allowed[req.Key] {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "software.unsupported_config_item", i18n.P{"key": req.Key})))
		return
	}
	// Reject value containing newlines or directive-terminating characters
	if hasLineBreak(req.Value) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "software.value_no_newline")))
		return
	}
	if errMsg := validateSoftwareConfigValue(lang, req.Name, req.Key, req.Value); errMsg != "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(errMsg))
		return
	}

	// Ensure config file exists (for conf.d files created by baseline)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if req.Name == "PHP" {
			if _, err := executor.EnsurePHPRuntimeConfigFile(); err != nil {
				log.Printf("创建 PHP 配置文件失败: %v", err)
				c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.create_php_config_failed")))
				return
			}
		} else if req.Name == "MariaDB" {
			os.WriteFile(configPath, []byte("# OLS WPanel\n[mysqld]\n"), 0644)
		}
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.read_config_failed")))
		return
	}

	content := string(data)
	var oldValue string
	switch req.Name {
	case "Redis":
		oldValue = executor.FindRedisConfigValue(content, req.Key)
	default:
		oldValue = findPHPIniValue(content, req.Key)
	}

	// Simple backup
	os.WriteFile(configPath+".olswpanel.bak", data, 0644)

	// Replace value using appropriate function per software
	var newContent string
	switch req.Name {
	case "PHP":
		newContent = replaceIniValue(content, req.Key, req.Value)
	case "Redis":
		newContent = executor.ReplaceRedisConfigValue(content, req.Key, req.Value)
	default:
		newContent = replaceIniValue(content, req.Key, req.Value)
	}

	if newContent == content && oldValue == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "software.config_not_found", i18n.P{"key": req.Key})))
		return
	}

	// MariaDB and Redis lack a reliable configuration preflight check. Apply writes
	// atomically, restart, check readiness, and roll back on failure before reporting success.
	if req.Name == "MariaDB" || req.Name == "Redis" {
		// Enforce unchanged-value checks here too; direct API callers must not trigger needless restarts.
		if newContent == content {
			c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": i18n.T(lang, "software.config_unchanged")}))
			return
		}
		ready := softwareReadinessCheck(req.Name)
		result := executor.SafeApplyRestartConfig(configPath, newContent, content, serviceName, ready)
		if !result.Applied {
			log.Printf("%s 配置应用失败 rolled_back=%v rollback_ok=%v: %v", req.Name, result.RolledBack, result.RollbackSucceeded, result.Err)
			switch {
			case result.RolledBack && result.RollbackSucceeded:
				c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.apply_failed_rolled_back", i18n.P{"error": result.Err.Error()})))
			case result.RolledBack:
				c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.apply_failed_rollback_failed", i18n.P{"service": serviceName, "error": result.Err.Error()})))
			default:
				c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.apply_failed", i18n.P{"error": result.Err.Error()})))
			}
			return
		}
		softwareReadCache.invalidate()
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": i18n.T(lang, "software.config_updated_reloaded", i18n.P{"service": serviceName})}))
		return
	}

	if newContent != content {
		if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.write_config_failed")))
			return
		}
	}

	// Syntax check
	if checkCmd != "" {
		out, err := runSoftwareShellCommand(checkCmd)
		if err != nil {
			os.WriteFile(configPath, data, 0644)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.syntax_check_failed_with_rollback", i18n.P{"output": strings.TrimSpace(string(out))})))
			return
		}
	}

	// Reload
	if req.Name == "PHP" && phpConfigRequiresVHostRegeneration(req.Key) {
		if applyErr := softwareRegenerateAllSitesOLSConfigs(); applyErr != nil {
			restoreErr := os.WriteFile(configPath, data, 0644)
			if restoreErr == nil {
				if recoveryOut, err := runSoftwareShellCommand(checkCmd); err != nil {
					restoreErr = errors.New(strings.TrimSpace(string(recoveryOut)))
					if restoreErr.Error() == "" {
						restoreErr = err
					}
				}
			}
			if restoreErr == nil {
				restoreErr = softwareRegenerateAllSitesOLSConfigs()
			}
			log.Printf("PHP 配置应用失败并恢复: apply=%v recovery=%v", applyErr, restoreErr)
			if restoreErr != nil {
				c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.apply_failed_rollback_failed", i18n.P{"service": serviceName, "error": applyErr.Error()})))
				return
			}
			c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.apply_failed_rolled_back", i18n.P{"error": applyErr.Error()})))
			return
		}
	} else {
		reloadOut, reloadErr := runSoftwareShellCommand(reloadCmd)
		if reloadErr != nil {
			restoreErr := os.WriteFile(configPath, data, 0644)
			var recoveryErr error
			if restoreErr == nil && checkCmd != "" {
				if recoveryOut, err := runSoftwareShellCommand(checkCmd); err != nil {
					recoveryErr = errors.New(strings.TrimSpace(string(recoveryOut)))
					if recoveryErr.Error() == "" {
						recoveryErr = err
					}
				}
			}
			if restoreErr == nil && recoveryErr == nil {
				if recoveryOut, err := runSoftwareShellCommand(reloadCmd); err != nil {
					recoveryErr = errors.New(strings.TrimSpace(string(recoveryOut)))
					if recoveryErr.Error() == "" {
						recoveryErr = err
					}
				}
			}
			log.Printf("%s 配置重载失败并回滚: reload=%v output=%s restore=%v recovery=%v", req.Name, reloadErr, string(reloadOut), restoreErr, recoveryErr)
			if restoreErr != nil || recoveryErr != nil {
				c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.apply_failed_rollback_failed", i18n.P{"service": serviceName, "error": reloadErr.Error()})))
				return
			}
			c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.apply_failed_rolled_back", i18n.P{"error": reloadErr.Error()})))
			return
		}
	}

	softwareReadCache.invalidate()
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": i18n.T(lang, "software.config_updated_reloaded", i18n.P{"service": serviceName})}))
}

// softwareReadinessCheck lets SafeApplyRestartConfig verify service availability
// after restart instead of relying only on the systemctl exit code.
func softwareReadinessCheck(name string) func(context.Context) error {
	switch name {
	case "MariaDB":
		return func(ctx context.Context) error { return executor.MariaDBReady(ctx, config.AppConfig) }
	case "Redis":
		return executor.RedisReady
	default:
		return nil
	}
}

// Recommend calculates settings from server hardware and site count without
// writing files or restarting services. Administrators apply them explicitly.
func (h *SoftwareHandler) Recommend(c *gin.Context) {
	lang := softwareLang(c)
	name := c.Query("name")
	facts := executor.CollectSystemFacts()
	totalMB := facts.TotalMemoryBytes / 1024 / 1024

	recommendations := map[string]string{}
	switch name {
	case "PHP":
		recommendations["opcache.memory_consumption"] = strconv.Itoa(executor.RecommendOPcacheMemoryConsumptionMB(facts))
		recommendations["opcache.max_accelerated_files"] = strconv.Itoa(executor.RecommendOPcacheMaxAcceleratedFiles(facts))
	case "MariaDB":
		recommendations["innodb_buffer_pool_size"] = strconv.Itoa(executor.RecommendInnoDBBufferPoolSizeMB(facts)) + "M"
	case "Redis":
		recommendations["maxmemory"] = strconv.Itoa(executor.RecommendRedisMaxmemoryMB(facts)) + "mb"
	default:
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.T(lang, "software.unknown_software")))
		return
	}

	reasonKey := "software.recommend_reason"
	if name == "PHP" {
		// Only two OPcache fields depend on hardware; the other six reflect workload needs.
		// Name the changed fields so administrators know the recommendation covers only those two.
		reasonKey = "software.recommend_reason_php"
	}
	reason := i18n.T(lang, reasonKey, i18n.P{
		"mem":   strconv.FormatUint(totalMB, 10),
		"sites": strconv.Itoa(facts.SiteCount),
	})

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"facts": gin.H{
			"total_memory_mb": totalMB,
			"cpu_cores":       facts.CPUCores,
			"site_count":      facts.SiteCount,
		},
		"reason":          reason,
		"recommendations": recommendations,
	}))
}

// ClearOpcache clears the global PHP bytecode cache. Restrict this server-wide
// operation to panel administrators because it briefly affects every site.
func (h *SoftwareHandler) ClearOpcache(c *gin.Context) {
	lang := softwareLang(c)
	if err := softwareClearOPcache(); err != nil {
		log.Printf("清空 OPcache 失败: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(lang, "software.opcache_clear_failed", i18n.P{"error": err.Error()})))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": i18n.T(lang, "software.opcache_cleared")}))
}

func getPHPInfo(ctx context.Context, lang string, fresh bool) softwareItem {
	ver, status := "", i18n.T(lang, "software.status_unavailable")
	if out, err := softwareReadCache.read(ctx, fresh, executor.LSPHPBinaryPath(), "-v"); err == nil {
		fields := strings.Fields(strings.SplitN(out, "\n", 2)[0])
		if len(fields) >= 2 {
			ver = fields[1]
		}
	}
	if ver != "" {
		status = i18n.T(lang, "software.installed")
		if out, err := softwareReadCache.read(ctx, fresh, executor.LSPHPBinaryPath(), "-m"); err == nil && out != "" {
			status = i18n.T(lang, "software.php_installed_extensions", i18n.P{"count": strconv.Itoa(len(strings.Fields(out)))})
		}
	}
	return softwareItem{
		Name:          "PHP",
		Version:       strings.TrimSpace(ver),
		Status:        status,
		VersionPolicy: i18n.T(lang, "software.php_runtime_version_policy"),
		ConfigPath:    executor.PHPRuntimeConfigPath(),
		Configs: []softwareConfig{
			{Key: "memory_limit", Label: i18n.T(lang, "software.memory_limit_label"), Hint: i18n.T(lang, "software.memory_limit_hint")},
			{Key: "upload_max_filesize", Label: i18n.T(lang, "software.upload_max_filesize_label"), Hint: i18n.T(lang, "software.upload_max_filesize_hint")},
			{Key: "post_max_size", Label: i18n.T(lang, "software.post_max_size_label"), Hint: i18n.T(lang, "software.post_max_size_hint")},
			{Key: "max_execution_time", Label: i18n.T(lang, "software.max_execution_time_label"), Hint: i18n.T(lang, "software.max_execution_time_hint")},
			{Key: "max_input_vars", Label: i18n.T(lang, "software.max_input_vars_label"), Hint: i18n.T(lang, "software.max_input_vars_hint")},
			{Key: "opcache.memory_consumption", Label: i18n.T(lang, "software.opcache_memory_consumption_label"), Hint: i18n.T(lang, "software.opcache_memory_consumption_hint")},
			{Key: "opcache.max_accelerated_files", Label: i18n.T(lang, "software.opcache_max_accelerated_files_label"), Hint: i18n.T(lang, "software.opcache_max_accelerated_files_hint")},
		},
	}
}

func getOpenLiteSpeedInfo(ctx context.Context, lang string, fresh bool) softwareItem {
	ver := softwareServiceVersion(ctx, fresh, "lshttpd")
	return softwareItem{
		Name:          "OpenLiteSpeed",
		Version:       strings.TrimSpace(ver),
		Status:        softwareInstalledStatus(lang, ver),
		VersionPolicy: i18n.T(lang, "software.ols_runtime_version_policy"),
		ConfigPath:    "",
		Configs:       []softwareConfig{},
		Details:       openLiteSpeedRuntimeDetails(lang, "/usr/local/lsws/conf/httpd_config.conf"),
	}
}

func getMariaDBInfo(ctx context.Context, lang string, fresh bool) softwareItem {
	ver := softwareServiceVersion(ctx, fresh, "mariadb")
	return softwareItem{
		Name:          "MariaDB",
		Version:       strings.TrimSpace(ver),
		Status:        softwareInstalledStatus(lang, ver),
		VersionPolicy: i18n.T(lang, "software.mariadb_runtime_version_policy"),
		ConfigPath:    "/etc/mysql/mariadb.conf.d/99-olswpanel.cnf",
		Configs: []softwareConfig{
			{Key: "innodb_buffer_pool_size", Label: i18n.T(lang, "software.innodb_buffer_pool_size_label"), Hint: i18n.T(lang, "software.innodb_buffer_pool_size_hint")},
		},
	}
}

func getRedisInfo(ctx context.Context, lang string, fresh bool) softwareItem {
	ver := softwareServiceVersion(ctx, fresh, "redis-server")
	status := i18n.T(lang, "software.status_unavailable")
	for _, service := range softwareGuardSnapshot() {
		if service.ServiceName == "redis-server" && ver != "" {
			status = i18n.T(lang, "software.stopped")
			if service.Running {
				status = i18n.T(lang, "software.running")
			}
			break
		}
	}
	return softwareItem{
		Name:          "Redis",
		Version:       strings.TrimSpace(ver),
		Status:        status,
		VersionPolicy: i18n.T(lang, "software.redis_runtime_version_policy"),
		ConfigPath:    "/etc/redis/redis.conf",
		Configs: []softwareConfig{
			{Key: "maxmemory", Label: i18n.T(lang, "software.maxmemory_label"), Hint: i18n.T(lang, "software.maxmemory_hint")},
		},
	}
}

func getSystemPackageInfo(ctx context.Context, lang, name, service string, fresh bool) softwareItem {
	version := softwareServiceVersion(ctx, fresh, service)
	return softwareItem{
		Name:          name,
		Version:       version,
		Status:        softwareInstalledStatus(lang, version),
		VersionPolicy: i18n.T(lang, "software.system_package_version_policy"),
	}
}

func softwareInstalledStatus(lang, version string) string {
	if version == "" {
		return i18n.T(lang, "software.status_unavailable")
	}
	return i18n.T(lang, "software.installed")
}

func softwareServiceVersion(ctx context.Context, fresh bool, service string) string {
	var name string
	args := []string{"--version"}
	switch service {
	case "lshttpd":
		name, args = executor.OpenLiteSpeedBinaryPath(), []string{"-v"}
	case "mariadb":
		name = "mariadb"
	case "redis-server":
		name = "redis-server"
	case "nftables":
		name = "nft"
	case "fail2ban":
		name = "fail2ban-client"
	default:
		return ""
	}
	output, err := softwareReadCache.read(ctx, fresh, name, args...)
	if err != nil || output == "" {
		return ""
	}
	switch service {
	case "lshttpd":
		return parseOpenLiteSpeedVersion(output)
	case "mariadb":
		return parseMariaDBVersion(output)
	case "redis-server":
		for _, field := range strings.Fields(output) {
			if version, ok := strings.CutPrefix(field, "v="); ok {
				return version
			}
		}
	default:
		fields := strings.Fields(output)
		if len(fields) >= 2 {
			return strings.TrimPrefix(fields[1], "v")
		}
	}
	return ""
}

var (
	openLiteSpeedVersionRE = regexp.MustCompile(`(?i)LiteSpeed/([^\s]+)`)
	mariaDBDistribRE       = regexp.MustCompile(`(?i)\bDistrib\s+([^,\s]+)`)
	mariaDBVersionRE       = regexp.MustCompile(`(?i)\b([0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9.+~:_-]+)?)\b`)
)

func parseOpenLiteSpeedVersion(output string) string {
	if match := openLiteSpeedVersionRE.FindStringSubmatch(output); len(match) == 2 {
		return strings.TrimSpace(match[1])
	}
	return strings.TrimSpace(strings.SplitN(output, "\n", 2)[0])
}

func parseMariaDBVersion(output string) string {
	output = strings.TrimSpace(strings.SplitN(output, "\n", 2)[0])
	if match := mariaDBDistribRE.FindStringSubmatch(output); len(match) == 2 {
		return strings.TrimSpace(match[1])
	}
	if match := mariaDBVersionRE.FindStringSubmatch(output); len(match) == 2 {
		return strings.TrimSpace(match[1])
	}
	return output
}

func parseAptCandidateVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && key == "Candidate" {
			candidate := strings.TrimSpace(value)
			if candidate != "(none)" {
				return candidate
			}
		}
	}
	return ""
}

func applyPackageUpdateInfo(ctx context.Context, fresh bool, item *softwareItem, packageName string) {
	if item == nil || packageName == "" {
		return
	}
	installedOut, installedErr := softwareReadCache.read(ctx, fresh, "dpkg-query", "-W", "-f=${Version}", packageName)
	candidateOut, candidateErr := softwareReadCache.read(ctx, fresh, "apt-cache", "policy", packageName)
	if installedErr != nil || candidateErr != nil {
		return
	}
	installed := strings.TrimSpace(installedOut)
	candidate := parseAptCandidateVersion(candidateOut)
	if installed == "" || candidate == "" {
		return
	}
	item.CandidateVersion = candidate
	if installed == candidate {
		return
	}
	_, err := softwareReadCache.read(ctx, fresh, "dpkg", "--compare-versions", installed, "lt", candidate)
	item.UpdateAvailable = err == nil
}

func openLiteSpeedRuntimeDetails(lang, path string) []softwareDetail {
	content, err := os.ReadFile(path)
	text := string(content)
	setting := func(key string) (int, bool) {
		matches := regexp.MustCompile("(?m)^[\\t ]*"+regexp.QuoteMeta(key)+"[\\t ]+([0-9]+)[\\t ]*(?:#.*)?$").FindAllStringSubmatch(text, -1)
		if err != nil || len(matches) != 1 {
			return 0, false
		}
		value, parseErr := strconv.Atoi(matches[0][1])
		return value, parseErr == nil
	}
	state := func(enabled, known bool) (string, string) {
		if !known {
			return i18n.T(lang, "software.health_unknown"), "muted"
		}
		if enabled {
			return i18n.T(lang, "software.enabled"), "success"
		}
		return i18n.T(lang, "software.disabled"), "muted"
	}
	details := make([]softwareDetail, 0, 4)
	compression, compressionKnown := setting("enableGzipCompress")
	gzip, gzipKnown := setting("enableDynGzipCompress")
	value, tone := state(compression == 1 && gzip == 1, compressionKnown && (compression == 0 || gzipKnown))
	details = append(details, softwareDetail{Label: i18n.T(lang, "software.ols_gzip"), Value: value, Tone: tone})
	brotli, brotliKnown := setting("enableBrCompress")
	value, tone = state(compression == 1 && brotli > 0, compressionKnown && (compression == 0 || brotliKnown))
	details = append(details, softwareDetail{Label: i18n.T(lang, "software.ols_brotli"), Value: value, Tone: tone})
	quic, quicKnown := setting("quicEnable")
	value, tone = state(quic == 1, quicKnown)
	details = append(details, softwareDetail{Label: i18n.T(lang, "software.ols_http3"), Value: value, Tone: tone})
	webAdmin, webAdminKnown := setting("disableWebAdmin")
	webAdminValue := i18n.T(lang, "software.ols_webadmin_disabled")
	webAdminTone := "info"
	if !webAdminKnown {
		webAdminValue = i18n.T(lang, "software.health_unknown")
		webAdminTone = "muted"
	} else if webAdmin != 1 {
		webAdminValue = i18n.T(lang, "software.ols_webadmin_enabled")
		webAdminTone = "warning"
	}
	details = append(details, softwareDetail{Label: i18n.T(lang, "software.ols_webadmin"), Value: webAdminValue, Tone: webAdminTone})
	return details
}

func replaceIniValue(content, key, value string) string {
	lines := strings.Split(content, "\n")
	prefix := key + " ="
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) || strings.HasPrefix(trimmed, key+"=") {
			lines[i] = key + " = " + value
			found = true
		}
	}
	if !found {
		lines = append(lines, "", "; OLS WPanel — WordPress 优化", key+" = "+value)
	}
	return strings.Join(lines, "\n")
}

func findPHPIniValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, key+" =") || strings.HasPrefix(trimmed, key+"=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
