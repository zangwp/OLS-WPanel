package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
	"github.com/zangwp/OLS-WPanel/internal/models"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type SettingsHandler struct {
	Auth             *AuthHandler
	WPPackageService *executor.WPPackageService
	ConfigPath       string
}

type settingsUpdateRequest struct {
	PanelTitle                *string `json:"panel_title"`
	Username                  *string `json:"username"`
	BasicAuthUser             *string `json:"basic_auth_user"`
	OldPassword               *string `json:"old_password"`
	Code                      string  `json:"code"`
	NewPassword               *string `json:"new_password"`
	BasicAuthPw               *string `json:"basic_auth_password"`
	Timezone                  *string `json:"timezone"`
	Hostname                  *string `json:"hostname"`
	NtpSync                   *bool   `json:"ntp_sync"`
	GithubProxy               *string `json:"github_proxy"`
	PanelAutoUpdateEnabled    *string `json:"panel_auto_update_enabled"`
	PanelAutoUpdateMode       *string `json:"panel_auto_update_mode"`
	PanelAutoUpdateWindow     *string `json:"panel_auto_update_window"`
	PanelAutoUpdateDelay      *string `json:"panel_auto_update_release_delay_minutes"`
	PanelAutoUpdateSigTimeout *string `json:"panel_auto_update_signature_timeout_minutes"`
	WPPackageAutoCheckEnabled *string `json:"wp_package_auto_check_enabled"`
}

const defaultPanelConfigPath = "/www/ols-wpanel/config.json"

func (h *SettingsHandler) configPath() string {
	if strings.TrimSpace(h.ConfigPath) != "" {
		return h.ConfigPath
	}
	return defaultPanelConfigPath
}

var (
	setSystemTimezone = func(timezone string) error {
		return exec.Command("timedatectl", "set-timezone", timezone).Run()
	}
	setSystemHostname = func(hostname string) error {
		return exec.Command("hostnamectl", "set-hostname", hostname).Run()
	}
	enableSystemNTP    = startSystemTimeSync
	ntpTimeSyncUnit    = detectNTPTimeSyncUnit
	readSystemTimezone = getTimezone
	readSystemHostname = getHostname
	readSystemNTP      = getNTPEnabled
)

func (h *SettingsHandler) GetSettings(c *gin.Context) {
	db := database.GetDB()
	var username string
	db.QueryRow("SELECT username FROM admin_users LIMIT 1").Scan(&username)

	basicAuthUser := readConfigValue(h.configPath(), "basic_auth", "username")

	var panelTitle string
	db.QueryRow("SELECT svalue FROM security_settings WHERE skey = 'panel_title'").Scan(&panelTitle)
	if panelTitle == "" {
		panelTitle = config.ProductName
	}

	var githubProxy string
	db.QueryRow("SELECT svalue FROM security_settings WHERE skey = 'github_proxy'").Scan(&githubProxy)
	autoUpdate := map[string]string{}
	for _, key := range []string{
		"panel_auto_update_enabled", "panel_auto_update_mode", "panel_auto_update_window",
		"panel_auto_update_release_delay_minutes", "panel_auto_update_signature_timeout_minutes",
		"panel_auto_update_last_target_version", "panel_auto_update_last_attempt_at",
		"panel_auto_update_last_status", "panel_auto_update_last_stage", "panel_auto_update_last_error",
		"panel_auto_update_last_success_at", "panel_auto_update_last_success_version",
	} {
		var v string
		err := db.QueryRow("SELECT svalue FROM security_settings WHERE skey = ?", key).Scan(&v)
		if err != nil && err != sql.ErrNoRows {
			log.Printf("读取面板自动更新设置失败 key=%s: %v", key, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("读取自动更新设置失败，请稍后重试"))
			return
		}
		autoUpdate[key] = v
	}

	timezone := getTimezone()
	hostname := getHostname()
	ntpSynced, ntpServer := getNTPSyncStatus()

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"username":          username,
		"basic_auth_user":   basicAuthUser,
		"panel_title":       panelTitle,
		"github_proxy":      githubProxy,
		"timezone":          timezone,
		"hostname":          hostname,
		"ntp_synced":        ntpSynced,
		"ntp_enabled":       getNTPEnabled(),
		"ntp_service":       ntpTimeSyncUnit(),
		"ntp_server":        ntpServer,
		"server_time":       time.Now().UnixMilli(),
		"panel_auto_update": autoUpdate,
	}))
}

func (h *SettingsHandler) UpdateSettings(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8192)
	var req settingsUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("参数错误"))
		return
	}
	if req.Username != nil || req.NewPassword != nil || req.BasicAuthUser != nil || req.BasicAuthPw != nil {
		unlock := LockAccountAuthentication()
		defer unlock()
	}

	db := database.GetDB()
	dbSettings, validationMessage := validateDatabaseSettings(req)
	if validationMessage != "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(validationMessage))
		return
	}

	// Changing the administrator identity is security-sensitive. Validate the
	// current credential before mutating either the username or password so a
	// failed password check can never leave a partial username change behind.
	var currentUsername, currentPasswordHash string
	requestedUsername := ""
	usernameChanged := false
	passwordRequested := req.NewPassword != nil && *req.NewPassword != ""
	passwordChanged := false
	newPasswordHash := ""
	if req.Username != nil || passwordRequested {
		if err := db.QueryRow("SELECT username, password_hash FROM admin_users LIMIT 1").Scan(&currentUsername, &currentPasswordHash); err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("查询用户失败"))
			return
		}
		requestedUsername = currentUsername
		if req.Username != nil {
			requestedUsername = strings.TrimSpace(*req.Username)
			if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`).MatchString(requestedUsername) {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("用户名应为3-64位字母、数字、点、下划线或连字符"))
				return
			}
			usernameChanged = requestedUsername != currentUsername
		}
		if usernameChanged || passwordRequested {
			if req.OldPassword == nil || *req.OldPassword == "" {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("请输入当前密码"))
				return
			}
		}
		if passwordRequested {
			if len(*req.NewPassword) < 8 || len(*req.NewPassword) > 72 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse("新密码应为8-72字节"))
				return
			}
		}
	}

	basicAuthChanged := (req.BasicAuthUser != nil && *req.BasicAuthUser != "" &&
		*req.BasicAuthUser != readConfigValue(h.configPath(), "basic_auth", "username")) ||
		(req.BasicAuthPw != nil && *req.BasicAuthPw != "")
	if basicAuthChanged && (usernameChanged || passwordRequested) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请分别保存入口认证与面板登录凭据"))
		return
	}
	if basicAuthChanged {
		if req.BasicAuthUser != nil && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`).MatchString(*req.BasicAuthUser) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("用户名应为3-64位字母、数字、点、下划线或连字符"))
			return
		}
		if req.BasicAuthPw != nil && *req.BasicAuthPw != "" && (len(*req.BasicAuthPw) < 8 || len(*req.BasicAuthPw) > 72) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("BasicAuth密码应为8-72字节"))
			return
		}
	}
	if usernameChanged || passwordRequested || basicAuthChanged {
		auth := h.Auth
		if auth == nil {
			auth = &AuthHandler{DB: db}
		}
		password := ""
		if req.OldPassword != nil {
			password = *req.OldPassword
		}
		if !auth.VerifySensitiveCredential(c, password, req.Code) {
			return
		}
	}
	// Perform costly replacement hashing only after the rate-limited current
	// password and MFA proof have passed. Reject overlong bcrypt inputs early.
	if passwordRequested {
		passwordChanged = bcrypt.CompareHashAndPassword([]byte(currentPasswordHash), []byte(*req.NewPassword)) != nil
		if passwordChanged {
			hash, err := bcrypt.GenerateFromPassword([]byte(*req.NewPassword), 12)
			if err != nil {
				c.JSON(http.StatusInternalServerError, models.ErrorResponse("密码加密失败"))
				return
			}
			newPasswordHash = string(hash)
		}
	}

	if usernameChanged || passwordChanged {
		tx, err := db.Begin()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("启动账户更新失败"))
			return
		}
		defer tx.Rollback()
		if usernameChanged {
			if _, err := tx.Exec("UPDATE admin_users SET username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1", requestedUsername); err != nil {
				c.JSON(http.StatusInternalServerError, models.ErrorResponse("更新用户名失败"))
				return
			}
		}
		if passwordChanged {
			if _, err := tx.Exec("UPDATE admin_users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1", newPasswordHash); err != nil {
				c.JSON(http.StatusInternalServerError, models.ErrorResponse("更新密码失败"))
				return
			}
		}
		if usernameChanged {
			if err := h.Auth.Audit.RenameUserTx(c.Request.Context(), tx, currentUsername, requestedUsername); err != nil {
				accountSecurityUnavailable(c)
				return
			}
		}
		if _, err := h.Auth.Audit.RecordTx(c.Request.Context(), tx, requestAuditEvent(c, requestedUsername, "credentials_changed")); err != nil {
			accountSecurityUnavailable(c)
			return
		}
		if err := tx.Commit(); err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("提交账户更新失败"))
			return
		}
		middleware.GlobalSessionStore.DeleteAll()
		h.Auth.dispatchSecurityNotifications(c)
	}

	if basicAuthChanged && !h.updateBasicAuthAccount(c, req) {
		return
	}

	var tzRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_/+\\-]+(/[A-Za-z][A-Za-z0-9_/+\\-]+)*$`)

	if req.Timezone != nil && *req.Timezone != "" {
		tz := strings.TrimSpace(*req.Timezone)
		if !tzRe.MatchString(tz) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("无效的时区"))
			return
		}
		if err := setSystemTimezone(tz); err != nil {
			log.Printf("设置时区失败 (%s): %v", tz, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("设置时区失败，请检查系统时间服务"))
			return
		}
		if actual := readSystemTimezone(); actual != tz {
			log.Printf("设置时区后实际值不一致: want=%s actual=%s", tz, actual)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("时区命令已执行，但服务器实际时区未更新"))
			return
		}
	}

	var hostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

	if req.Hostname != nil && *req.Hostname != "" {
		host := strings.TrimSpace(*req.Hostname)
		if !hostRe.MatchString(host) || len(host) > 253 || strings.HasPrefix(host, "-") || strings.HasSuffix(host, "-") {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("无效的主机名"))
			return
		}
		if err := setSystemHostname(host); err != nil {
			log.Printf("设置主机名失败 (%s): %v", host, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("设置主机名失败，请检查系统主机名服务"))
			return
		}
		if actual := readSystemHostname(); actual != host {
			log.Printf("设置主机名后实际值不一致: want=%s actual=%s", host, actual)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("主机名命令已执行，但服务器实际主机名未更新"))
			return
		}
	}

	if req.NtpSync != nil && *req.NtpSync {
		if err := enableSystemNTP(); err != nil {
			log.Printf("启用系统时间同步失败: %v", err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("时间同步启动失败: "+err.Error()))
			return
		}
		if !readSystemNTP() {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("时间同步命令已执行，但服务器没有启用自动时间同步"))
			return
		}
	}

	if err := saveSecuritySettingsTransaction(db, dbSettings); err != nil {
		log.Printf("保存面板数据库设置失败: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("设置保存失败，请稍后重试"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": "设置已更新"}))
}

func validateDatabaseSettings(req settingsUpdateRequest) (map[string]string, string) {
	updates := make(map[string]string)
	if req.PanelTitle != nil && *req.PanelTitle != "" {
		updates["panel_title"] = *req.PanelTitle
	}
	if req.GithubProxy != nil {
		proxy := strings.TrimRight(strings.TrimSpace(*req.GithubProxy), "/")
		if proxy != "" && !strings.HasPrefix(proxy, "https://") {
			return nil, "反代地址必须以 https:// 开头"
		}
		updates["github_proxy"] = proxy
	}
	if req.PanelAutoUpdateEnabled != nil {
		v := strings.TrimSpace(*req.PanelAutoUpdateEnabled)
		if v != "true" && v != "false" {
			return nil, "自动更新开关参数错误"
		}
		updates["panel_auto_update_enabled"] = v
	}
	if req.PanelAutoUpdateMode != nil {
		v := strings.TrimSpace(*req.PanelAutoUpdateMode)
		if v != "patch_only" && v != "all_stable" {
			return nil, "自动更新模式参数错误"
		}
		updates["panel_auto_update_mode"] = v
	}
	if req.PanelAutoUpdateWindow != nil {
		v := strings.TrimSpace(*req.PanelAutoUpdateWindow)
		if !regexp.MustCompile(`^\d{2}:\d{2}-\d{2}:\d{2}$`).MatchString(v) {
			return nil, "自动更新时间窗口格式应为 HH:MM-HH:MM"
		}
		parts := strings.Split(v, "-")
		if _, err := time.Parse("15:04", parts[0]); err != nil {
			return nil, "自动更新时间窗口包含无效时间"
		}
		if _, err := time.Parse("15:04", parts[1]); err != nil {
			return nil, "自动更新时间窗口包含无效时间"
		}
		updates["panel_auto_update_window"] = v
	}
	minuteSettings := []struct {
		raw      *string
		key      string
		min, max int
	}{
		{req.PanelAutoUpdateDelay, "panel_auto_update_release_delay_minutes", 1, 1440},
		{req.PanelAutoUpdateSigTimeout, "panel_auto_update_signature_timeout_minutes", 5, 1440},
	}
	for _, setting := range minuteSettings {
		if setting.raw == nil {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(*setting.raw))
		if err != nil || v < setting.min || v > setting.max {
			return nil, fmt.Sprintf("分钟数必须在 %d-%d 之间", setting.min, setting.max)
		}
		updates[setting.key] = strconv.Itoa(v)
	}
	if req.WPPackageAutoCheckEnabled != nil {
		v := strings.TrimSpace(*req.WPPackageAutoCheckEnabled)
		if v != "true" && v != "false" {
			return nil, "自动检测开关参数错误"
		}
		updates["wp_package_auto_check_enabled"] = v
	}
	return updates, ""
}

func saveSecuritySettingsTransaction(db *sql.DB, updates map[string]string) error {
	if len(updates) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range updates {
		if _, err := tx.Exec(`INSERT INTO security_settings (skey, svalue, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT(skey) DO UPDATE SET svalue = excluded.svalue, updated_at = excluded.updated_at`, key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (h *SettingsHandler) TestProxy(c *gin.Context) {
	proxy := strings.TrimRight(strings.TrimSpace(c.Query("url")), "/")
	if proxy == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请提供反代地址"))
		return
	}
	if !strings.HasPrefix(proxy, "https://") {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("反代地址必须以 https:// 开头"))
		return
	}

	testURL := fmt.Sprintf("%s/https://api.github.com/repos/%s/%s/releases/latest", proxy, config.ReleaseRepoOwner, config.ReleaseRepoName)
	client := &http.Client{Timeout: 10 * time.Second}
	start := time.Now()
	resp, err := client.Get(testURL)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"ok":      false,
			"error":   fmt.Sprintf("连接失败: %v", err),
			"latency": elapsed,
		}))
		return
	}
	resp.Body.Close()

	if resp.StatusCode == 200 {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"ok":      true,
			"latency": elapsed,
		}))
	} else {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"ok":      false,
			"error":   fmt.Sprintf("HTTP %d", resp.StatusCode),
			"latency": elapsed,
		}))
	}
}

func (h *SettingsHandler) GetOperationLogs(c *gin.Context) {
	db := database.GetDB()

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "10"))
	if perPage != 10 && perPage != 20 && perPage != 50 {
		perPage = 10
	}

	where := make([]string, 0, 2)
	args := make([]interface{}, 0, 4)
	status := strings.ToLower(strings.TrimSpace(c.Query("status")))
	if status != "" {
		allowed := map[string]bool{"success": true, "failed": true, "running": true, "waiting": true, "skipped": true, "info": true}
		if !allowed[status] {
			c.JSON(http.StatusBadRequest, models.ErrorResponse("无效的日志状态筛选"))
			return
		}
		where = append(where, "status = ?")
		args = append(args, status)
	}
	queryText := strings.TrimSpace(c.Query("q"))
	if len(queryText) > 64 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("日志搜索内容不能超过64个字符"))
		return
	}
	if queryText != "" {
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(queryText)
		where = append(where, `(operation LIKE ? ESCAPE '\' OR target LIKE ? ESCAPE '\')`)
		pattern := "%" + escaped + "%"
		args = append(args, pattern, pattern)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM operation_logs"+whereSQL, args...).Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("查询失败"))
		return
	}

	offset := (page - 1) * perPage
	listArgs := append(append([]interface{}{}, args...), perPage, offset)
	rows, err := db.Query(`SELECT id, operation, target, status, message, created_at
		FROM operation_logs`+whereSQL+` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("查询失败"))
		return
	}
	defer rows.Close()

	var logs []models.OperationLog
	for rows.Next() {
		var l models.OperationLog
		if err := rows.Scan(&l.ID, &l.Operation, &l.Target, &l.Status, &l.Message, &l.CreatedAt); err != nil {
			continue
		}
		logs = append(logs, l)
	}
	if logs == nil {
		logs = []models.OperationLog{}
	}

	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"data":        logs,
		"total":       total,
		"page":        page,
		"per_page":    perPage,
		"total_pages": totalPages,
	}))
}

func GetPanelTitle() string {
	db := database.GetDB()
	if db == nil {
		return config.ProductName
	}
	var title string
	db.QueryRow("SELECT svalue FROM security_settings WHERE skey = 'panel_title'").Scan(&title)
	if title == "" {
		return config.ProductName
	}
	return title
}

func readConfigValue(configPath, section, key string) string {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	var cfg map[string]map[string]interface{}
	if json.Unmarshal(data, &cfg) != nil {
		return ""
	}
	if sec, ok := cfg[section]; ok {
		if v, ok := sec[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func getNTPSyncStatus() (bool, string) {
	out, _ := exec.Command("timedatectl", "show", "--property=NTPSynchronized", "--value").Output()
	synced := strings.TrimSpace(string(out)) == "yes"
	server := ""
	return synced, server
}

var timeSyncCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// StartSystemTimeSync shares the panel's provider-aware synchronization with the CLI.
func StartSystemTimeSync() error { return startSystemTimeSync() }

func startSystemTimeSync() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	unit, err := selectNTPTimeSyncUnit(ctx)
	if err != nil {
		return err
	}
	if unit == "" {
		out, err := timeSyncCommand(ctx, "apt-get", "install", "-y", "--no-install-recommends", "systemd-timesyncd")
		if err != nil {
			log.Printf("安装时间同步服务失败: %s", out)
			return fmt.Errorf("缺少时间同步服务，安装 systemd-timesyncd 失败；请检查 APT 与网络")
		}
		unit = "systemd-timesyncd.service"
	}
	if out, err := timeSyncCommand(ctx, "systemctl", "enable", "--now", unit); err != nil {
		return fmt.Errorf("启动 %s 失败: %s", unit, strings.TrimSpace(string(out)))
	}
	// Do not ask timedated to choose an NTP provider again: it could select a
	// different installed service and undo the active-provider decision above.
	if out, err := timeSyncCommand(ctx, "systemctl", "restart", unit); err != nil {
		return fmt.Errorf("重启 %s 失败: %s", unit, strings.TrimSpace(string(out)))
	}
	if out, err := timeSyncCommand(ctx, "systemctl", "is-active", "--quiet", unit); err != nil {
		return fmt.Errorf("%s 启动后未处于运行状态: %s", unit, strings.TrimSpace(string(out)))
	}
	return nil
}

func getNTPEnabled() bool {
	out, err := exec.Command("timedatectl", "show", "--property=NTP", "--value").CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "yes"
}

// Prefer the running provider, rather than the first installed package. A
// conflicting pair of active providers must be handled explicitly by the admin.
func detectNTPTimeSyncUnit() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	unit, _ := selectNTPTimeSyncUnit(ctx)
	return unit
}

func selectNTPTimeSyncUnit(ctx context.Context) (string, error) {
	var active, installed, masked []string
	activeIDs := map[string]bool{}
	for _, unit := range []string{"chrony.service", "systemd-timesyncd.service", "ntpsec.service", "ntp.service", "openntpd.service"} {
		output, err := timeSyncCommand(ctx, "systemctl", "show", unit, "--property=Id", "--property=LoadState", "--property=ActiveState", "--no-pager")
		properties := map[string]string{}
		for _, line := range strings.Split(string(output), "\n") {
			if key, value, ok := strings.Cut(line, "="); ok {
				properties[strings.TrimSpace(key)] = strings.TrimSpace(value)
			}
		}
		if err != nil && properties["LoadState"] != "not-found" {
			return "", fmt.Errorf("无法确认 %s 的运行状态，停止修改时间同步服务", unit)
		}
		switch properties["LoadState"] {
		case "masked":
			// A running unit can be masked without being stopped. Ignoring it
			// would allow starting another provider alongside the original daemon.
			switch properties["ActiveState"] {
			case "inactive", "failed", "maintenance":
			default:
				return "", fmt.Errorf("%s 已被屏蔽且仍在运行或活动状态未知，请先检查现有时间同步服务", unit)
			}
			masked = append(masked, unit)
		case "loaded":
			state := properties["ActiveState"]
			switch state {
			case "active", "activating", "reloading", "deactivating", "inactive", "failed", "maintenance":
			default:
				return "", fmt.Errorf("%s 的活动状态未知，停止修改时间同步服务", unit)
			}
			installed = append(installed, unit)
			if state == "active" || state == "activating" || state == "reloading" || state == "deactivating" {
				id := properties["Id"]
				if id == "" {
					id = unit
				}
				if !activeIDs[id] {
					active = append(active, unit)
					activeIDs[id] = true
				}
			}
		case "not-found":
			continue
		default:
			return "", fmt.Errorf("%s 的服务状态未知，停止修改时间同步服务", unit)
		}
	}
	if len(active) > 1 {
		return "", fmt.Errorf("检测到多个时间同步服务正在运行（%s）；请保留一套后重试", strings.Join(active, ", "))
	}
	if len(active) == 1 {
		return active[0], nil
	}
	if len(installed) > 0 {
		return installed[0], nil
	}
	if len(masked) > 0 {
		return "", fmt.Errorf("时间同步服务已被管理员屏蔽（%s），请先检查服务策略", strings.Join(masked, ", "))
	}
	return "", nil
}

// systemdUnitExists 判断 unit 是否存在且未被 mask（masked 单元 restart 必然失败）。
func systemdUnitExists(unit string) bool {
	out, err := exec.Command("systemctl", "list-unit-files", unit).Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == unit && fields[1] != "masked" && fields[1] != "masked-runtime" {
			return true
		}
	}
	return false
}

func getTimezone() string {
	out, _ := exec.Command("bash", "-c", "timedatectl show --property=Timezone --value 2>/dev/null").CombinedOutput()
	tz := strings.TrimSpace(string(out))
	if tz == "" {
		if data, err := os.ReadFile("/etc/timezone"); err == nil {
			tz = strings.TrimSpace(string(data))
		}
	}
	return tz
}

func getHostname() string {
	out, _ := exec.Command("bash", "-c", "hostnamectl hostname 2>/dev/null || hostname").CombinedOutput()
	return strings.TrimSpace(string(out))
}

// ============================================================
// WordPress 安装包管理
// ============================================================

func (h *SettingsHandler) GetWPPackage(c *gin.Context) {
	cfg := config.AppConfig
	pkgPath := cfg.Paths.WordPressPackage
	autoCheck := readWPPackageAutoCheckStatus()

	info, err := os.Stat(pkgPath)
	if err != nil {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
			"available":  false,
			"path":       pkgPath,
			"auto_check": autoCheck,
		}))
		return
	}

	version, locale, _ := executor.LocalPackageInfo(c.Request.Context(), pkgPath)

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"available":  true,
		"path":       pkgPath,
		"size":       info.Size(),
		"size_text":  formatFileSize(info.Size()),
		"updated_at": info.ModTime().Format("2006-01-02 15:04:05"),
		"version":    version,
		"locale":     locale,
		"auto_check": autoCheck,
	}))
}

// readWPPackageAutoCheckStatus reads the WordPress package auto-check
// toggle and its last-run status, written by executor.StartWPPackageAutoUpdateScheduler.
func readWPPackageAutoCheckStatus() gin.H {
	db := database.GetDB()
	autoCheck := gin.H{}
	for _, key := range []string{
		"wp_package_auto_check_enabled", "wp_package_last_check_at",
		"wp_package_last_check_status", "wp_package_last_check_error",
		"wp_package_last_remote_version",
	} {
		var v string
		db.QueryRow("SELECT svalue FROM security_settings WHERE skey = ?", key).Scan(&v)
		autoCheck[key] = v
	}
	return autoCheck
}

func (h *SettingsHandler) UploadWPPackage(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请选择文件"))
		return
	}

	// 校验文件扩展名
	name := strings.ToLower(file.Filename)
	if !strings.HasSuffix(name, ".zip") {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("仅支持 .zip 格式的安装包"))
		return
	}

	// 限制文件大小（WordPress 安装包通常 25-30MB，上限 100MB）
	if file.Size > 100*1024*1024 {
		c.JSON(http.StatusRequestEntityTooLarge, models.ErrorResponse(i18n.TE(c.Request, "settings.wp_package_too_large")))
		return
	}
	if h.WPPackageService == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.TE(c.Request, "settings.wp_package_publish_failed")))
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(i18n.TE(c.Request, "settings.wp_package_invalid")))
		return
	}
	defer src.Close()
	report, err := h.WPPackageService.PublishUpload(c.Request.Context(), src, file.Size)
	if err != nil {
		code := executor.ArchiveErrorCode(err)
		log.Printf("WordPress package upload rejected: code=%s", code)
		writeWPPackageError(c, code, false)
		return
	}
	log.Printf("WordPress package published from upload: version=%s entries=%d archive_bytes=%d", report.Version, report.Inspection.EntryCount, report.Inspection.ArchiveBytes)
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"message": i18n.TE(c.Request, "settings.upload_success"),
	}))
}

func (h *SettingsHandler) DownloadWPPackage(c *gin.Context) {
	if h.WPPackageService == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.TE(c.Request, "settings.wp_package_publish_failed")))
		return
	}
	report, err := h.WPPackageService.DownloadLatest(c.Request.Context())
	if err != nil {
		code := executor.ArchiveErrorCode(err)
		log.Printf("WordPress package download rejected: code=%s", code)
		writeWPPackageError(c, code, true)
		return
	}
	log.Printf("WordPress package published from official download: version=%s entries=%d archive_bytes=%d", report.Version, report.Inspection.EntryCount, report.Inspection.ArchiveBytes)
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"message": i18n.TE(c.Request, "settings.package_download_complete"),
	}))
}

func writeWPPackageError(c *gin.Context, code string, download bool) {
	status := http.StatusBadRequest
	key := "settings.wp_package_invalid"
	switch code {
	case "archive_upload_too_large", "archive_too_large":
		if download {
			status, key = http.StatusBadGateway, "settings.wp_package_download_invalid"
		} else {
			status, key = http.StatusRequestEntityTooLarge, "settings.wp_package_too_large"
		}
	case "package_busy":
		status, key = http.StatusConflict, "settings.wp_package_busy"
	case "package_download_timeout", "archive_validation_timeout":
		status, key = http.StatusGatewayTimeout, "settings.wp_package_download_timeout"
	case "package_download_failed":
		status, key = http.StatusBadGateway, "settings.wp_package_download_failed"
	case "package_publish_failed":
		status, key = http.StatusInternalServerError, "settings.wp_package_publish_failed"
	default:
		if download {
			status, key = http.StatusBadGateway, "settings.wp_package_download_invalid"
		}
	}
	c.JSON(status, models.ErrorResponse(i18n.TE(c.Request, key)))
}

func (h *SettingsHandler) DeleteWPPackage(c *gin.Context) {
	cfg := config.AppConfig
	pkgPath := cfg.Paths.WordPressPackage

	if err := os.Remove(pkgPath); err != nil && !os.IsNotExist(err) {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("删除失败"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"message": "安装包已删除",
	}))
}

func formatFileSize(size int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case size >= GB:
		return fmt.Sprintf("%.1f GB", float64(size)/float64(GB))
	case size >= MB:
		return fmt.Sprintf("%.1f MB", float64(size)/float64(MB))
	case size >= KB:
		return fmt.Sprintf("%.1f KB", float64(size)/float64(KB))
	default:
		return fmt.Sprintf("%d B", size)
	}
}

func updateConfigValue(configPath, section, key, value string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败")
	}
	var cfg map[string]map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("解析配置文件失败")
	}
	sec, ok := cfg[section]
	if !ok {
		return fmt.Errorf("配置段 %s 不存在", section)
	}
	sec[key] = value
	newData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败")
	}
	if err := os.WriteFile(configPath, newData, 0600); err != nil {
		return fmt.Errorf("写入配置文件失败")
	}
	return nil
}

// ============================================================
// 面板数据库备份管理
// ============================================================

func (h *SettingsHandler) GetDBBackups(c *gin.Context) {
	cfg := config.AppConfig
	backupDir := filepath.Join(cfg.Panel.BackupDir, "panel-db")
	backups, err := database.ListDBBackups(backupDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("查询备份列表失败"))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(backups))
}

func (h *SettingsHandler) CreateDBBackup(c *gin.Context) {
	cfg := config.AppConfig
	backupDir := filepath.Join(cfg.Panel.BackupDir, "panel-db")

	path, err := database.BackupDatabase(backupDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("备份失败: "+err.Error()))
		return
	}

	// 校验备份完整性
	if verr := database.VerifyDBBackup(path); verr != nil {
		os.Remove(path)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("备份校验失败: "+verr.Error()))
		return
	}

	database.CleanupOldDBBackups(backupDir, 7)

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"message": "数据库备份完成",
	}))
}

func (h *SettingsHandler) RestoreDBBackup(c *gin.Context) {
	var req struct {
		Filename string `json:"filename"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Filename == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请选择要恢复的备份"))
		return
	}

	cfg := config.AppConfig
	backupDir := filepath.Join(cfg.Panel.BackupDir, "panel-db")

	backupPath, err := database.RestoreDBBackupPath(backupDir, req.Filename)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}

	// 校验备份文件完整性
	if verr := database.VerifyDBBackup(backupPath); verr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("备份文件校验失败，无法恢复: "+verr.Error()))
		return
	}

	backupVersion, err := database.DBBackupSchemaVersion(backupPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("读取备份版本失败: "+err.Error()))
		return
	}
	if backupVersion != "" && executor.CompareVersions(backupVersion, database.LatestVersion()) > 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("该备份来自更高版本的 OLS WPanel，当前版本无法安全恢复"))
		return
	}

	status, err := executor.StartPanelDBRestore(cfg, backupPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"message":    "数据库恢复中，面板将自动重启并检查结果",
		"restore_id": status.ID,
	}))
}

func (h *SettingsHandler) GetDBRestoreStatus(c *gin.Context) {
	c.JSON(http.StatusOK, models.SuccessResponse(executor.ReconcilePanelDBRestoreStatus(config.AppConfig)))
}

func (h *SettingsHandler) DeleteDBBackup(c *gin.Context) {
	filename := c.Query("filename")
	if filename == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请指定文件名"))
		return
	}

	cfg := config.AppConfig
	backupDir := filepath.Join(cfg.Panel.BackupDir, "panel-db")

	fullPath, err := database.RestoreDBBackupPath(backupDir, filename)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}

	if err := os.Remove(fullPath); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("删除失败"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": "备份已删除"}))
}

func (h *SettingsHandler) DownloadDBBackup(c *gin.Context) {
	filename := c.Param("filename")

	cfg := config.AppConfig
	backupDir := filepath.Join(cfg.Panel.BackupDir, "panel-db")

	fullPath, err := database.RestoreDBBackupPath(backupDir, filename)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}

	c.FileAttachment(fullPath, filename)
}
