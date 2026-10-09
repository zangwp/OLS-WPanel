package executor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

var syncMu sync.Mutex
var fail2banSettingsApplyMu sync.Mutex
var sshRecordActionPending atomic.Bool
var manualAddPersistBan = AddPersistBan
var manualRemovePersistBan = RemovePersistBan
var conditionalRemoveWebPersistBan = RemovePersistBan
var syncAddPersistBan = AddPersistBan
var syncRemovePersistBan = RemovePersistBan

var persistNftExec = func(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

var persistNftMu sync.Mutex

const googlebotOfficialURL = "https://developers.google.com/crawling/ipranges/common-crawlers.json"

var googlebotHTTPClient = &http.Client{Timeout: 15 * time.Second}

// fail2banFilterConfig 只负责全站洪泛/探测信号（429 限流、敏感文件 404 探测）。
// 登录/XML-RPC 认证爆破信号已经拆分到 fail2banLoginFilterConfig + olswpanel-login
// jail，读取的是 WordPress wp_login_failed 写入的 wp-login-security.log，不再
// 从这里的 access.log 里用响应状态推测登录失败——避免同一次登录失败被两个
// jail 分别计数、触发两次独立封禁。
const fail2banSensitive404Regex = `(?i)^<HOST> - - \[.*\] "(?:GET|POST) .*(?:\.env(?:\.[^/?\s"]+)?|\.git|config\.bak|wp-config\.php|secrets\.(?:json|ya?ml)|settings\.py|application\.properties|config\.toml|\.sql|\.tar|\.gz|\.zip|\.old|\.swp|\.save|\.ds_store)(?:[/?\s"]|$).*" 404 .*$`

const fail2banFilterConfig = `# OLS WPanel Generated — DO NOT EDIT MANUALLY
[Definition]
failregex = ^<HOST> .* ".*" 429 .*$
            ` + fail2banSensitive404Regex + `
ignoreregex =
`

// Consume only real WordPress authentication failures. A login form returned
// with HTTP 200, a password-reset request, or disabled XML-RPC's HTTP 403 is not
// evidence of a failed password. The timestamp is optional here because
// Fail2ban removes a recognized date before applying failregex.
const fail2banLoginFilterConfig = `# OLS WPanel Generated — DO NOT EDIT MANUALLY
[Definition]
datepattern = %%Y-%%m-%%dT%%H:%%M:%%S%%z
failregex = ^<HOST> \[(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)?\] OLS_WPANEL_LOGIN_FAILED$
ignoreregex =
`

// The markers are appended by OpenLiteSpeed from server-set rewrite
// environment variables. Anchor the fixed suffix so user-controlled request
// headers/query strings cannot masquerade as a block/auto-ban decision.
const fail2banSQLiFilterConfig = `# OLS WPanel Generated — DO NOT EDIT MANUALLY
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "[A-Z]+ [^"]*" 403 [0-9]+(?: "[^"]*" "[^"]*")?(?: peer=(?:-|[0-9a-fA-F:.]+))? ols_security="sqli" ols_autoban="1"$
ignoreregex =
`

func init() {
	database.RegisterUpgrade("1.0.26", cleanupDuplicateActiveFirewallBans)
}

func cleanupDuplicateActiveFirewallBans() error {
	return deduplicateActiveFirewallBans(database.GetDB())
}

type fail2banConfigBackup struct {
	path    string
	data    []byte
	existed bool
}

func deployFail2ban(webWhitelistIPs, sshWhitelistIPs string, maxRetry, findTime, banTime, sqliMaxRetry, sqliFindTime int) error {
	logRoot, err := fail2banWebsiteLogRoot()
	if err != nil {
		return err
	}
	jailDir := "/etc/fail2ban/jail.d"
	filterDir := "/etc/fail2ban/filter.d"
	actionDir := "/etc/fail2ban/action.d"
	os.MkdirAll(jailDir, 0755)
	os.MkdirAll(filterDir, 0755)
	os.MkdirAll(actionDir, 0755)

	ensureLogFiles(logRoot)
	jailPath := filepath.Join(jailDir, "olswpanel.conf")
	localPath := "/etc/fail2ban/fail2ban.local"
	recordActionPath := filepath.Join(actionDir, "olswpanel-record.conf")
	filterPath := filepath.Join(filterDir, "olswpanel.conf")
	filter404Path := filepath.Join(filterDir, "olswpanel-404.conf")
	filterLoginPath := filepath.Join(filterDir, "olswpanel-login.conf")
	filterSQLiPath := filepath.Join(filterDir, "olswpanel-sqli.conf")
	backups, err := backupFail2banConfigFiles(jailPath, recordActionPath, filterPath, filter404Path, filterLoginPath, filterSQLiPath, localPath)
	if err != nil {
		return err
	}
	rollbackDeploy := func(cause error) error {
		if restoreErr := restoreFail2banConfigFiles(backups); restoreErr != nil {
			return fmt.Errorf("%w; rollback fail2ban config files failed: %v", cause, restoreErr)
		}
		if reloadErr := reloadOrStartFail2ban(); reloadErr != nil {
			return fmt.Errorf("%w; fail2ban config files were rolled back, but reload failed: %v", cause, reloadErr)
		}
		return cause
	}

	webIgnoreIPs, err := buildFail2banIgnoreIPs(webWhitelistIPs)
	if err != nil {
		return err
	}
	sshIgnoreIPs, err := buildFail2banIgnoreIPs(sshWhitelistIPs)
	if err != nil {
		return err
	}

	if maxRetry <= 0 {
		maxRetry = 5
	}
	if findTime <= 0 {
		findTime = 60
	}
	if banTime <= 0 {
		banTime = 600
	}
	if sqliMaxRetry <= 0 {
		sqliMaxRetry = 5
	}
	if sqliFindTime <= 0 {
		sqliFindTime = 600
	}

	jailConfig := fmt.Sprintf(`# OLS WPanel Generated — DO NOT EDIT MANUALLY
[olswpanel]
enabled = true
filter = olswpanel
action = nftables-multiport[name=olswpanel, port="http,https"]
         olswpanel-record[name=olswpanel]
logpath = /www/wwwlogs/*/access.log
          /www/wwwlogs/*/error.log
maxretry = %d
findtime = %d
bantime = %d
bantime.increment = true
bantime.multipliers = 1 6 36 144 1008
bantime.maxtime = 7d
bantime.overalljails = false
ignoreip = %s

[olswpanel-404]
enabled = true
filter = olswpanel-404
action = nftables-multiport[name=olswpanel-404, port="http,https"]
         olswpanel-record[name=olswpanel-404]
logpath = /www/wwwlogs/*/access.log
maxretry = 30
findtime = 60
bantime = %d
bantime.increment = true
bantime.multipliers = 1 6 36 144 1008
bantime.maxtime = 7d
bantime.overalljails = false
ignoreip = %s

[olswpanel-login]
enabled = true
filter = olswpanel-login
action = nftables-multiport[name=olswpanel-login, port="http,https"]
         olswpanel-record[name=olswpanel-login]
logpath = /www/wwwlogs/*/wp-login-security.log
maxretry = %d
findtime = %d
bantime = %d
bantime.increment = true
bantime.multipliers = 1 6 36 144 1008
bantime.maxtime = 7d
bantime.overalljails = false
ignoreip = %s

[olswpanel-sshd]
enabled = true
filter = sshd
action = nftables-multiport[name=olswpanel-sshd, port="ssh"]
         olswpanel-record[name=olswpanel-sshd]
logpath = /var/log/auth.log
maxretry = %d
findtime = %d
bantime = %d
bantime.increment = true
bantime.multipliers = 1 6 36 144 1008
bantime.maxtime = 7d
bantime.overalljails = false
ignoreip = %s
`, maxRetry, findTime, banTime, webIgnoreIPs, banTime, webIgnoreIPs, maxRetry, findTime, banTime, webIgnoreIPs, maxRetry, findTime, banTime, sshIgnoreIPs)
	jailConfig += fmt.Sprintf(`
[olswpanel-sqli]
enabled = true
filter = olswpanel-sqli
action = nftables-multiport[name=olswpanel-sqli, port="http,https"]
         olswpanel-record[name=olswpanel-sqli]
logpath = /www/wwwlogs/*/access.log
maxretry = %d
findtime = %d
bantime = %d
bantime.increment = true
bantime.multipliers = 1 6 36 144 1008
bantime.maxtime = 7d
bantime.overalljails = false
ignoreip = %s
`, sqliMaxRetry, sqliFindTime, banTime, webIgnoreIPs)
	jailConfig, err = renderFail2banWebsiteLogPaths(jailConfig, logRoot)
	if err != nil {
		return err
	}
	if err := validateGeneratedFail2banJailConfig(jailConfig); err != nil {
		return err
	}

	if err := os.WriteFile(jailPath, []byte(jailConfig), 0644); err != nil {
		return rollbackDeploy(fmt.Errorf("写入 jail 配置失败: %w", err))
	}

	if err := writeFail2banLocal(localPath); err != nil {
		return rollbackDeploy(fmt.Errorf("写入 fail2ban 本地配置失败: %w", err))
	}

	recordActionConfig := `# OLS WPanel Generated - DO NOT EDIT MANUALLY
[Definition]
actionban = /usr/local/bin/ols-wpanel --record-fail2ban <ip> --ban-jail <name> --ban-bantime <bantime> --ban-count <bancount> --ban-restored=<restored>
actionunban = /usr/local/bin/ols-wpanel --unban-fail2ban <ip> --ban-jail <name>
`
	if err := os.WriteFile(recordActionPath, []byte(recordActionConfig), 0644); err != nil {
		return rollbackDeploy(fmt.Errorf("写入记录 action 配置失败: %w", err))
	}

	if err := os.WriteFile(filterPath, []byte(fail2banFilterConfig), 0644); err != nil {
		return rollbackDeploy(fmt.Errorf("写入 filter 配置失败: %w", err))
	}

	filter404Config := `# OLS WPanel Generated — DO NOT EDIT MANUALLY
[Definition]
failregex = ^<HOST> - - \[.*\] ".*" 404 .*$
ignoreregex =
`

	if err := os.WriteFile(filter404Path, []byte(filter404Config), 0644); err != nil {
		return rollbackDeploy(fmt.Errorf("写入 404 filter 配置失败: %w", err))
	}

	if err := os.WriteFile(filterLoginPath, []byte(fail2banLoginFilterConfig), 0644); err != nil {
		return rollbackDeploy(fmt.Errorf("写入登录爆破 filter 配置失败: %w", err))
	}
	if err := os.WriteFile(filterSQLiPath, []byte(fail2banSQLiFilterConfig), 0644); err != nil {
		return rollbackDeploy(fmt.Errorf("写入 SQL 注入防护 filter 配置失败: %w", err))
	}

	if _, err := executeCommand("fail2ban-client", "-t"); err != nil {
		return rollbackDeploy(fmt.Errorf("Fail2ban 配置校验失败: %w", err))
	}
	if err := reloadOrStartFail2ban(); err != nil {
		return rollbackDeploy(fmt.Errorf("重载 fail2ban 失败: %w", err))
	}
	if err := ensureFail2banSSHRecordAction(); err != nil {
		return rollbackDeploy(fmt.Errorf("启用 SSH 封禁记录 action 失败: %w", err))
	}
	return nil
}

func validateGeneratedFail2banJailConfig(config string) error {
	for _, jail := range []string{"olswpanel", "olswpanel-404", "olswpanel-login", "olswpanel-sshd", "olswpanel-sqli"} {
		header := "[" + jail + "]"
		start := strings.Index(config, header)
		if start < 0 {
			return fmt.Errorf("invalid generated Fail2ban jail config: missing %s", header)
		}
		section := config[start+len(header):]
		if end := strings.Index(section, "\n["); end >= 0 {
			section = section[:end]
		}
		for _, directive := range []string{
			"bantime = 600",
			"bantime.increment = true",
			"bantime.multipliers = 1 6 36 144 1008",
			"bantime.maxtime = 7d",
			"bantime.overalljails = false",
		} {
			if strings.Count(section, directive) != 1 {
				return fmt.Errorf("invalid generated Fail2ban jail config: %s: %s", jail, directive)
			}
		}
	}
	sshdSection := config[strings.Index(config, "[olswpanel-sshd]"):]
	if !strings.Contains(sshdSection, "olswpanel-record[name=olswpanel-sshd]") {
		return fmt.Errorf("invalid generated Fail2ban jail config: olswpanel-sshd: missing record action")
	}
	return nil
}

func writeFail2banLocal(path string) error {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines)+3)
	inDefault, foundDefault, wrotePurge := false, false, false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if inDefault && !wrotePurge {
				out = append(out, "dbpurgeage = 30d")
				wrotePurge = true
			}
			if strings.EqualFold(trimmed, "[DEFAULT]") {
				if foundDefault {
					return fmt.Errorf("fail2ban.local contains multiple [DEFAULT] sections")
				}
				foundDefault, inDefault = true, true
			} else {
				inDefault = false
			}
			out = append(out, line)
			continue
		}
		if inDefault {
			key, _, found := strings.Cut(trimmed, "=")
			if found && strings.EqualFold(strings.TrimSpace(key), "dbpurgeage") {
				if !wrotePurge {
					out = append(out, "dbpurgeage = 30d")
					wrotePurge = true
				}
				continue
			}
		}
		out = append(out, line)
	}
	if inDefault && !wrotePurge {
		out = append(out, "dbpurgeage = 30d")
	} else if !foundDefault {
		out = append([]string{"[DEFAULT]", "dbpurgeage = 30d", ""}, out...)
	}
	content := strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0644)
}

func backupFail2banConfigFiles(paths ...string) ([]fail2banConfigBackup, error) {
	backups := make([]fail2banConfigBackup, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				backups = append(backups, fail2banConfigBackup{path: path})
				continue
			}
			return nil, fmt.Errorf("读取 Fail2ban 配置备份失败: %w", err)
		}
		backups = append(backups, fail2banConfigBackup{path: path, data: data, existed: true})
	}
	return backups, nil
}

func restoreFail2banConfigFiles(backups []fail2banConfigBackup) error {
	var errs []error
	for _, backup := range backups {
		if backup.existed {
			if err := os.WriteFile(backup.path, backup.data, 0644); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", backup.path, err))
			}
			continue
		}
		if err := os.Remove(backup.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("%s: %w", backup.path, err))
		}
	}
	return errors.Join(errs...)
}

func reloadOrStartFail2ban() error {
	if _, err := executeCommand("fail2ban-client", "reload"); err != nil {
		if _, activeErr := executeCommand("systemctl", "is-active", "--quiet", "fail2ban"); activeErr == nil {
			return err
		}
		if _, startErr := executeCommand("systemctl", "start", "fail2ban"); startErr != nil {
			return startErr
		}
	}
	return nil
}

func ensureFail2banSSHRecordAction() error {
	out, err := executeCommand("fail2ban-client", "get", "olswpanel-sshd", "actions")
	if err != nil {
		return err
	}
	if strings.Contains(out, "olswpanel-record") {
		sshRecordActionPending.Store(false)
		return nil
	}
	status, err := executeCommand("fail2ban-client", "status", "olswpanel-sshd")
	if err != nil {
		return err
	}
	if len(parseBannedIPs(status)) > 0 {
		sshRecordActionPending.Store(true)
		log.Printf("olswpanel-sshd 仍有活动封禁，暂缓重启 jail 以启用记录 action")
		return nil
	}
	_, err = executeCommand("fail2ban-client", "reload", "--restart", "olswpanel-sshd")
	if err == nil {
		sshRecordActionPending.Store(false)
	}
	return err
}

func buildFail2banIgnoreIPs(whitelistIPs string) (string, error) {
	ignoreIPs := "127.0.0.1/8 ::1"
	if whitelistIPs == "" {
		return ignoreIPs, nil
	}
	for _, ip := range strings.Split(whitelistIPs, "\n") {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if strings.ContainsAny(ip, " \t\r") {
			return "", fmt.Errorf("白名单 IP 格式不正确: %s", ip)
		}
		if strings.Contains(ip, "/") {
			if _, _, err := net.ParseCIDR(ip); err != nil {
				return "", fmt.Errorf("白名单 IP 格式不正确: %s", ip)
			}
		} else if net.ParseIP(ip) == nil {
			return "", fmt.Errorf("白名单 IP 格式不正确: %s", ip)
		}
		ignoreIPs += " " + ip
	}
	return ignoreIPs, nil
}

func ensureLogFiles(logRoot string) {
	hasLogs := false
	entries, err := os.ReadDir(logRoot)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			for _, name := range []string{"access.log", "error.log", "wp-security.log", "wp-login-security.log", "wp-sqli-security.log", "php-error.log", "php-slow.log"} {
				touch(filepath.Join(logRoot, e.Name(), name))
			}
			hasLogs = true
		}
	}
	if !hasLogs {
		placeholder := filepath.Join(logRoot, "_panel_placeholder")
		os.MkdirAll(placeholder, 0755)
		for _, name := range []string{"access.log", "error.log", "wp-security.log", "wp-login-security.log", "wp-sqli-security.log", "php-error.log", "php-slow.log"} {
			touch(filepath.Join(placeholder, name))
		}
	}
	touch("/var/log/auth.log")
}

func ensureSiteLogFiles(logDir string) {
	if strings.TrimSpace(logDir) == "" {
		return
	}
	touch(filepath.Join(logDir, "access.log"))
	touch(filepath.Join(logDir, "error.log"))
	touch(filepath.Join(logDir, "wp-security.log"))
	touch(filepath.Join(logDir, "wp-login-security.log"))
	touch(filepath.Join(logDir, "php-error.log"))
	touch(filepath.Join(logDir, "php-slow.log"))
}

func touch(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		f.Close()
	}
}

func ReloadFail2ban() error {
	if _, err := executeCommand("fail2ban-client", "reload"); err != nil {
		if _, activeErr := executeCommand("systemctl", "is-active", "--quiet", "fail2ban"); activeErr == nil {
			return fmt.Errorf("reload fail2ban failed: %w", err)
		}
	}
	return nil
}

func executeRefreshWhitelist(task *Task) TaskResult {
	var result TaskResult
	err := WithFail2banSettingsLock(func(apply func() error) error {
		result = executeRefreshWhitelistLocked(task, apply)
		return nil
	})
	if err != nil {
		return TaskResult{Success: false, Message: err.Error()}
	}
	return result
}

func executeRefreshWhitelistLocked(task *Task, apply func() error) TaskResult {
	var allIPs []string
	var details []string
	db := database.GetDB()
	if db == nil {
		return TaskResult{Success: false, Message: "刷新官方白名单失败: 数据库未初始化"}
	}
	updates := make(map[string]securitySettingUpdate)
	var refreshedCloudflareIPs []string

	if cfIPs, err := fetchCloudflareIPs(); err == nil {
		allIPs = append(allIPs, cfIPs...)
		details = append(details, fmt.Sprintf("Cloudflare: %d 条", len(cfIPs)))
		refreshedCloudflareIPs = append([]string(nil), cfIPs...)
		updates["cloudflare_realip_ips"] = securitySettingUpdate{
			value:       strings.Join(cfIPs, "\n"),
			description: "Cloudflare 官方 IP 段缓存",
		}
	} else {
		cfIPs, cacheErr := readCachedSecurityIPRanges(db, "cloudflare_realip_ips")
		if cacheErr != nil {
			return TaskResult{Success: false, Message: fmt.Sprintf("读取 Cloudflare IP 段缓存失败: %v", cacheErr)}
		}
		allIPs = append(allIPs, cfIPs...)
		details = append(details, fmt.Sprintf("Cloudflare: 获取失败，沿用缓存 %d 条", len(cfIPs)))
	}
	googleIPs, googleSource, googleErr := fetchGooglebotIPsWithFallback()
	if googleErr == nil {
		allIPs = append(allIPs, googleIPs...)
		details = append(details, fmt.Sprintf("Googlebot: %d 条（%s）", len(googleIPs), googlebotSourceLabel(googleSource)))
		updates["googlebot_ips"] = securitySettingUpdate{value: strings.Join(googleIPs, "\n"), description: "googlebot_ips 官方 IP 段缓存"}
		updates["googlebot_ips_source"] = securitySettingUpdate{value: googleSource, description: "Googlebot IP 段当前来源"}
		updates["googlebot_ips_last_success_at"] = securitySettingUpdate{value: time.Now().UTC().Format("2006-01-02 15:04:05"), description: "Googlebot IP 段最近成功更新时间"}
		updates["googlebot_ips_last_error"] = securitySettingUpdate{value: "", description: "Googlebot IP 段最近刷新错误"}
	} else {
		cached, cacheErr := readCachedSecurityIPRanges(db, "googlebot_ips")
		if cacheErr != nil {
			return TaskResult{Success: false, Message: fmt.Sprintf("读取 Googlebot IP 段缓存失败: %v", cacheErr)}
		}
		allIPs = append(allIPs, cached...)
		updates["googlebot_ips_last_error"] = securitySettingUpdate{value: googleErr.Error(), description: "Googlebot IP 段最近刷新错误"}
		if len(cached) > 0 {
			details = append(details, fmt.Sprintf("Googlebot: 官方与中转均失败，沿用缓存 %d 条", len(cached)))
		} else {
			details = append(details, "Googlebot: 官方与中转均失败，暂无有效缓存，可手动导入")
		}
	}
	if bingIPs, err := fetchBingbotIPs(); err == nil {
		allIPs = append(allIPs, bingIPs...)
		details = append(details, fmt.Sprintf("Bingbot: %d 条", len(bingIPs)))
		updates["bingbot_ips"] = securitySettingUpdate{value: strings.Join(bingIPs, "\n"), description: "bingbot_ips 官方 IP 段缓存"}
	} else {
		cached, cacheErr := readCachedSecurityIPRanges(db, "bingbot_ips")
		if cacheErr != nil {
			return TaskResult{Success: false, Message: fmt.Sprintf("读取 Bingbot IP 段缓存失败: %v", cacheErr)}
		}
		allIPs = append(allIPs, cached...)
		details = append(details, fmt.Sprintf("Bingbot: 获取失败，沿用缓存 %d 条", len(cached)))
	}

	updates["official_whitelist_ips"] = securitySettingUpdate{
		value:       strings.Join(uniqueStrings(allIPs), "\n"),
		description: "自动获取的官方 IP 白名单",
	}
	updates["last_whitelist_update"] = securitySettingUpdate{
		value:       time.Now().UTC().Format("2006-01-02 15:04:05"),
		description: "官方 IP 白名单最近更新时间",
	}
	if err := writeSecuritySettingUpdates(db, updates); err != nil {
		return TaskResult{Success: false, Message: fmt.Sprintf("保存官方白名单缓存失败: %v", err)}
	}

	if len(refreshedCloudflareIPs) > 0 {
		if err := DeployCloudflareRealIPConfig(refreshedCloudflareIPs); err != nil {
			details = append(details, "Cloudflare Real IP: 配置失败")
		} else {
			details = append(details, "Cloudflare Real IP: 已更新")
		}
	}

	if err := apply(); err != nil {
		return TaskResult{Success: false, Message: err.Error()}
	}

	return TaskResult{
		Success: true,
		Message: fmt.Sprintf("共获取 %d 条（%s）", len(allIPs), strings.Join(details, "；")),
	}
}

func googlebotSourceLabel(source string) string {
	if source == "relay" {
		return "OLS WPanel 中转"
	}
	if source == "manual" {
		return "手动导入"
	}
	return "Google 官方"
}

type securitySettingUpdate struct {
	value       string
	description string
}

func writeSecuritySettingUpdates(db *sql.DB, updates map[string]securitySettingUpdate) error {
	if db == nil {
		return errors.New("database is not initialized")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	keys := make([]string, 0, len(updates))
	for key := range updates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		update := updates[key]
		if _, err := tx.Exec(`INSERT INTO security_settings (skey, svalue, description, updated_at)
			VALUES (?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT(skey) DO UPDATE SET svalue = excluded.svalue, description = excluded.description, updated_at = excluded.updated_at`,
			key, update.value, update.description); err != nil {
			return fmt.Errorf("write security setting %q: %w", key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit security setting updates: %w", err)
	}
	return nil
}

func readCachedSecurityIPRanges(db *sql.DB, key string) ([]string, error) {
	raw, err := readRequiredFail2banSetting(db, key)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	ips, err := NormalizeOfficialIPRanges(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid cached ranges for %q: %w", key, err)
	}
	return ips, nil
}

// WithFail2banSettingsLock serializes every Fail2ban settings snapshot,
// deployment, and rollback. The callback receives the lock-aware internal
// apply function so callers can keep their database mutation and compensation
// in the same critical section without recursively acquiring the mutex.
func WithFail2banSettingsLock(fn func(apply func() error) error) error {
	if fn == nil {
		return errors.New("fail2ban settings callback is nil")
	}
	fail2banSettingsApplyMu.Lock()
	defer fail2banSettingsApplyMu.Unlock()
	return fn(applyFail2banSettingsLocked)
}

func ApplyFail2banSettings() error {
	return WithFail2banSettingsLock(func(apply func() error) error {
		return apply()
	})
}

func applyFail2banSettingsLocked() error {
	db := database.GetDB()
	if db == nil {
		return errors.New("apply Fail2ban settings: database is not initialized")
	}

	settings := make(map[string]string)
	for _, key := range []string{
		"official_whitelist_ips",
		"whitelist_ips",
		"ssh_whitelist_ips",
		"fail2ban_maxretry",
		"fail2ban_findtime",
		"wp_sqli_ban_threshold",
		"wp_sqli_ban_window_seconds",
		"auto_whitelist_enabled",
	} {
		value, err := readRequiredFail2banSetting(db, key)
		if err != nil {
			return err
		}
		settings[key] = value
	}
	cdnRealIPIPs, err := combinedCDNRealIPRangesForFail2ban(db)
	if err != nil {
		return err
	}

	webIPs, sshIPs := fail2banWhitelistScopes(settings, cdnRealIPIPs)

	mr, err := parseRequiredPositiveSetting("fail2ban_maxretry", settings["fail2ban_maxretry"])
	if err != nil {
		return err
	}
	ft, err := parseRequiredPositiveSetting("fail2ban_findtime", settings["fail2ban_findtime"])
	if err != nil {
		return err
	}
	sqliMR, err := parseRequiredPositiveSetting("wp_sqli_ban_threshold", settings["wp_sqli_ban_threshold"])
	if err != nil {
		return err
	}
	sqliFT, err := parseRequiredPositiveSetting("wp_sqli_ban_window_seconds", settings["wp_sqli_ban_window_seconds"])
	if err != nil {
		return err
	}
	autoEnabled := settings["auto_whitelist_enabled"]
	if autoEnabled != "true" && autoEnabled != "false" {
		return fmt.Errorf("invalid security setting %q: expected true or false", "auto_whitelist_enabled")
	}
	// The incremental ladder is intentionally fixed at 10m, 1h, 6h, 24h and 7d.
	bt := 600

	if err := deployFail2ban(webIPs, sshIPs, mr, ft, bt, sqliMR, sqliFT); err != nil {
		return err
	}

	if autoEnabled == "false" {
		if out, err := executeCommand("systemctl", "stop", "olswpanel-whitelist.timer"); err != nil {
			return fmt.Errorf("stop whitelist timer: %w: %s", err, strings.TrimSpace(out))
		}
		if out, err := executeCommand("systemctl", "disable", "olswpanel-whitelist.timer"); err != nil {
			return fmt.Errorf("disable whitelist timer: %w: %s", err, strings.TrimSpace(out))
		}
	} else {
		if err := DeployWhitelistTimer(); err != nil {
			return err
		}
	}
	return nil
}

func fail2banWhitelistScopes(settings map[string]string, cdnRealIPIPs string) (webIPs, sshIPs string) {
	// Official crawler/CDN ranges and website exceptions are only safe for web
	// jails. SSH has a separate, deliberately empty-by-default allowlist.
	webIPs = joinSecurityIPLists(
		settings["official_whitelist_ips"],
		settings["whitelist_ips"],
		cdnRealIPIPs,
	)
	sshIPs = strings.TrimSpace(settings["ssh_whitelist_ips"])
	return webIPs, sshIPs
}

func joinSecurityIPLists(values ...string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, "\n")
}

func readRequiredFail2banSetting(db *sql.DB, key string) (string, error) {
	if db == nil {
		return "", errors.New("read security setting: database is not initialized")
	}
	var value string
	if err := db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = ?`, key).Scan(&value); err != nil {
		return "", fmt.Errorf("read required security setting %q: %w", key, err)
	}
	return value, nil
}

func parseRequiredPositiveSetting(key, raw string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid security setting %q: expected a positive integer", key)
	}
	return value, nil
}

func combinedCDNRealIPRangesForFail2ban(db *sql.DB) (string, error) {
	if db == nil {
		return "", errors.New("read CDN real-IP ranges: database is not initialized")
	}
	rows, err := db.Query(`SELECT DISTINCT g.id, g.provider, g.ip_ranges
		FROM cdn_realip_groups g
		INNER JOIN website_cdn_realip_groups wg ON wg.group_id = g.id
		INNER JOIN websites w ON w.id = wg.website_id
		WHERE g.enabled = 1 AND w.cdn_realip_enabled = 1`)
	if err != nil {
		return "", fmt.Errorf("query CDN real-IP ranges for Fail2ban: %w", err)
	}

	type fail2banCDNGroup struct {
		id       int
		provider string
		raw      string
	}
	var groups []fail2banCDNGroup
	for rows.Next() {
		var group fail2banCDNGroup
		if err := rows.Scan(&group.id, &group.provider, &group.raw); err != nil {
			_ = rows.Close()
			return "", fmt.Errorf("scan CDN real-IP group for Fail2ban: %w", err)
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return "", fmt.Errorf("iterate CDN real-IP ranges for Fail2ban: %w", err)
	}
	if err := rows.Close(); err != nil {
		return "", fmt.Errorf("close CDN real-IP ranges query: %w", err)
	}

	seen := make(map[string]bool)
	var merged []string
	for _, group := range groups {
		raw := group.raw
		if group.provider == CDNProviderCloudflare && strings.TrimSpace(raw) == "" {
			raw, err = readRequiredFail2banSetting(db, "cloudflare_realip_ips")
			if err != nil {
				return "", fmt.Errorf("read Cloudflare ranges for CDN group %d: %w", group.id, err)
			}
		}
		ranges, err := NormalizeCDNRealIPRanges(raw)
		if err != nil {
			return "", fmt.Errorf("invalid CDN real-IP ranges for group %d: %w", group.id, err)
		}
		for _, item := range ranges {
			if !seen[item] {
				seen[item] = true
				merged = append(merged, item)
			}
		}
	}
	sort.Strings(merged)
	return strings.Join(merged, "\n"), nil
}

type fail2banJailIP struct{ jail, ip string }

type fail2banTicket struct {
	bannedAt  time.Time
	expiresAt time.Time
	duration  int
}

type fail2banSnapshot struct {
	active         map[fail2banJailIP]bool
	tickets        map[fail2banJailIP]fail2banTicket
	jailStatusRead map[string]bool
	webBanned      map[string]bool
	webStatusRead  bool
}

func readActiveFail2banBans() fail2banSnapshot {
	snapshot := fail2banSnapshot{
		active:         make(map[fail2banJailIP]bool),
		tickets:        make(map[fail2banJailIP]fail2banTicket),
		jailStatusRead: make(map[string]bool),
		webBanned:      make(map[string]bool),
	}

	for _, jail := range []string{"olswpanel", "olswpanel-404", "olswpanel-login", "olswpanel-sshd", "olswpanel-sqli"} {
		out, err := executeCommand("fail2ban-client", "status", jail)
		if err != nil || out == "" {
			log.Printf("Fail2ban 状态同步跳过 %s：无法读取 jail 状态", jail)
			continue
		}
		snapshot.jailStatusRead[jail] = true
		isWebJail := isWebBanSource(jail)
		if isWebJail {
			snapshot.webStatusRead = true
		}
		activeIPs := parseBannedIPs(out)
		for _, ip := range activeIPs {
			snapshot.active[fail2banJailIP{jail: jail, ip: ip}] = true
			if isWebJail {
				snapshot.webBanned[ip] = true
			}
		}
		if len(activeIPs) > 0 {
			if ticketOut, err := executeCommand("fail2ban-client", "get", jail, "banip", "--with-time"); err == nil {
				for ip, ticket := range parseFail2banTickets(ticketOut, time.Local) {
					pair := fail2banJailIP{jail: jail, ip: ip}
					if snapshot.active[pair] {
						snapshot.tickets[pair] = ticket
					}
				}
			} else {
				log.Printf("Fail2ban ticket 时间读取失败 %s：%v", jail, err)
			}
		}
	}
	return snapshot
}

func SyncFail2banBans() {
	syncMu.Lock()
	defer syncMu.Unlock()

	snapshot := readActiveFail2banBans()
	syncFail2banSnapshot(snapshot)
}

// SyncFail2banBansAndReadEnforcement reconciles lifecycle state and reuses the
// same Fail2ban snapshot for the current-ban view.
func SyncFail2banBansAndReadEnforcement() CurrentBanEnforcement {
	syncMu.Lock()
	defer syncMu.Unlock()

	snapshot := readActiveFail2banBans()
	syncFail2banSnapshot(snapshot)
	return readCurrentBanEnforcement(snapshot)
}

func syncFail2banSnapshot(snapshot fail2banSnapshot) {
	if sshRecordActionPending.Load() && snapshot.jailStatusRead["olswpanel-sshd"] {
		sshActive := false
		for pair := range snapshot.active {
			if pair.jail == "olswpanel-sshd" {
				sshActive = true
				break
			}
		}
		if !sshActive {
			if err := ensureFail2banSSHRecordAction(); err != nil {
				log.Printf("启用 SSH 封禁记录 action 失败: %v", err)
			}
		}
	}

	db := database.GetDB()
	reconcileFail2banBans(db, snapshot)
	reconcilePanelManagedBans(db, time.Now(), snapshot.webBanned)
}

func reconcileFail2banBans(db *sql.DB, snapshot fail2banSnapshot) {
	for pair := range snapshot.active {
		ticket, hasTicket := snapshot.tickets[pair]
		found, err := restoreActiveFail2banReceipt(db, pair, ticket, hasTicket)
		if err != nil || found {
			continue
		}
		banTime := 600
		if hasTicket {
			banTime = ticket.duration
		}
		if err := RecordFail2banBan(pair.ip, pair.jail, banTime, 1, false); err == nil && hasTicket {
			_, _ = restoreActiveFail2banReceipt(db, pair, ticket, true)
		}
	}

	rows, err := db.Query(`SELECT id, ip_address, source_jail FROM firewall_bans
		WHERE unbanned_at IS NULL
		AND source_jail IN ('olswpanel','olswpanel-404','olswpanel-login','olswpanel-sshd','olswpanel-sqli')`)
	if err != nil {
		return
	}
	defer rows.Close()

	var expiredIDs []int
	for rows.Next() {
		var id int
		var ip, jail string
		if rows.Scan(&id, &ip, &jail) != nil {
			continue
		}
		if !snapshot.jailStatusRead[jail] {
			if isWebBanSource(jail) {
				snapshot.webBanned[ip] = true
			}
			continue
		}
		if snapshot.active[fail2banJailIP{jail: jail, ip: ip}] {
			if err := removePanelManagedPersistBanIfUnused(db, ip); err != nil {
				log.Printf("清理 IP %s 的面板持久封禁失败，将在后续同步重试: %v", ip, err)
			}
			if isWebBanSource(jail) {
				snapshot.webBanned[ip] = true
			}
			continue
		}
		if err := removePanelManagedPersistBanIfUnused(db, ip); err != nil {
			log.Printf("清理已结束 Fail2ban 回执 IP %s 的面板持久封禁失败，请检查执行层: %v", ip, err)
		}
		expiredIDs = append(expiredIDs, id)
	}

	for _, id := range expiredIDs {
		db.Exec("UPDATE firewall_bans SET unbanned_at = datetime('now') WHERE id = ?", id)
	}
	return
}

func restoreActiveFail2banReceipt(db *sql.DB, pair fail2banJailIP, ticket fail2banTicket, hasTicket bool) (bool, error) {
	var id int
	var expiresAt *time.Time
	err := db.QueryRow(`SELECT id, expires_at FROM firewall_bans
		WHERE ip_address=? AND source_jail=? AND unbanned_at IS NULL
		ORDER BY banned_at DESC,id DESC LIMIT 1`, pair.ip, pair.jail).Scan(&id, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := db.Exec(`UPDATE firewall_bans SET unbanned_at=datetime('now')
		WHERE ip_address=? AND source_jail=? AND unbanned_at IS NULL AND id<>?`, pair.ip, pair.jail, id); err != nil {
		return false, err
	}
	if hasTicket {
		var expiry interface{}
		if ticket.expiresAt.After(time.Now()) {
			expiry = ticket.expiresAt.UTC().Format("2006-01-02 15:04:05")
		}
		_, err := db.Exec(`UPDATE firewall_bans SET banned_at=?,expires_at=?,ban_level=? WHERE id=?`,
			ticket.bannedAt.UTC().Format("2006-01-02 15:04:05"), expiry, fail2banBanLevel(ticket.duration), id)
		return true, err
	}
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		if _, err := db.Exec("UPDATE firewall_bans SET expires_at=NULL WHERE id=?", id); err != nil {
			return false, err
		}
	}
	return true, nil
}

func parseFail2banTickets(output string, location *time.Location) map[string]fail2banTicket {
	tickets := make(map[string]fail2banTicket)
	if location == nil {
		location = time.Local
	}
	for _, line := range strings.Split(output, "\n") {
		left, right, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		plus := strings.LastIndex(left, " + ")
		if plus < 0 {
			continue
		}
		identityAndTime := strings.Fields(strings.TrimSpace(left[:plus]))
		if len(identityAndTime) < 3 || net.ParseIP(identityAndTime[0]) == nil {
			continue
		}
		duration, err := strconv.Atoi(strings.TrimSpace(left[plus+3:]))
		if err != nil || duration < 1 || duration > 7*24*60*60 {
			continue
		}
		bannedAt, err := time.ParseInLocation("2006-01-02 15:04:05", strings.Join(identityAndTime[1:], " "), location)
		if err != nil {
			continue
		}
		expiresAt, err := time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(right), location)
		if err != nil || !expiresAt.After(bannedAt) {
			continue
		}
		tickets[identityAndTime[0]] = fail2banTicket{bannedAt: bannedAt, expiresAt: expiresAt, duration: duration}
	}
	return tickets
}

func reconcilePanelManagedBans(db *sql.DB, now time.Time, webBannedSet map[string]bool) {
	rows, err := db.Query(`SELECT id,ip_address,ban_level,expires_at,source_jail FROM firewall_bans
		WHERE unbanned_at IS NULL AND source_jail IN ('panel','panel_scan','manual')`)
	if err != nil {
		return
	}
	defer rows.Close()

	var expiredIDs []int
	expiredIPs := make(map[string]bool)
	var persistErrors []error
	for rows.Next() {
		var id, level int
		var ip, jail string
		var expiresAt *time.Time
		if rows.Scan(&id, &ip, &level, &expiresAt, &jail) != nil {
			continue
		}
		if expiresAt != nil && !expiresAt.After(now) {
			expiredIDs = append(expiredIDs, id)
			expiredIPs[ip] = true
			continue
		}
		// Manual bans are always backed by the persistent nftables set. The
		// level threshold applies only to automatically escalated panel bans.
		if jail == "manual" || level >= 3 {
			if err := syncAddPersistBan(ip); err != nil {
				persistErrors = append(persistErrors, err)
			}
		}
		if isWebBanSource(jail) {
			webBannedSet[ip] = true
		}
	}
	for _, id := range expiredIDs {
		db.Exec("UPDATE firewall_bans SET unbanned_at=datetime('now') WHERE id=?", id)
	}
	for ip := range expiredIPs {
		if err := removePanelManagedPersistBanIfUnused(db, ip); err != nil {
			persistErrors = append(persistErrors, err)
		}
	}
	if len(persistErrors) > 0 {
		log.Printf("持久封禁同步存在 %d 个失败，数据库记录已保留并将在下次同步重试: %v", len(persistErrors), errors.Join(persistErrors...))
	}
}

func removePanelManagedPersistBanIfUnused(db *sql.DB, ip string) error {
	var panelManagedCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM firewall_bans
		WHERE ip_address=? AND source_jail IN ('panel','panel_scan','manual') AND unbanned_at IS NULL
		AND (source_jail='manual' OR ban_level>=3)
		AND (expires_at IS NULL OR expires_at > datetime('now'))`, ip).Scan(&panelManagedCount)
	if panelManagedCount == 0 {
		return syncRemovePersistBan(ip)
	}
	return nil
}

func RecordFail2banBan(ip, jail string, banTime, banCount int, restored bool) error {
	db := database.GetDB()
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	if banTime < 1 || banTime > 7*24*60*60 {
		return fmt.Errorf("invalid Fail2ban ban time: %d", banTime)
	}
	if banCount < 1 || banCount > 1_000_000 {
		return fmt.Errorf("invalid Fail2ban ban count: %d", banCount)
	}

	jail = normalizeFail2banJail(jail)
	if jail == "" {
		jail = detectFail2banJail(ip)
		if jail == "" {
			jail = "olswpanel"
		}
	}
	if restored {
		// Fail2ban restart runs actionunban while stopping, then restores active
		// tickets with actionban. Reopen the existing receipt without creating a
		// new history row or incrementing its counter.
		_, err := db.Exec(`UPDATE firewall_bans SET unbanned_at=NULL
			WHERE id = (
				SELECT id FROM firewall_bans
				WHERE ip_address=? AND source_jail=? AND is_manual=0
				ORDER BY id DESC LIMIT 1
			)`, ip, jail)
		return err
	}

	banLevel := fail2banBanLevel(banTime)
	reason := "Fail2ban 自动封禁"
	if jail == "olswpanel-404" {
		reason = "404 泛滥检测"
	} else if jail == "olswpanel-sshd" {
		reason = "SSH 暴力破解"
	} else if jail == "olswpanel-login" {
		reason = "登录/XML-RPC 认证爆破"
	} else if jail == "olswpanel-sqli" {
		reason = "重复高置信度 SQL 注入请求"
	}
	expiresModifier := fmt.Sprintf("+%d seconds", banTime)

	var protectedCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM firewall_bans WHERE ip_address=? AND (is_manual=1 OR ban_level>=5)
		AND unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))`, ip).Scan(&protectedCount)
	if protectedCount > 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var activeID, activeLevel int
	err = tx.QueryRow(
		`SELECT id, ban_level
		 FROM firewall_bans
		 WHERE ip_address = ? AND source_jail = ? AND is_manual=0 AND unbanned_at IS NULL
		   AND (expires_at IS NULL OR expires_at > datetime('now'))
		 ORDER BY id DESC LIMIT 1`,
		ip, jail,
	).Scan(&activeID, &activeLevel)
	if err == nil {
		if activeLevel >= 5 {
			return nil
		}
		if _, err := tx.Exec(
			`UPDATE firewall_bans
			 SET ban_level = ?, reason = ?, source_jail = ?, ban_count = ?,
			     banned_at = CURRENT_TIMESTAMP, expires_at = datetime('now', ?)
			 WHERE id = ?`,
			banLevel, reason, jail, banCount, expiresModifier, activeID,
		); err != nil {
			return err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	} else if _, err := tx.Exec(
		`INSERT INTO firewall_bans (ip_address, ban_level, reason, source_jail, ban_count, expires_at)
		 VALUES (?, ?, ?, ?, ?, datetime('now', ?))`,
		ip, banLevel, reason, jail, banCount, expiresModifier,
	); err != nil {
		return err
	}
	if err := insertFirewallBanHistory(tx, ip, banLevel, reason, jail, banCount, false, banTime); err != nil {
		return err
	}
	return tx.Commit()
}

func insertFirewallBanHistory(tx *sql.Tx, ip string, level int, reason, jail string, banCount int, manual bool, duration int) error {
	manualValue := 0
	if manual {
		manualValue = 1
	}
	if duration < 0 {
		_, err := tx.Exec(`INSERT INTO firewall_ban_history
			(ip_address,ban_level,reason,source_jail,ban_count,is_manual,duration_seconds,expires_at)
			VALUES (?,?,?,?,?,?,NULL,NULL)`, ip, level, reason, jail, banCount, manualValue)
		return err
	}
	modifier := fmt.Sprintf("+%d seconds", duration)
	_, err := tx.Exec(`INSERT INTO firewall_ban_history
		(ip_address,ban_level,reason,source_jail,ban_count,is_manual,duration_seconds,expires_at)
		VALUES (?,?,?,?,?,?,?,datetime('now',?))`, ip, level, reason, jail, banCount, manualValue, duration, modifier)
	return err
}

func fail2banBanLevel(banTime int) int {
	if banTime <= 10*60 {
		return 2
	}
	if banTime <= 24*60*60 {
		return 3
	}
	return 4
}

func RecordFail2banUnban(ip, jail string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	jail = normalizeFail2banJail(jail)
	if jail == "" {
		return fmt.Errorf("invalid Fail2ban jail")
	}
	_, err := database.GetDB().Exec(`UPDATE firewall_bans SET unbanned_at=datetime('now')
		WHERE ip_address=? AND source_jail=? AND is_manual=0 AND unbanned_at IS NULL`, ip, jail)
	if err != nil {
		return err
	}
	if isWebBanSource(jail) {
		return maybeRemoveWebPersistBan(ip)
	}
	return nil
}

func maybeRemoveWebPersistBan(ip string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	var activeWebBans int
	err := database.GetDB().QueryRow(`SELECT COUNT(*) FROM firewall_bans
		WHERE ip_address=? AND source_jail IN ('olswpanel','olswpanel-404','olswpanel-login','olswpanel-sqli','manual')
		AND unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))`, ip).Scan(&activeWebBans)
	if err != nil || activeWebBans > 0 {
		return err
	}
	return conditionalRemoveWebPersistBan(ip)
}

func MaybeRemovePersistBan(ip string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	var activePersistentBans int
	err := database.GetDB().QueryRow(`SELECT COUNT(*) FROM firewall_bans
		WHERE ip_address=? AND (is_manual=1 OR ban_level>=5)
		AND unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))`, ip).Scan(&activePersistentBans)
	if err != nil || activePersistentBans > 0 {
		return err
	}
	return RemovePersistBan(ip)
}

type activeFirewallBanCandidate struct {
	id       int
	level    int
	count    int
	bannedAt string
}

func deduplicateActiveFirewallBans(db *sql.DB) error {
	if db == nil {
		return nil
	}
	rows, err := db.Query(`
		SELECT ip_address, source_jail
		FROM firewall_bans
		WHERE unbanned_at IS NULL
			AND (expires_at IS NULL OR expires_at > datetime('now'))
		GROUP BY ip_address, source_jail
		HAVING COUNT(*) > 1`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type duplicateGroup struct{ ip, jail string }
	var groups []duplicateGroup
	for rows.Next() {
		var group duplicateGroup
		if err := rows.Scan(&group.ip, &group.jail); err != nil {
			return err
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, group := range groups {
		if err := deduplicateActiveFirewallBanIP(db, group.ip, group.jail); err != nil {
			return err
		}
	}
	return nil
}

func deduplicateActiveFirewallBanIP(db *sql.DB, ip, jail string) error {
	if db == nil || ip == "" || jail == "" {
		return nil
	}
	rows, err := db.Query(`
		SELECT id, ban_level, ban_count, banned_at
		FROM firewall_bans
		WHERE ip_address = ? AND source_jail = ? AND unbanned_at IS NULL
			AND (expires_at IS NULL OR expires_at > datetime('now'))
		ORDER BY ban_level DESC, banned_at DESC, id DESC`, ip, jail)
	if err != nil {
		return err
	}
	defer rows.Close()

	var bans []activeFirewallBanCandidate
	for rows.Next() {
		var row activeFirewallBanCandidate
		if err := rows.Scan(&row.id, &row.level, &row.count, &row.bannedAt); err != nil {
			return err
		}
		bans = append(bans, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(bans) <= 1 {
		return nil
	}

	keep := bans[0]
	maxCount := keep.count
	var duplicateIDs []int
	for _, ban := range bans[1:] {
		duplicateIDs = append(duplicateIDs, ban.id)
		if ban.count > maxCount {
			maxCount = ban.count
		}
	}
	if _, err := db.Exec(`UPDATE firewall_bans SET ban_count = ? WHERE id = ?`, maxCount, keep.id); err != nil {
		return err
	}
	for _, id := range duplicateIDs {
		if _, err := db.Exec(`UPDATE firewall_bans SET unbanned_at = datetime('now') WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}

func normalizeFail2banJail(jail string) string {
	switch strings.TrimSpace(jail) {
	case "olswpanel", "olswpanel-404", "olswpanel-login", "olswpanel-sshd", "olswpanel-sqli":
		return strings.TrimSpace(jail)
	default:
		return ""
	}
}

func isWebBanSource(jail string) bool {
	return jail == "olswpanel" || jail == "olswpanel-404" || jail == "olswpanel-login" || jail == "olswpanel-sqli" || jail == "manual"
}

func detectFail2banJail(ip string) string {
	for _, jail := range []string{"olswpanel", "olswpanel-404", "olswpanel-login", "olswpanel-sqli"} {
		out, err := executeCommand("fail2ban-client", "status", jail)
		if err != nil {
			continue
		}
		for _, bannedIP := range parseBannedIPs(out) {
			if bannedIP == ip {
				return jail
			}
		}
	}
	return ""
}

type persistBanFamily struct {
	family   string
	setType  string
	saddr    string
	sshLimit bool
}

var persistBanFamilies = []persistBanFamily{
	{family: "ip", setType: "ipv4_addr", saddr: "ip", sshLimit: true},
	{family: "ip6", setType: "ipv6_addr", saddr: "ip6"},
}

func persistFamilyFor(ip net.IP) (persistBanFamily, error) {
	if ip == nil {
		return persistBanFamily{}, errors.New("invalid IP")
	}
	if ip.To4() != nil {
		return persistBanFamilies[0], nil
	}
	return persistBanFamilies[1], nil
}

func nftErrorContains(output string, err error, fragment string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(output+" "+err.Error()), strings.ToLower(fragment))
}

func runPersistNft(args ...string) error {
	out, err := persistNftExec(args...)
	if err == nil || nftErrorContains(out, err, "file exists") {
		return nil
	}
	if out != "" {
		return fmt.Errorf("nft %s failed: %w (%s)", strings.Join(args, " "), err, out)
	}
	return fmt.Errorf("nft %s failed: %w", strings.Join(args, " "), err)
}

func ensurePersistNftablesLocked() error {
	var errs []error
	for _, family := range persistBanFamilies {
		if err := ensurePersistFamilyLocked(family); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func ensurePersistFamilyLocked(family persistBanFamily) error {
	if err := runPersistNft("add", "table", family.family, "olswpanel_persist"); err != nil {
		return err
	}
	if err := runPersistNft("add", "chain", family.family, "olswpanel_persist", "input", "{", "type", "filter", "hook", "input", "priority", "-1", ";", "}"); err != nil {
		return err
	}
	if err := runPersistNft("add", "set", family.family, "olswpanel_persist", "banned_ips", "{", "type", family.setType, ";", "}"); err != nil {
		return err
	}
	chain, err := persistNftExec("list", "chain", family.family, "olswpanel_persist", "input")
	if err != nil {
		return fmt.Errorf("list nft %s persist chain: %w", family.family, err)
	}
	banRule := family.saddr + " saddr @banned_ips drop"
	if !strings.Contains(chain, banRule) {
		if err := runPersistNft("add", "rule", family.family, "olswpanel_persist", "input", family.saddr, "saddr", "@banned_ips", "drop"); err != nil {
			return err
		}
	}
	if !family.sshLimit {
		return nil
	}
	if err := runPersistNft("add", "set", "ip", "olswpanel_persist", "ssh_limit", "{", "type", "ipv4_addr", ";", "flags", "dynamic,timeout", ";", "timeout", "1m", ";", "size", "65535", ";", "}"); err != nil {
		return err
	}
	chain, err = persistNftExec("list", "chain", "ip", "olswpanel_persist", "input")
	if err != nil {
		return fmt.Errorf("list nft ip persist chain: %w", err)
	}
	if !strings.Contains(chain, "tcp dport 22 ct state new") {
		return runPersistNft("add", "rule", "ip", "olswpanel_persist", "input", "tcp", "dport", "22", "ct", "state", "new", "add", "@ssh_limit", "{", "ip", "saddr", "limit", "rate", "over", "3/minute", "}", "drop")
	}
	return nil
}

func EnsurePersistNftables() error {
	persistNftMu.Lock()
	defer persistNftMu.Unlock()
	return ensurePersistNftablesLocked()
}

func AddPersistBan(ip string) error {
	normalized, ok := NormalizeIP(ip)
	if !ok {
		return fmt.Errorf("invalid IP: %s", strings.TrimSpace(ip))
	}
	family, _ := persistFamilyFor(net.ParseIP(normalized))
	persistNftMu.Lock()
	defer persistNftMu.Unlock()
	if err := ensurePersistFamilyLocked(family); err != nil {
		return err
	}
	return runPersistNft("add", "element", family.family, "olswpanel_persist", "banned_ips", "{", normalized, "}")
}

func RemovePersistBan(ip string) error {
	normalized, ok := NormalizeIP(ip)
	if !ok {
		return fmt.Errorf("invalid IP: %s", strings.TrimSpace(ip))
	}
	family, _ := persistFamilyFor(net.ParseIP(normalized))
	persistNftMu.Lock()
	defer persistNftMu.Unlock()
	out, err := persistNftExec("delete", "element", family.family, "olswpanel_persist", "banned_ips", "{", normalized, "}")
	if err == nil || nftErrorContains(out, err, "no such file or directory") || nftErrorContains(out, err, "no such file") {
		return nil
	}
	return fmt.Errorf("remove nft %s persistent ban: %w", family.family, err)
}

func parseBannedIPs(status string) []string {
	var ips []string
	for _, line := range strings.Split(status, "\n") {
		idx := strings.Index(line, "Banned IP list:")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len("Banned IP list:"):])
		for _, ip := range strings.Fields(rest) {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func fetchCloudflareIPs() ([]string, error) {
	var ips []string
	for _, url := range []string{
		"https://www.cloudflare.com/ips-v4/",
		"https://www.cloudflare.com/ips-v6/",
	} {
		out, err := executeCommand("curl", "-s", "-f", "-L", url)
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					ips = append(ips, line)
				}
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("无法获取 Cloudflare IP 段")
	}
	return ips, nil
}

func fetchGooglebotIPs() ([]string, error) {
	return fetchGooglebotIPsFromURL(googlebotOfficialURL)
}

func fetchGooglebotIPsWithFallback() ([]string, string, error) {
	ips, err := fetchGooglebotIPs()
	if err != nil {
		return nil, "", fmt.Errorf("Google 官方源: %w", err)
	}
	return ips, "official", nil
}

func fetchGooglebotIPsFromURL(url string) ([]string, error) {
	resp, err := googlebotHTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var data struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	var ips []string
	for _, p := range data.Prefixes {
		if p.IPv4Prefix != "" {
			ips = append(ips, p.IPv4Prefix)
		}
		if p.IPv6Prefix != "" {
			ips = append(ips, p.IPv6Prefix)
		}
	}
	return validateOfficialIPRanges(ips)
}

// NormalizeOfficialIPRanges 接受一行一个 IP/CIDR，返回可安全用于官方爬虫验证的公网网段。
func NormalizeOfficialIPRanges(raw string) ([]string, error) {
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		var data struct {
			Prefixes []struct {
				IPv4Prefix string `json:"ipv4Prefix"`
				IPv6Prefix string `json:"ipv6Prefix"`
			} `json:"prefixes"`
		}
		if err := json.Unmarshal([]byte(raw), &data); err != nil {
			return nil, fmt.Errorf("JSON 格式不正确: %w", err)
		}
		var values []string
		for _, prefix := range data.Prefixes {
			values = append(values, prefix.IPv4Prefix, prefix.IPv6Prefix)
		}
		return validateOfficialIPRanges(values)
	}
	var ips []string
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' }) {
		ips = append(ips, strings.TrimSpace(field))
	}
	return validateOfficialIPRanges(ips)
}

func validateOfficialIPRanges(ips []string) ([]string, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("IP 段为空")
	}
	if len(ips) > 512 {
		return nil, fmt.Errorf("IP 段数量超过 512 条")
	}
	var normalized []string
	for _, value := range uniqueStrings(ips) {
		ip, network, err := net.ParseCIDR(value)
		if err != nil {
			ip = net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("无效 IP/CIDR: %s", value)
			}
			if ip.To4() != nil {
				value += "/32"
			} else {
				value += "/128"
			}
			_, network, _ = net.ParseCIDR(value)
		}
		ones, bits := network.Mask.Size()
		if (bits == 32 && ones < 16) || (bits == 128 && ones < 32) || !isPublicOfficialIP(ip) {
			return nil, fmt.Errorf("不允许过宽或非公网 IP 段: %s", value)
		}
		normalized = append(normalized, network.String())
	}
	return uniqueStrings(normalized), nil
}

func isPublicOfficialIP(ip net.IP) bool {
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast() && !ip.IsUnspecified()
}

// IsPublicIPAddress reports whether value is a single globally routable IP.
// Security middleware uses this before persisting automatic bans so spoofed
// loopback/private addresses cannot pollute ban history.
func IsPublicIPAddress(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	return ip != nil && isPublicOfficialIP(ip)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func fetchBingbotIPs() ([]string, error) {
	out, err := executeCommand("curl", "-s", "-f", "-L", "https://www.bing.com/toolbox/bingbot.json")
	if err != nil {
		return nil, err
	}
	var data struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		return nil, err
	}
	var ips []string
	for _, p := range data.Prefixes {
		if p.IPv4Prefix != "" {
			ips = append(ips, p.IPv4Prefix)
		}
		if p.IPv6Prefix != "" {
			ips = append(ips, p.IPv6Prefix)
		}
	}
	return ips, nil
}

func executeManualBan(task *Task) TaskResult {
	payload, ok := task.Payload.(*ManualBanPayload)
	if !ok {
		return TaskResult{Success: false, Message: "任务参数类型错误"}
	}

	ip := strings.TrimSpace(payload.IP)
	if ip == "" {
		return TaskResult{Success: false, Message: "IP 地址不能为空"}
	}

	if net.ParseIP(ip) == nil {
		return TaskResult{Success: false, Message: "IP 地址格式不正确"}
	}

	db := database.GetDB()
	if db == nil {
		return TaskResult{Success: false, Message: "database not initialized"}
	}

	jail := "manual"
	banLevel := 2
	duration := 600
	if payload.Duration == 3600 {
		duration = 3600
		banLevel = 3
	} else if payload.Duration == 86400 {
		duration = 86400
		banLevel = 3
	} else if payload.Duration == 0 {
		duration = -1
		banLevel = 5
	}

	var expires interface{}
	if duration < 0 {
		expires = nil
	} else {
		expires = time.Now().Add(time.Duration(duration) * time.Second)
	}

	if err := manualAddPersistBan(ip); err != nil {
		return TaskResult{Success: false, Message: "封禁失败: " + err.Error()}
	}

	tx, err := db.Begin()
	if err != nil {
		_ = manualRemovePersistBan(ip)
		return TaskResult{Success: false, Message: "封禁记录写入失败"}
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO firewall_bans (ip_address, ban_level, reason, source_jail, is_manual, ban_count, expires_at)
		 VALUES (?, ?, '管理员手动封禁', ?, 1, 1, ?)`,
		ip, banLevel, jail, expires,
	); err != nil {
		_ = manualRemovePersistBan(ip)
		return TaskResult{Success: false, Message: "封禁记录写入失败"}
	}
	if err := insertFirewallBanHistory(tx, ip, banLevel, "管理员手动封禁", jail, 1, true, duration); err != nil {
		_ = manualRemovePersistBan(ip)
		return TaskResult{Success: false, Message: "封禁历史写入失败"}
	}
	if err := tx.Commit(); err != nil {
		_ = manualRemovePersistBan(ip)
		return TaskResult{Success: false, Message: "封禁记录写入失败"}
	}

	msg := fmt.Sprintf("IP %s 已封禁", ip)
	if payload.Duration == 0 {
		msg += "（永久）"
	} else if payload.Duration >= 3600 {
		msg += fmt.Sprintf("（%d 小时）", payload.Duration/3600)
	} else {
		msg += fmt.Sprintf("（%d 分钟）", payload.Duration/60)
	}

	return TaskResult{Success: true, Message: msg}
}

func parseIntOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func RunWhitelistRefresh() string {
	return executeRefreshWhitelist(&Task{ID: "cli-refresh", Type: TaskRefreshWhitelist}).Message
}

func DeployWhitelistTimer() error {
	timerUnit := `[Unit]
Description=OLS WPanel Weekly Whitelist Refresh
Requires=olswpanel-whitelist.service

[Timer]
OnCalendar=Mon *-*-* 04:00:00
Persistent=true

[Install]
WantedBy=timers.target
`

	serviceUnit := `[Unit]
Description=OLS WPanel Whitelist Refresh

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ols-wpanel --refresh-whitelist --config=/www/ols-wpanel/config.json
`

	if err := os.WriteFile("/etc/systemd/system/olswpanel-whitelist.timer", []byte(timerUnit), 0644); err != nil {
		return fmt.Errorf("写入白名单定时器失败: %w", err)
	}
	if err := os.WriteFile("/etc/systemd/system/olswpanel-whitelist.service", []byte(serviceUnit), 0644); err != nil {
		return fmt.Errorf("写入白名单刷新服务失败: %w", err)
	}
	if _, err := executeCommand("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("重载 systemd 配置失败: %w", err)
	}
	if _, err := executeCommand("systemctl", "enable", "olswpanel-whitelist.timer"); err != nil {
		return fmt.Errorf("启用白名单定时器失败: %w", err)
	}
	if _, err := executeCommand("systemctl", "start", "olswpanel-whitelist.timer"); err != nil {
		return fmt.Errorf("启动白名单定时器失败: %w", err)
	}
	return nil
}

func UnbanAllIPs() string {
	db := database.GetDB()

	unbanned, _ := db.Exec("UPDATE firewall_bans SET unbanned_at = datetime('now') WHERE unbanned_at IS NULL")
	unbanCount := int64(0)
	if unbanned != nil {
		unbanCount, _ = unbanned.RowsAffected()
	}

	for _, family := range []string{"ip", "ip6"} {
		out, err := persistNftExec("flush", "set", family, "olswpanel_persist", "banned_ips")
		if err != nil && !nftErrorContains(out, err, "no such file") {
			log.Printf("清空 %s 持久封禁集合失败: %v", family, err)
		}
	}
	for _, jail := range []string{"olswpanel", "olswpanel-404", "olswpanel-login", "olswpanel-sshd", "olswpanel-sqli"} {
		out, err := executeCommand("fail2ban-client", "status", jail)
		if err == nil && out != "" {
			for _, ip := range parseBannedIPs(out) {
				executeCommand("fail2ban-client", "set", jail, "unbanip", ip)
			}
		}
	}

	return fmt.Sprintf("已清空所有封禁规则，共解封 %d 条记录", unbanCount)
}

func CleanExpiredBans() {
	db := database.GetDB()

	rows, err := db.Query(`SELECT id, ip_address, source_jail FROM firewall_bans
		WHERE unbanned_at IS NULL AND expires_at IS NOT NULL AND expires_at <= datetime('now')`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var ip, jail string
		if rows.Scan(&id, &ip, &jail) != nil {
			continue
		}

		// Fail2ban-controlled bans are closed by actionunban or SyncFail2banBans.
		// Do not expire them from the panel clock while Fail2ban may still enforce them.
		// normalizeFail2banJail recognizes every Fail2ban-managed jail name, so a
		// future jail addition can't silently fall through this skip list again.
		if normalizeFail2banJail(jail) != "" {
			continue
		}
		db.Exec("UPDATE firewall_bans SET unbanned_at = datetime('now') WHERE id = ?", id)
		if err := removePanelManagedPersistBanIfUnused(db, ip); err != nil {
			log.Printf("清理已过期 IP %s 的持久封禁失败，请检查执行层: %v", ip, err)
		}
		if isWebBanSource(jail) {
			_ = maybeRemoveWebPersistBan(ip)
		}
	}
}

func StartFail2banSyncScheduler() {
	GoSafe(func() {
		SyncFail2banBans()
		CleanExpiredBans()
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			SyncFail2banBans()
			CleanExpiredBans()
		}
	})
}
