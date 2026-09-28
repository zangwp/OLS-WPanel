package executor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/database"
)

type OLSVHostData struct {
	Domain           string
	Aliases          []string
	ServerNames      string
	WebRoot          string
	LogDir           string
	SystemUser       string
	UseSSL           bool
	SSLCertPath      string
	SSLKeyPath       string
	PHPProxy         string
	LSPHPBinary      string
	TemplateVer      string
	AccessLogMode    string
	LSCacheEnabled   bool
	LSCacheTTL       int
	LSCacheKey       string
	SiteType         string
	RateLimitEnabled bool
	RateLimitBurst   int
	BotLimitEnabled  bool
	BotLimitBurst    int
	XMLRPCEnabled    bool
	CDNRealIPEnabled bool
	CDNRealIPHeader  string
	CDNRealIPRanges  []string
	CDNRealIPCompat  bool
	SQLiBlockEnabled bool
	SQLiAutoBanLog   bool
	PHPMaxChildren   int
}

type TemplateEngine struct {
	BackupDir string
}

const olsVHostConfigBackupKeepCount = 7

func NormalizeWPSecurityLogWhitelist(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	lines := strings.Split(raw, "\n")
	if len(lines) > 200 {
		return nil, fmt.Errorf("WordPress安全日志白名单最多200行")
	}
	patterns := make([]string, 0, len(lines))
	seen := map[string]bool{}
	for _, line := range lines {
		pattern := strings.TrimSpace(line)
		if pattern == "" {
			continue
		}
		if len(pattern) > 200 {
			return nil, fmt.Errorf("白名单路径过长: %s", pattern)
		}
		if !strings.HasPrefix(pattern, "/") {
			return nil, fmt.Errorf("白名单路径必须以 / 开头: %s", pattern)
		}
		if strings.ContainsAny(pattern, " \t\r\n;{}()[]^~\\\"'`$#") {
			return nil, fmt.Errorf("白名单路径包含不允许的字符: %s", pattern)
		}
		if strings.Contains(pattern, "..") {
			return nil, fmt.Errorf("白名单路径不能包含 ..: %s", pattern)
		}
		if !seen[pattern] {
			patterns = append(patterns, pattern)
			seen[pattern] = true
		}
	}
	return patterns, nil
}

func NewTemplateEngine(backupDir string) *TemplateEngine {
	os.MkdirAll(backupDir, 0755)
	return &TemplateEngine{BackupDir: backupDir}
}

func (e *TemplateEngine) RenderOLSVHostConfig(data *OLSVHostData) (string, error) {
	return renderOLSVHostConfig(data)
}

func GetSQLiProtectionSettings() (blockEnabled, autoBanEnabled bool) {
	blockEnabled, autoBanEnabled = true, true
	if database.GetDB() == nil {
		return
	}
	var block, autoBan string
	_ = database.GetDB().QueryRow(`SELECT svalue FROM security_settings WHERE skey='wp_sqli_block_enabled'`).Scan(&block)
	_ = database.GetDB().QueryRow(`SELECT svalue FROM security_settings WHERE skey='wp_sqli_autoban_enabled'`).Scan(&autoBan)
	if block != "" {
		blockEnabled = block == "true"
	}
	if autoBan != "" {
		autoBanEnabled = autoBan == "true"
	}
	return
}

func (e *TemplateEngine) ApplyOLSVHostConfig(configContent string, targetPath string, enabledPath string) error {
	if locked, err := siteMigrationLockedByOLSVHostConfig(targetPath); err != nil {
		return fmt.Errorf("检查站点迁移锁失败: %w", err)
	} else if locked {
		return errSiteMigrationBusy
	}
	return applyOLSVHostConfig(e, configContent, targetPath, enabledPath)
}

func siteMigrationLockedByOLSVHostConfig(targetPath string) (bool, error) {
	db := database.GetDB()
	if db == nil || strings.TrimSpace(targetPath) == "" {
		return false, nil
	}
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM site_migration_locks ml
		JOIN websites w ON w.id=ml.site_id
		WHERE ml.status='active' AND w.ols_vhost_config_path=?`, filepath.Clean(targetPath)).Scan(&count)
	return count > 0, err
}

// ApplyOLSVHostConfigKeepDisabled 校验并写入 OpenLiteSpeed 配置文件内容（含旧配置备份），
// 但不创建/恢复 sites-enabled 软链接，也不触发 reload。
// 用于刷新已暂停网站的配置模板，避免把暂停中的站点重新暴露为可访问。
func (e *TemplateEngine) ApplyOLSVHostConfigKeepDisabled(configContent string, targetPath string) error {
	return e.writeOLSVHostConfigFile(configContent, targetPath)
}

// writeOLSVHostConfigFile 校验 OpenLiteSpeed 配置语法，备份旧文件后写入 targetPath。
// 不涉及启用链接和 OpenLiteSpeed 重载，由调用方决定是否启用。
func (e *TemplateEngine) writeOLSVHostConfigFile(configContent string, targetPath string) error {
	if err := validateOLSVHostContent(configContent, targetPath); err != nil {
		return err
	}
	old, err := os.ReadFile(targetPath)
	hadOld := err == nil
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := writeOLSFileAtomic(targetPath, []byte(configContent), 0640); err != nil {
		return fmt.Errorf("写入 OpenLiteSpeed 虚拟主机配置失败: %w", err)
	}
	if e != nil && e.BackupDir != "" && hadOld && !bytes.Equal(old, []byte(configContent)) {
		backupDir := filepath.Join(e.BackupDir, "openlitespeed")
		if err := os.MkdirAll(backupDir, 0750); err == nil {
			backupName := filepath.Base(targetPath) + fmt.Sprintf(".bak.%d", time.Now().UnixNano())
			_ = os.WriteFile(filepath.Join(backupDir, backupName), old, 0600)
		}
	}
	return nil
}

func (e *TemplateEngine) RemoveOLSVHostConfig(targetPath string, enabledPath string) error {
	if err := os.Remove(enabledPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	_, err := reloadOLSManagedRegistry(filepath.Dir(enabledPath))
	return err
}

func getConfBaseName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

func cleanupOLSVHostConfigBackups(backupDir, targetPath string, keepCount int) int {
	if keepCount <= 0 {
		keepCount = olsVHostConfigBackupKeepCount
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return 0
	}

	prefix := getConfBaseName(targetPath) + ".bak."
	type backupFile struct {
		name string
		ts   int64
	}
	backups := make([]backupFile, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		ts, err := strconv.ParseInt(strings.TrimPrefix(entry.Name(), prefix), 10, 64)
		if err != nil {
			continue
		}
		backups = append(backups, backupFile{name: entry.Name(), ts: ts})
	}
	if len(backups) <= keepCount {
		return 0
	}

	sort.Slice(backups, func(i, j int) bool {
		if backups[i].ts == backups[j].ts {
			return backups[i].name > backups[j].name
		}
		return backups[i].ts > backups[j].ts
	})

	removed := 0
	for _, backup := range backups[keepCount:] {
		if os.Remove(filepath.Join(backupDir, backup.name)) == nil {
			removed++
		}
	}
	return removed
}
