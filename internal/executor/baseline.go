package executor

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func EnsureWordPressBaseline() {
	ensurePHPBaseline()
	ensureOpenLiteSpeedBaseline()
	ensureMariaDBBaseline()
	ensureRedisBaseline()
	ensureWordPressLoginAuditBaseline()
}

func ensureWordPressLoginAuditBaseline() {
	db := database.GetDB()
	if db == nil {
		return
	}
	rows, err := db.Query(`SELECT id, domain, web_root, log_dir, system_user FROM websites WHERE site_type != 'php'`)
	if err != nil {
		log.Printf("[OLS-WPanel] 读取 WordPress 登录审计基线失败: %v", err)
		return
	}
	type auditSite struct {
		id                            int
		domain, webRoot, logDir, user string
	}
	var sites []auditSite
	for rows.Next() {
		var site auditSite
		if err := rows.Scan(&site.id, &site.domain, &site.webRoot, &site.logDir, &site.user); err != nil {
			log.Printf("[OLS-WPanel] 读取 WordPress 登录审计站点失败: %v", err)
			continue
		}
		sites = append(sites, site)
	}
	readErr := rows.Err()
	rows.Close() // PHP-runtime lookup may use the same SQLite connection.
	if readErr != nil {
		log.Printf("[OLS-WPanel] WordPress 登录审计基线扫描失败: %v", readErr)
	}
	for _, site := range sites {
		if !TryAcquireSiteOpLock(site.id, "login-audit-baseline") {
			log.Printf("[OLS-WPanel] 网站维护中，跳过登录审计基线 site=%d", site.id)
			continue
		}
		err := ConfigureWPLoginFailureLogging(site.webRoot, site.logDir, site.user)
		ReleaseSiteOpLock(site.id)
		if err != nil {
			log.Printf("[OLS-WPanel] WordPress 登录审计基线未启用 domain=%s: %v", site.domain, err)
		}
	}
}

func ensurePHPBaseline() {
	changed, err := EnsurePHPRuntimeConfigFile()
	if err == nil && changed {
		// Do not start a service deliberately stopped by the administrator.
		if exec.Command("systemctl", "is-active", "--quiet", "lshttpd").Run() != nil {
			return
		}
		paths := currentOLSRuntimePaths()
		if out, err := exec.Command(paths.binary, "-t").CombinedOutput(); err != nil {
			log.Printf("[OLS-WPanel] PHP baseline changed; OLS validation failed, service left running: %v: %s", err, strings.TrimSpace(string(out)))
			return
		}
		if out, err := exec.Command("systemctl", "restart", "lshttpd").CombinedOutput(); err != nil {
			log.Printf("[OLS-WPanel] PHP baseline OLS restart failed: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
}

func ensureOpenLiteSpeedBaseline() {
	paths := currentOLSRuntimePaths()
	if out, err := exec.Command(paths.binary, "-t").CombinedOutput(); err != nil {
		log.Printf("[OLS-WPanel] OpenLiteSpeed 配置检查失败: %s", strings.TrimSpace(string(out)))
	}
}

func ensureMariaDBBaseline() {
	path := "/etc/mysql/mariadb.conf.d/99-olswpanel.cnf"
	if _, err := os.Stat(path); err == nil {
		return
	}
	poolSize := fmt.Sprintf("%dM", RecommendInnoDBBufferPoolSizeMB(CollectSystemFacts()))
	content := fmt.Sprintf(`# OLS WPanel — WordPress 安全基线 (安装时自动生成)
[mysqld]
innodb_buffer_pool_size = %s
`, poolSize)
	os.WriteFile(path, []byte(content), 0644)
	exec.Command("systemctl", "restart", "mariadb").Run()
}

func ensureRedisBaseline() {
	path := "/etc/redis/redis.conf"
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[OLS-WPanel] 读取 Redis 基线配置失败: %v", err)
		return
	}

	content := string(data)
	if FindRedisConfigValue(content, "maxmemory-policy") == "" && FindRedisConfigValue(content, "include") != "" {
		log.Printf("[OLS-WPanel] Redis 配置包含生效的 include 指令，跳过自动补充 maxmemory-policy，请管理员确认实际淘汰策略")
	}
	maxmem := fmt.Sprintf("%dmb", RecommendRedisMaxmemoryMB(CollectSystemFacts()))
	next, changed := BuildRedisBaselineConfig(content, maxmem)
	if !changed {
		return
	}

	result := SafeApplyRestartConfig(path, next, content, "redis-server", RedisReady)
	switch {
	case result.Applied:
		log.Printf("[OLS-WPanel] Redis 对象缓存基线已应用")
	case result.RolledBack && result.RollbackSucceeded:
		log.Printf("[OLS-WPanel] Redis 对象缓存基线应用失败，已恢复原配置: %v", result.Err)
	case result.RolledBack:
		log.Printf("[OLS-WPanel] Redis 对象缓存基线应用及回滚均失败，需要管理员立即检查 Redis: %v", result.Err)
	default:
		log.Printf("[OLS-WPanel] Redis 对象缓存基线应用失败，配置未改动: %v", result.Err)
	}
}

func getTotalMemoryKB() int64 {
	out, err := exec.Command("bash", "-c", "grep MemTotal /proc/meminfo | awk '{print $2}'").CombinedOutput()
	if err != nil {
		return 2097152 // default 2GB fallback
	}
	var kb int64
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &kb)
	return kb
}
