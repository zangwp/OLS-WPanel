package executor

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func EnsureWordPressBaseline() {
	ensurePHPBaseline()
	ensureOpenLiteSpeedBaseline()
	ensureMariaDBBaseline()
	ensureRedisBaseline()
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
