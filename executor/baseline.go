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
	ensureNginxBaseline()
	ensureMariaDBBaseline()
	ensureRedisBaseline()
}

func ensurePHPBaseline() {
	changed, err := EnsurePHPRuntimeConfigFile()
	if err == nil && changed {
		exec.Command("systemctl", "restart", "lsws").Run()
	}
}

func ensureNginxBaseline() {
	paths := currentOLSRuntimePaths()
	if out, err := exec.Command(paths.binary, "-t").CombinedOutput(); err != nil {
		log.Printf("[OLS-WPanel] OpenLiteSpeed 配置检查失败: %s", strings.TrimSpace(string(out)))
	}
}

// ensureNginxCacheBypassMap 定义 $wp_cache_skip_args，供每个站点的 FastCGI 缓存绕过
// 判断复用（站点模板里引用了这个全局变量，不能在每个站点自己的配置文件里各定义一份——
// map 指令只能在 http{} 顶层出现一次，两个站点各定义一份同名变量会导致 nginx -t 报重复定义）。
//
// 语义：只要查询字符串完全由已知的营销/统计追踪参数组成（utm_*/fbclid/gclid 等），就不算
// "真实查询参数"，仍然允许命中缓存；只要出现任何一个不在名单里的参数，$wp_cache_skip_args
// 就会保留原始 $args（非空），触发跳过缓存——这样从广告点击进来的流量不会把缓存打穿。
func ensureNginxCacheBypassMap() {
	// OpenLiteSpeed + LSCWP handles cache bypass rules in each site's .htaccess.
}

func ensureNginxSSLDefaultServer() {
	// The shared HTTPS listener uses the panel-managed fallback certificate.
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
