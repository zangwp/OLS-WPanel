package executor

import (
	"bytes"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

var olsTrustedProxyConfigMu sync.Mutex

func EnsureCloudflareRealIPConfig() error {
	if strings.TrimSpace(cachedCloudflareRealIPRanges()) != "" {
		return nil
	}
	cfIPs, err := fetchCloudflareIPs()
	if err != nil {
		return err
	}
	return DeployCloudflareRealIPConfig(cfIPs)
}

func DeployCloudflareRealIPConfig(cfIPs []string) error {
	if len(cfIPs) == 0 {
		return fmt.Errorf("cloudflare IP list is empty")
	}
	for _, ip := range cfIPs {
		if !isValidIPOrCIDR(strings.TrimSpace(ip)) {
			return fmt.Errorf("invalid Cloudflare network: %s", ip)
		}
	}
	// OLS WPanel uses the cached official ranges for Fail2ban allowlists. It
	// intentionally does not write OpenLiteSpeed real_ip directives on an OLS host.
	cacheCloudflareRealIPRanges(cfIPs)
	return nil
}

// ApplyOLSTrustedProxyList configures the only safe OpenLiteSpeed real-IP
// mode: X-Forwarded-For is honored only when the direct peer is in the trusted
// list. The enabled built-in Cloudflare group applies automatically; other
// groups retain their explicit website bindings.
func ApplyOLSTrustedProxyList() error {
	olsTrustedProxyConfigMu.Lock()
	defer olsTrustedProxyConfigMu.Unlock()
	ranges, err := combinedOLSTrustedProxyRanges(database.GetDB())
	if err != nil {
		return err
	}
	paths := currentOLSRuntimePaths()
	old, _, err := readOLSTrustedProxyConfig(paths.mainConfig)
	if err != nil {
		return err
	}
	candidate, err := renderOLSTrustedProxyMainConfig(old, paths.managed, ranges)
	if err != nil {
		return err
	}
	if bytes.Equal(old, candidate) {
		return nil
	}
	if err := refreshTrustedProxyReady(); err != nil {
		return err
	}
	return applyOLSTrustedProxyRanges(paths.mainConfig, paths.managed, ranges)
}

// Respect an administrator-disabled or statically configured built-in group.
// A custom group merely labelled Cloudflare must not activate global trust.
func automaticCloudflareProxyEnabled(db *sql.DB) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("读取 Cloudflare 自动代理设置失败: 数据库未初始化")
	}
	var enabled int
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM cdn_realip_groups WHERE provider=? AND builtin=1 AND enabled=1 AND TRIM(COALESCE(ip_ranges,''))='')`, CDNProviderCloudflare).Scan(&enabled)
	if err != nil {
		return false, fmt.Errorf("读取 Cloudflare 自动代理设置失败: %w", err)
	}
	return enabled == 1, nil
}

func combinedOLSTrustedProxyRanges(db *sql.DB) ([]string, error) {
	raw, err := combinedCDNRealIPRangesForFail2ban(db)
	if err != nil {
		return nil, err
	}
	ranges, err := NormalizeCDNRealIPRanges(raw)
	if err != nil {
		return nil, err
	}
	automatic, err := automaticCloudflareProxyEnabled(db)
	if err != nil || !automatic {
		return ranges, err
	}
	cloudflare, err := readCachedSecurityIPRanges(db, "cloudflare_realip_ips")
	if err != nil {
		return nil, fmt.Errorf("读取 Cloudflare 自动可信代理缓存失败: %w", err)
	}
	if len(cloudflare) == 0 {
		return nil, fmt.Errorf("Cloudflare 官方 IP 段尚未缓存，未修改原可信代理配置，请先刷新官方数据")
	}
	return uniqueStrings(append(ranges, cloudflare...)), nil
}

// Keep the exact pre-refresh ACL, including an older install that has not
// adopted automatic trust yet. Recomputing from old cache is not a rollback.
func snapshotOLSTrustedProxyRestore() (func() error, error) {
	olsTrustedProxyConfigMu.Lock()
	defer olsTrustedProxyConfigMu.Unlock()
	paths := currentOLSRuntimePaths()
	old, metadata, err := readOLSTrustedProxyConfig(paths.mainConfig)
	if err != nil {
		return nil, err
	}
	ranges, err := combinedOLSTrustedProxyRanges(database.GetDB())
	if err != nil {
		return nil, err
	}
	expected, err := renderOLSTrustedProxyMainConfig(old, paths.managed, ranges)
	if err != nil {
		return nil, err
	}
	return func() error {
		olsTrustedProxyConfigMu.Lock()
		defer olsTrustedProxyConfigMu.Unlock()
		current, _, err := readOLSTrustedProxyConfig(paths.mainConfig)
		if err != nil {
			return err
		}
		if bytes.Equal(current, old) {
			return nil
		}
		if !bytes.Equal(current, expected) {
			return fmt.Errorf("OpenLiteSpeed 主配置在刷新期间发生外部修改，未覆盖修改，请人工核对")
		}
		if err := writeOLSTrustedProxyConfigAtomic(paths.mainConfig, old, metadata); err != nil {
			return err
		}
		if err := refreshTrustedProxyReady(); err != nil {
			return fmt.Errorf("原 OpenLiteSpeed 主配置已恢复，未启动已停止的服务: %w", err)
		}
		_, err = testAndRestartOpenLiteSpeed()
		return err
	}, nil
}

func cacheCloudflareRealIPRanges(cfIPs []string) {
	if database.GetDB() == nil {
		return
	}
	database.GetDB().Exec(`UPDATE security_settings SET svalue = ?, updated_at = CURRENT_TIMESTAMP WHERE skey = 'cloudflare_realip_ips'`, strings.Join(cfIPs, "\n"))
}
