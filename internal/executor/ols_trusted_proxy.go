package executor

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

const olsTrustedIPListPath = "/usr/local/lsws/conf/trusted-ip-list"

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
// list. OpenLiteSpeed already recognizes Cloudflare and QUIC.cloud, while the
// list below adds the explicitly enabled custom CDN ranges.
func ApplyOLSTrustedProxyList() error {
	raw, err := combinedCDNRealIPRangesForFail2ban(database.GetDB())
	if err != nil {
		return err
	}
	ranges, err := NormalizeCDNRealIPRanges(raw)
	if err != nil {
		return err
	}
	content := renderOLSTrustedProxyList(ranges)
	old, readErr := os.ReadFile(olsTrustedIPListPath)
	hadOld := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if err := writeOLSFileAtomic(olsTrustedIPListPath, []byte(content), 0640); err != nil {
		return fmt.Errorf("写入 OpenLiteSpeed 可信代理列表失败: %w", err)
	}
	if _, err := testAndRestartOpenLiteSpeed(); err != nil {
		_ = restoreOLSFile(olsTrustedIPListPath, old, hadOld, 0640)
		_, _ = testAndRestartOpenLiteSpeed()
		return err
	}
	return nil
}

func renderOLSTrustedProxyList(ranges []string) string {
	seen := make(map[string]bool)
	clean := make([]string, 0, len(ranges))
	for _, item := range ranges {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] || !isValidIPOrCIDR(item) {
			continue
		}
		seen[item] = true
		clean = append(clean, item)
	}
	sort.Strings(clean)
	var out strings.Builder
	out.WriteString("# OLS WPanel managed trusted proxy list. DO NOT EDIT.\n")
	for _, item := range clean {
		out.WriteString(item)
		out.WriteString("T\n")
	}
	return out.String()
}

func cacheCloudflareRealIPRanges(cfIPs []string) {
	if database.GetDB() == nil {
		return
	}
	database.GetDB().Exec(`UPDATE security_settings SET svalue = ?, updated_at = CURRENT_TIMESTAMP WHERE skey = 'cloudflare_realip_ips'`, strings.Join(cfIPs, "\n"))
}
