package executor

import (
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
// list. Every selected, enabled CDN's origin ranges, including Cloudflare,
// are reconciled into the server ACL with T suffixes; this does not rely on
// OpenLiteSpeed's built-in provider list remaining current.
func ApplyOLSTrustedProxyList() error {
	olsTrustedProxyConfigMu.Lock()
	defer olsTrustedProxyConfigMu.Unlock()
	raw, err := combinedCDNRealIPRangesForFail2ban(database.GetDB())
	if err != nil {
		return err
	}
	ranges, err := NormalizeCDNRealIPRanges(raw)
	if err != nil {
		return err
	}
	paths := currentOLSRuntimePaths()
	return applyOLSTrustedProxyRanges(paths.mainConfig, paths.managed, ranges)
}

func cacheCloudflareRealIPRanges(cfIPs []string) {
	if database.GetDB() == nil {
		return
	}
	database.GetDB().Exec(`UPDATE security_settings SET svalue = ?, updated_at = CURRENT_TIMESTAMP WHERE skey = 'cloudflare_realip_ips'`, strings.Join(cfIPs, "\n"))
}
