package executor

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Refresh holds fail2banSettingsApplyMu before acquiring the OLS ACL mutex.
// ApplyOLSTrustedProxyList never acquires the Fail2ban mutex in reverse order.
var refreshOfficialCloudflareIPs = fetchCloudflareIPs
var refreshOfficialGooglebotIPs = fetchGooglebotIPsWithFallback
var refreshOfficialBingbotIPs = fetchBingbotIPs
var refreshTrustedProxyReady = func() error {
	if olsIPv6UpgradePaused() {
		return errors.New("OpenLiteSpeed 已暂停，未刷新选中 Cloudflare 的缓存与可信代理配置；恢复运行后重试")
	}
	if !olsTrustedProxyUpgradeActive() {
		return errors.New("OpenLiteSpeed 未运行，未刷新选中 Cloudflare 的缓存与可信代理配置；启动后重试")
	}
	return nil
}

// Only a selected, enabled group using the official cache is affected by a
// cache refresh. An explicitly configured static group has its own ranges.
func selectedCachedCloudflareProxy(db *sql.DB) (bool, error) {
	var selected int
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM cdn_realip_groups g INNER JOIN website_cdn_realip_groups wg ON wg.group_id=g.id INNER JOIN websites w ON w.id=wg.website_id WHERE g.enabled=1 AND w.cdn_realip_enabled=1 AND g.provider=? AND TRIM(COALESCE(g.ip_ranges,''))='')`, CDNProviderCloudflare).Scan(&selected)
	return selected == 1, err
}

type refreshSecuritySnapshot struct {
	exists           bool
	value, updatedAt string
	description      sql.NullString
}

// Cloudflare officially publishes /13 IPv4 and /29 IPv6 prefixes. Crawler
// imports retain their stricter validator; only these fixed official CDN
// sources and their cache use this separate public CIDR/address-family check.
// expectedBits=0 reads a mixed cache; endpoint responses require 32 or 128.
func normalizeCloudflareIPRanges(raw string, expectedBits int) ([]string, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 || len(fields) > 512 {
		return nil, errors.New("Cloudflare IP 段为空或超过 512 条")
	}
	var ranges []string
	for _, item := range fields {
		ip, network, err := net.ParseCIDR(item)
		if err != nil {
			return nil, errors.New("Cloudflare 官方源包含无效 CIDR")
		}
		ones, bits := network.Mask.Size()
		if expectedBits != 0 && bits != expectedBits || bits == 128 && ip.To4() != nil {
			return nil, errors.New("Cloudflare 官方源包含错误地址族")
		}
		if bits == 32 && ones < 8 || bits == 128 && ones < 16 || !isPublicOfficialIP(ip) || !isPublicOfficialIP(network.IP) {
			return nil, errors.New("Cloudflare 官方源包含过宽或非公网网段")
		}
		ranges = append(ranges, network.String())
	}
	return uniqueStrings(ranges), nil
}

func snapshotRefreshSecuritySettings(db *sql.DB, updates map[string]securitySettingUpdate) (map[string]refreshSecuritySnapshot, error) {
	snapshot := make(map[string]refreshSecuritySnapshot, len(updates))
	for key := range updates {
		var row refreshSecuritySnapshot
		err := db.QueryRow(`SELECT svalue,description,CAST(updated_at AS TEXT) FROM security_settings WHERE skey=?`, key).Scan(&row.value, &row.description, &row.updatedAt)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		row.exists = err == nil
		snapshot[key] = row
	}
	return snapshot, nil
}
func restoreRefreshSecuritySettings(db *sql.DB, snapshot map[string]refreshSecuritySnapshot) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	keys := make([]string, 0, len(snapshot))
	for key := range snapshot {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		row := snapshot[key]
		if row.exists {
			_, err = tx.Exec(`INSERT INTO security_settings(skey,svalue,description,updated_at) VALUES(?,?,?,?) ON CONFLICT(skey) DO UPDATE SET svalue=excluded.svalue,description=excluded.description,updated_at=excluded.updated_at`, key, row.value, row.description, row.updatedAt)
		} else {
			_, err = tx.Exec(`DELETE FROM security_settings WHERE skey=?`, key)
		}
		if err != nil {
			return fmt.Errorf("恢复缓存 %s: %w", key, err)
		}
	}
	return tx.Commit()
}
