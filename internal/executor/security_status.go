package executor

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// GetSecurityRuntimeStatus returns a compact, non-sensitive view of the
// effective security runtime. Commands and unit names are fixed constants so
// this diagnostic endpoint never turns user input into a shell invocation.
func GetSecurityRuntimeStatus() (models.SecurityRuntimeStatus, error) {
	db := database.GetDB()
	if db == nil {
		return models.SecurityRuntimeStatus{}, fmt.Errorf("security status: database is not initialized")
	}

	status := models.SecurityRuntimeStatus{
		Fail2ban: serviceSecurityStatus("fail2ban.service"),
		Nftables: serviceSecurityStatus("nftables.service"),
	}
	status.WhitelistTimer.Active = systemdUnitState("is-active", "olswpanel-whitelist.timer")
	status.WhitelistTimer.Enabled = systemdUnitState("is-enabled", "olswpanel-whitelist.timer")
	if next, err := executeCommand("systemctl", "show", "olswpanel-whitelist.timer", "--property=NextElapseUSecRealtime", "--value"); err == nil {
		status.WhitelistTimer.NextRun = strings.TrimSpace(next)
	}

	if err := db.QueryRow(`SELECT COUNT(*) FROM firewall_bans
		WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`).Scan(&status.ActiveBans); err != nil {
		return models.SecurityRuntimeStatus{}, fmt.Errorf("query active bans: %w", err)
	}

	var official, web, ssh string
	for key, target := range map[string]*string{
		"official_whitelist_ips": &official,
		"whitelist_ips":          &web,
		"ssh_whitelist_ips":      &ssh,
		"last_whitelist_update":  &status.LastWhitelistUpdate,
	} {
		if err := db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = ?`, key).Scan(target); err != nil && err != sql.ErrNoRows {
			return models.SecurityRuntimeStatus{}, fmt.Errorf("query security setting %s: %w", key, err)
		}
	}
	status.OfficialWhitelist = countSecurityListEntries(official)
	status.WebWhitelist = countSecurityListEntries(web)
	status.SSHWhitelist = countSecurityListEntries(ssh)

	if err := db.QueryRow(`SELECT COUNT(*) FROM cdn_realip_groups WHERE enabled = 1`).Scan(&status.CDNEnabledGroups); err != nil {
		return models.SecurityRuntimeStatus{}, fmt.Errorf("query enabled CDN groups: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM websites WHERE cdn_realip_enabled = 1`).Scan(&status.CDNProtectedSites); err != nil {
		return models.SecurityRuntimeStatus{}, fmt.Errorf("query CDN protected sites: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(DISTINCT w.id)
		FROM websites w
		LEFT JOIN website_cdn_realip_groups wg ON wg.website_id = w.id
		LEFT JOIN cdn_realip_groups g ON g.id = wg.group_id AND g.enabled = 1
		WHERE w.cdn_realip_enabled = 1
		AND (g.id IS NULL OR (g.provider <> 'cloudflare' AND TRIM(g.ip_ranges) = ''))`).Scan(&status.CDNInvalidBindings); err != nil {
		return models.SecurityRuntimeStatus{}, fmt.Errorf("query invalid CDN bindings: %w", err)
	}

	return status, nil
}

func serviceSecurityStatus(unit string) models.SecurityServiceStatus {
	return models.SecurityServiceStatus{
		Active:  systemdUnitState("is-active", unit),
		Enabled: systemdUnitState("is-enabled", unit),
	}
}

func systemdUnitState(action, unit string) bool {
	out, err := executeCommand("systemctl", action, unit)
	return err == nil && strings.TrimSpace(out) != ""
}

func countSecurityListEntries(raw string) int {
	count := 0
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}
