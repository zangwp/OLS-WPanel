package executor

import (
	"fmt"
	"net"
	"strings"
)

// These names are kept as internal compatibility shims for older Fail2ban
// action files. OLS WPanel v1 enforces bans with the persistent nftables set;
// it never writes or reloads an Nginx configuration.
func AddNginxBan(ip string) error {
	return AddPersistBan(strings.TrimSpace(ip))
}

func RemoveNginxBan(ip string) error {
	return RemovePersistBan(strings.TrimSpace(ip))
}

func EnsureNginxBannedIPsConfig() error {
	return EnsurePersistNftables()
}

// Fail2ban owns its short-lived bans. The persistent set is changed only by
// explicit panel/manual-ban operations, so a periodic snapshot must not erase
// administrator-managed entries. Validate the snapshot here and otherwise do
// nothing.
func ReplaceNginxBannedIPs(ips map[string]bool) error {
	for ip, banned := range ips {
		if banned && !isValidIPOrCIDR(strings.TrimSpace(ip)) {
			return fmt.Errorf("invalid IP: %s", ip)
		}
	}
	return nil
}

func isValidIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
