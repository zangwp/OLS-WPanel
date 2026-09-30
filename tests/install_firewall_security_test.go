package tests

import (
	"strings"
	"testing"
)

func TestFreshInstallCreatesSafeNftablesBaseline(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	for _, required := range []string{
		"configure_fresh_firewall() {",
		"detect_installer_ssh_port() {",
		`add chain inet filter input { type filter hook input priority filter; policy drop; }`,
		`ct state established,related counter accept`,
		`iifname "lo" counter accept`,
		`meta l4proto ipv6-icmp counter accept`,
		`ip protocol icmp counter accept`,
		`tcp dport ${ssh_port} ct state new counter accept`,
		`tcp dport 80 ct state new counter accept`,
		`tcp dport 443 ct state new counter accept`,
		`udp dport 443 ct state new counter accept`,
		`tcp dport 8443 ct state new counter accept`,
		`nft --check --file "$nft_stage"`,
		`printf 'flush ruleset\n' > "$nft_snapshot"`,
		`nft --check --file "$nft_snapshot"`,
		`install -o root -g root -m 0600 "$nft_snapshot" /etc/nftables.conf`,
		`systemctl enable --now nftables`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("install.sh missing secure firewall baseline %q", required)
		}
	}
	for _, forbidden := range []string{
		"flush ruleset\nadd table inet filter",
		"tcp dport 3306",
		"tcp dport 6379",
		"tcp dport 7080",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("install.sh contains unsafe firewall baseline %q", forbidden)
		}
	}
}

func TestInstallerPreservesExistingFirewallOwnership(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	for _, required := range []string{
		`if $REPAIR_MODE; then`,
		`repair模式保留现有防火墙规则和默认策略`,
		`ufw status 2>/dev/null | grep -F "Status: active" >/dev/null`,
		`未覆盖其余规则或默认策略`,
		`nft list ruleset 2>/dev/null | grep -F "hook input" >/dev/null`,
		`检测到自定义 nftables 入站链`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("install.sh missing existing-firewall preservation guard %q", required)
		}
	}

	call := requiredIndex(t, script, "configure_fresh_firewall\n")
	mariaDB := requiredIndex(t, script, "# MariaDB 安全加固")
	if call >= mariaDB {
		t.Fatalf("firewall baseline must be configured before MariaDB setup: firewall=%d mariadb=%d", call, mariaDB)
	}
}
