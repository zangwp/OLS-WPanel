package executor

import (
	"reflect"
	"strings"
	"testing"
)

func sshBootstrapTestChain() string {
	return `table inet filter {
 chain input {
  type filter hook input priority filter; policy drop;
  ct state invalid counter packets 1 bytes 40 drop comment "ols-wpanel-core:invalid"
  ct state established,related counter accept comment "ols-wpanel-core:established"
  iifname "lo" counter accept comment "ols-wpanel-core:loopback"
  ip protocol icmp counter accept
  meta l4proto ipv6-icmp counter accept
  ip saddr 203.0.113.0/24 tcp dport 22 counter accept comment "ols-wpanel-core:ssh"
  tcp dport 8443 counter accept comment "ols-wpanel-panel"
  tcp dport 80 counter accept
  tcp dport 443 counter accept
  udp dport 443 counter accept
 }
}`
}

func TestSSHMigrationBootstrapCopiesExistingAllowlist(t *testing.T) {
	rules, err := sshBootstrapAccessRules(sshBootstrapTestChain(), 22, 8443)
	if err != nil {
		t.Fatal(err)
	}
	want := []FirewallAccessRule{{"tcp", 22, "203.0.113.0/24"}, {"tcp", 8443, ""}, {"tcp", 80, ""}, {"tcp", 443, ""}, {"udp", 443, ""}}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("existing policy changed during bootstrap: %v, want %v", rules, want)
	}
	dual, err := migrateSSHAccess(rules, 22, 2222, true)
	if err != nil {
		t.Fatal(err)
	}
	if dual[0].Source != want[0].Source || dual[1].Source != want[0].Source || dual[1].Port != 2222 {
		t.Fatalf("SSH migration widened the original source: %v", dual)
	}
	if script := accessRulesScript(dual, false); strings.Contains(script, "delete table") {
		t.Fatal("bootstrap migration tried to replace an absent access table")
	}
}

func TestSSHMigrationBootstrapRejectsUnknownOrOpenPolicies(t *testing.T) {
	chain := sshBootstrapTestChain()
	for _, changed := range []string{
		strings.Replace(chain, "policy drop", "policy accept", 1),
		strings.Replace(chain, "tcp dport 22", "tcp dport { 22, 2222 }", 1),
		strings.Replace(chain, "tcp dport 22", "tcp dport 2222", 1),
		strings.Replace(chain, "tcp dport 8443", "tcp dport 9443", 1),
		strings.Replace(chain, "tcp dport 80", "iifname eth0 tcp dport 80", 1),
		chain + "\ntcp dport 9999 accept",
		strings.Replace(chain, "203.0.113.0/24", "::/0", 1),
	} {
		if _, err := sshBootstrapAccessRules(changed, 22, 8443); err == nil {
			t.Fatalf("unsafe or incomplete bootstrap policy accepted: %s", changed)
		}
	}
}
