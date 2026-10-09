package executor

import (
	"strings"
	"testing"
)

func accessTestRules() []FirewallAccessRule {
	return []FirewallAccessRule{{"tcp", 22, "203.0.113.5"}, {"tcp", 8443, "203.0.113.0/24"}, {"tcp", 443, ""}}
}

func TestAccessRulesValidateManagementAndSources(t *testing.T) {
	rules, err := normalizeAccessRules(accessTestRules(), "203.0.113.5", 22, 8443)
	if err != nil || len(rules) != 3 || rules[0].Source != "203.0.113.5/32" {
		t.Fatalf("unexpected normalization: %+v %v", rules, err)
	}
	for _, tc := range []struct {
		name  string
		rules []FirewallAccessRule
	}{
		{"missing SSH", accessTestRules()[1:]},
		{"wrong manager", []FirewallAccessRule{{"tcp", 22, "203.0.113.6"}, {"tcp", 8443, "203.0.113.5"}}},

		{"injected source", append(accessTestRules(), FirewallAccessRule{"tcp", 8080, "1.2.3.4; accept"})},
		{"public database", append(accessTestRules(), FirewallAccessRule{"tcp", 3306, ""})},
		{"wildcard CIDR", append(accessTestRules(), FirewallAccessRule{"tcp", 8080, "::/0"})},
		{"bad protocol", append(accessTestRules(), FirewallAccessRule{"tcp;accept", 8080, ""})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := normalizeAccessRules(tc.rules, "203.0.113.5", 22, 8443); err == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}

func TestAccessRulesIPv6AndIndependentDrop(t *testing.T) {
	rules, err := normalizeAccessRules([]FirewallAccessRule{{"tcp", 2222, "2001:db8::1"}, {"tcp", 9443, "2001:db8::/64"}, {"udp", 443, ""}}, "2001:db8::1", 2222, 9443)
	if err != nil {
		t.Fatal(err)
	}
	script := accessRulesScript(rules, true)
	for _, want := range []string{"delete table inet ols_wpanel_access", "hook input priority -5; policy drop", "ip6 saddr 2001:db8::1/128 tcp dport 2222", "ct state established,related accept", "meta l4proto ipv6-icmp accept", "udp sport 67 udp dport 68", "udp dport 443"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %s in %s", want, script)
		}
	}
	for _, bad := range []string{"flush ruleset", "delete table inet filter", "tcp dport 80", "tcp dport 443"} {
		if strings.Contains(script, bad) {
			t.Fatalf("unexpected %s", bad)
		}
	}
	if strings.Contains(accessRulesScript(rules, false), "delete table") {
		t.Fatal("first apply must not delete missing table")
	}
}

func TestAccessPreviewFingerprintRejectsChanges(t *testing.T) {
	a := accessFingerprint("table inet filter { old allow }", accessTestRules(), 22, 8443)
	if a == accessFingerprint("table inet filter { new allow }", accessTestRules(), 22, 8443) {
		t.Fatal("external rule change not detected")
	}
	rules := accessTestRules()
	rules[2].Port = 80
	if a == accessFingerprint("table inet filter { old allow }", rules, 22, 8443) {
		t.Fatal("selection change not detected")
	}
	if a == accessFingerprint("table inet filter { old allow }", accessTestRules(), 22, 9443) {
		t.Fatal("panel endpoint change not detected")
	}
	if a == accessFingerprint("table inet filter { old allow }", accessTestRules(), 2222, 8443) {
		t.Fatal("SSH endpoint change not detected")
	}
}

func TestAccessAllowsPublicSSHAndPanelDefault(t *testing.T) {
	rules, err := normalizeAccessRules([]FirewallAccessRule{{"tcp", 22, ""}, {"tcp", 8443, ""}, {"tcp", 80, ""}, {"tcp", 443, ""}}, "203.0.113.5", 22, 8443)
	if err != nil || len(rules) != 4 {
		t.Fatalf("public default rejected: %v", err)
	}
}
