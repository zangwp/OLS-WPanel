package executor

import (
	"context"
	"strings"
	"testing"
)

func TestNormalizeFirewallPortRule(t *testing.T) {
	tests := []struct {
		name    string
		req     FirewallPortRuleRequest
		wantErr string
		source  string
	}{
		{name: "tcp any", req: FirewallPortRuleRequest{Protocol: "TCP", Port: 8080, SourceMode: "any", ConfirmPublic: true}, source: ""},
		{name: "single ipv4", req: FirewallPortRuleRequest{Protocol: "tcp", Port: 8443, Source: "203.0.113.9"}, source: "203.0.113.9/32"},
		{name: "cidr", req: FirewallPortRuleRequest{Protocol: "udp", Port: 443, Source: "2001:db8::/64"}, source: "2001:db8::/64"},
		{name: "temporary duration missing", req: FirewallPortRuleRequest{Protocol: "tcp", Port: 8080, Source: "203.0.113.9", DurationMode: "temporary"}, wantErr: "至少"},
		{name: "any source unconfirmed", req: FirewallPortRuleRequest{Protocol: "tcp", Port: 8080, SourceMode: "any"}, wantErr: "确认"},
		{name: "ipv4 zero prefix unconfirmed", req: FirewallPortRuleRequest{Protocol: "tcp", Port: 8080, SourceMode: "specific", Source: "0.0.0.0/0"}, wantErr: "确认"},
		{name: "ipv6 zero prefix unconfirmed", req: FirewallPortRuleRequest{Protocol: "tcp", Port: 8080, SourceMode: "specific", Source: "::/0"}, wantErr: "确认"},
		{name: "specific source missing", req: FirewallPortRuleRequest{Protocol: "tcp", Port: 8080, SourceMode: "specific"}, wantErr: "不能为空"},
		{name: "current source missing", req: FirewallPortRuleRequest{Protocol: "tcp", Port: 8080, SourceMode: "current"}, wantErr: "管理 IP"},
		{name: "bad protocol", req: FirewallPortRuleRequest{Protocol: "sctp", Port: 80}, wantErr: "协议"},
		{name: "bad port", req: FirewallPortRuleRequest{Protocol: "tcp", Port: 0}, wantErr: "端口"},
		{name: "bad source", req: FirewallPortRuleRequest{Protocol: "tcp", Port: 80, Source: "not-an-ip"}, wantErr: "来源"},
		{name: "public webadmin", req: FirewallPortRuleRequest{Protocol: "tcp", Port: 7080}, wantErr: "7080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeFirewallPortRule(tt.req)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err=%v, want fragment %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Source != tt.source {
				t.Fatalf("source=%q want %q", got.Source, tt.source)
			}
		})
	}
}

func TestSetInputPolicyUsesArgumentVector(t *testing.T) {
	original := portCommand
	defer func() { portCommand = original }()
	var name string
	var args []string
	portCommand = func(_ context.Context, command string, commandArgs ...string) (string, error) {
		name = command
		args = append([]string(nil), commandArgs...)
		return "", nil
	}
	if err := setInputPolicy(context.Background(), "inet", "filter", "input", "drop"); err != nil {
		t.Fatal(err)
	}
	if name != "nft" || strings.Join(args, " ") != "chain inet filter input { policy drop ; }" {
		t.Fatalf("unexpected policy command: %s %q", name, args)
	}
	if err := setInputPolicy(context.Background(), "inet", "filter", "input", "reject"); err == nil {
		t.Fatal("unsupported policy was accepted")
	}
}

func TestCoreRulesDoNotExposeManagementPortsGlobally(t *testing.T) {
	source := sourceExpression("203.0.113.8/32")
	ssh := append(source, "tcp", "dport", "22", "ct", "state", "new")
	joined := strings.Join(coreRuleArgs("inet", "filter", "input", "ssh", ssh...), " ")
	if !strings.Contains(joined, "ip saddr 203.0.113.8/32 tcp dport 22") {
		t.Fatalf("SSH core rule is not management-IP restricted: %q", joined)
	}
	if !strings.Contains(joined, "counter accept comment "+managedCoreCommentPrefix+"ssh") {
		t.Fatalf("SSH core rule is not attributable or counted: %q", joined)
	}
}

func TestManagementCoreRulesRejectStalePortsAndSources(t *testing.T) {
	old := portCommand
	defer func() { portCommand = old }()
	for _, tc := range []struct {
		name   string
		line   string
		source string
		port   string
		match  bool
	}{
		{name: "current IPv4", line: `ip saddr 203.0.113.8 tcp dport 49173 ct state new counter packets 0 bytes 0 accept comment "ols-wpanel-core:panel" # handle 9`, source: "203.0.113.8/32", port: "49173", match: true},
		{name: "current IPv6", line: `ip6 saddr 2001:db8::8 tcp dport 49173 ct state new counter packets 1 bytes 60 accept comment "ols-wpanel-core:panel"`, source: "2001:db8::8/128", port: "49173", match: true},
		{name: "stale port", line: `ip saddr 203.0.113.8 tcp dport 8443 ct state new counter accept comment "ols-wpanel-core:panel"`, source: "203.0.113.8/32", port: "49173"},
		{name: "different administrator", line: `ip saddr 203.0.113.9 tcp dport 49173 ct state new counter accept comment "ols-wpanel-core:panel"`, source: "203.0.113.8/32", port: "49173"},
		{name: "public source", line: `tcp dport 49173 ct state new counter accept comment "ols-wpanel-core:panel"`, source: "203.0.113.8/32", port: "49173"},
		{name: "unexpected condition", line: `ip saddr 203.0.113.8 tcp dport 49173 ct state invalid counter accept comment "ols-wpanel-core:panel"`, source: "203.0.113.8/32", port: "49173"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			portCommand = func(context.Context, string, ...string) (string, error) {
				t.Fatal("existing management rule was silently widened or replaced")
				return "", nil
			}
			expressions := append(sourceExpression(tc.source), "tcp", "dport", tc.port, "ct", "state", "new")
			err := addCoreRuleIfMissing(context.Background(), "inet", "filter", "input", tc.line, "panel", expressions...)
			if (err == nil) != tc.match {
				t.Fatalf("existing management rule result = %v, want match %t", err, tc.match)
			}
		})
	}
}

func TestManagedPortTagSeparatesRestrictedSources(t *testing.T) {
	a := managedPortTag("tcp", 8443, "203.0.113.1/32")
	b := managedPortTag("tcp", 8443, "203.0.113.2/32")
	if a == b || !strings.HasPrefix(a, managedPortCommentPrefix+"tcp:8443:src") {
		t.Fatalf("tags are not source-specific: %q %q", a, b)
	}
}

func TestNFTRuleArgsNeverUseShell(t *testing.T) {
	req := FirewallPortRuleRequest{Protocol: "tcp", Port: 8443, Source: "203.0.113.7/32"}
	args := nftRuleArgs("insert", "inet", "filter", "input", req)
	joined := strings.Join(args, " ")
	if strings.ContainsAny(joined, ";|&`$<>") {
		t.Fatalf("unsafe nft arguments: %q", joined)
	}
	if !strings.Contains(joined, "ip saddr 203.0.113.7/32 tcp dport 8443") {
		t.Fatalf("unexpected nft arguments: %q", joined)
	}
	if !strings.Contains(joined, "counter accept") {
		t.Fatalf("managed rule does not count matches: %q", joined)
	}
}

func TestListenerBindScope(t *testing.T) {
	for _, test := range []struct {
		address string
		want    string
	}{
		{address: "127.0.0.1", want: "local"},
		{address: "::1", want: "local"},
		{address: "0.0.0.0", want: "network"},
		{address: "::", want: "network"},
		{address: "192.0.2.10", want: "network"},
	} {
		if got := listenerBindScope(test.address); got != test.want {
			t.Fatalf("listenerBindScope(%q)=%q want %q", test.address, got, test.want)
		}
	}
}
