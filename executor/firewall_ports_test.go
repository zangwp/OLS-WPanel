package executor

import (
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
		{name: "tcp any", req: FirewallPortRuleRequest{Protocol: "TCP", Port: 8080}, source: ""},
		{name: "single ipv4", req: FirewallPortRuleRequest{Protocol: "tcp", Port: 8443, Source: "203.0.113.9"}, source: "203.0.113.9/32"},
		{name: "cidr", req: FirewallPortRuleRequest{Protocol: "udp", Port: 443, Source: "2001:db8::/64"}, source: "2001:db8::/64"},
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
}
