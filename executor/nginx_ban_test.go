package executor

import (
	"strings"
	"testing"
)

func TestLegacyNginxBanSnapshotOnlyValidatesInput(t *testing.T) {
	if err := ReplaceNginxBannedIPs(map[string]bool{
		"192.0.2.10":      true,
		"2001:db8::/32":   true,
		"ignored.invalid": false,
	}); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	if err := ReplaceNginxBannedIPs(map[string]bool{"bad value": true}); err == nil {
		t.Fatal("invalid snapshot was accepted")
	}
}

func TestRenderOLSTrustedProxyList(t *testing.T) {
	got := renderOLSTrustedProxyList([]string{
		"203.0.113.0/24",
		"bad value",
		"203.0.113.0/24",
		"2001:db8::/32",
	})
	if strings.Count(got, "203.0.113.0/24T") != 1 {
		t.Fatalf("expected duplicate IPv4 CIDR to be removed:\n%s", got)
	}
	if !strings.Contains(got, "2001:db8::/32T") {
		t.Fatalf("missing IPv6 CIDR:\n%s", got)
	}
	if strings.Contains(got, "bad value") {
		t.Fatalf("invalid address leaked into config:\n%s", got)
	}
}
