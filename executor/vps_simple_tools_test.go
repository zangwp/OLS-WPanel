package executor

import (
	"strings"
	"testing"
)

func TestVPSIPPriorityRoundTripPreservesAdministratorSettings(t *testing.T) {
	original := "# administrator comment\nlabel ::1/128 0\n"
	ipv4, err := buildVPSIPPriority(original, "ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ipv4, "precedence ::ffff:0:0/96 100") {
		t.Fatal("missing IPv4 priority")
	}
	ipv6, err := buildVPSIPPriority(ipv4, "ipv6")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ipv6, ipPriorityBegin) != 1 || !strings.Contains(ipv6, "precedence ::/0 100") {
		t.Fatal("duplicated priority or missing IPv6 rule")
	}
	restored, err := buildVPSIPPriority(ipv6, "default")
	if err != nil || restored != original {
		t.Fatalf("restored %q, %v", restored, err)
	}
}
func TestVPSIPPriorityRejectsCustomRulesAndInvalidModes(t *testing.T) {
	if _, err := buildVPSIPPriority("precedence ::/0 80\n", "ipv4"); err == nil {
		t.Fatal("overrode administrator rule")
	}
	if _, err := buildVPSIPPriority("", "ipv4; reboot"); err == nil {
		t.Fatal("accepted command input")
	}
	if _, err := buildVPSIPPriority(ipPriorityBegin+"\nbroken", "default"); err == nil {
		t.Fatal("accepted incomplete managed block")
	}
}
