package executor

import (
	"net"
	"strings"
	"testing"
)

func TestDNSPresetsUsePublishedPairedAddresses(t *testing.T) {
	presets := DNSPresets()
	if len(presets) != 2 {
		t.Fatalf("len(DNSPresets()) = %d, want 2", len(presets))
	}
	for _, preset := range presets {
		if len(preset.IPv4) != 2 || len(preset.IPv6) != 2 {
			t.Fatalf("preset %#v must contain paired IPv4 and IPv6 addresses", preset)
		}
		for _, address := range append(append([]string{}, preset.IPv4...), preset.IPv6...) {
			if net.ParseIP(address) == nil {
				t.Fatalf("invalid address %q", address)
			}
		}
	}
}

func TestRenderResolvedDNSConfigIncludesIPv6OnlyWhenAvailable(t *testing.T) {
	preset, ok := findDNSPreset("international")
	if !ok {
		t.Fatal("international preset not found")
	}
	ipv4Only := renderResolvedDNSConfig(preset, false)
	if !strings.HasPrefix(ipv4Only, dnsManagedMarker+"\n") || !strings.Contains(ipv4Only, "DNS=1.1.1.1 1.0.0.1") || strings.Contains(ipv4Only, "2606:") {
		t.Fatalf("unexpected IPv4-only config: %q", ipv4Only)
	}
	dualStack := renderResolvedDNSConfig(preset, true)
	if !strings.Contains(dualStack, "2606:4700:4700::1111") || !strings.Contains(dualStack, "Domains=~.") {
		t.Fatalf("unexpected dual-stack config: %q", dualStack)
	}
}

func TestParseIPAddressesDeduplicatesResolverOutput(t *testing.T) {
	got := parseIPAddresses("Global: 1.1.1.1 2606:4700:4700::1111\nLink 2 (eth0): 1.1.1.1 1.0.0.1")
	want := []string{"1.0.0.1", "1.1.1.1", "2606:4700:4700::1111"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parseIPAddresses() = %#v, want %#v", got, want)
	}
}

func TestPresetFromConfig(t *testing.T) {
	preset, _ := findDNSPreset("mainland_china")
	if got := presetFromConfig(renderResolvedDNSConfig(preset, true)); got != "mainland_china" {
		t.Fatalf("presetFromConfig() = %q", got)
	}
}

func TestContainsAnyDNSNormalizesAddresses(t *testing.T) {
	if !containsAnyDNS([]string{"2606:4700:4700:0:0:0:0:1111"}, []string{"2606:4700:4700::1111"}) {
		t.Fatal("equivalent IPv6 addresses were not matched")
	}
	if containsAnyDNS([]string{"8.8.8.8"}, []string{"1.1.1.1", "1.0.0.1"}) {
		t.Fatal("unrelated DNS address was matched")
	}
}
