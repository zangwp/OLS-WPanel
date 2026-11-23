package handlers

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestSSLPreflightCloudIPv4Mapping(t *testing.T) {
	const publicIPv4 = "192.0.2.24"
	lookup := func(_ context.Context, domain string) ([]net.IPAddr, error) {
		if domain == "wrong.example.com" {
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.25")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP(publicIPv4)}}, nil
	}
	interfaces := map[string]bool{"10.0.0.24": true}
	result, err := checkSSLPreflight(t.Context(), "example.com", []string{"www.example.com"}, interfaces, publicIPv4, lookup)
	if err != nil || !result.OK || len(result.Domains) != 2 || !result.Domains[0].Matched || !result.Domains[1].Matched {
		t.Fatalf("configured public address should match both names: %+v, %v", result, err)
	}
	for _, tc := range []struct{ domain, configured, answer string }{
		{"example.com", "", publicIPv4},
		{"wrong.example.com", publicIPv4, "192.0.2.25"},
	} {
		result, err := checkSSLPreflight(t.Context(), tc.domain, nil, interfaces, tc.configured, lookup)
		if err != nil || result.OK || len(result.HardWarnings) != 0 || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], tc.answer) {
			t.Fatalf("uncertain mapping should show the DNS answer as an advisory: %+v, %v", result, err)
		}
	}
}
