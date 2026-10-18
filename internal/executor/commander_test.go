package executor

import (
	"fmt"
	"strings"
	"testing"
)

const officialBingRangesFixture = `{"prefixes":[{"ipv4Prefix":"157.55.39.0/24"},{"ipv6Prefix":"2620:1ec:c11::/48"}]}`

func TestOfficialRangeFetchesPassActualCommandPolicy(t *testing.T) {
	calls := 0
	run := func(binary string, args ...string) (string, error) {
		calls++
		if !IsCommandAllowed(binary, args) {
			return "", fmt.Errorf("production command policy rejected official fetch: %s %v", binary, args)
		}
		switch args[len(args)-1] {
		case "https://www.cloudflare.com/ips-v4/":
			return refreshOfficialCFV4, nil
		case "https://www.cloudflare.com/ips-v6/":
			return refreshOfficialCFV6, nil
		case "https://www.bing.com/toolbox/bingbot.json":
			return officialBingRangesFixture, nil
		default:
			return "", fmt.Errorf("unexpected official endpoint")
		}
	}
	cloudflare, err := fetchCloudflareIPsWithCommand(run)
	if err != nil || len(cloudflare) != 22 || calls != 2 {
		t.Fatalf("official Cloudflare fetch failed through the production policy: count=%d calls=%d err=%v", len(cloudflare), calls, err)
	}
	bing, err := fetchBingbotIPsWithCommand(run)
	if err != nil || strings.Join(bing, "\n") != "157.55.39.0/24\n2620:1ec:c11::/48" || calls != 3 {
		t.Fatalf("official Bing fetch failed through the production policy: ranges=%v calls=%d err=%v", bing, calls, err)
	}
}

func TestOfficialRangeCurlPolicyAllowsOnlyFixedBoundedHTTPSCommands(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"cloudflare-v4", []string{"-fsSL", "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "5", "--max-time", "20", "https://www.cloudflare.com/ips-v4/"}},
		{"cloudflare-v6", []string{"-fsSL", "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "5", "--max-time", "20", "https://www.cloudflare.com/ips-v6/"}},
		{"bing", []string{"-s", "-f", "-L", "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "5", "--max-time", "20", "https://www.bing.com/toolbox/bingbot.json"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !IsCommandAllowed("curl", tc.args) {
				t.Fatal("fixed official IP command was rejected")
			}
			for _, extra := range []string{"-k", "--insecure", "--config=/tmp/untrusted", "-o", "--next", "--url=file:///etc/passwd"} {
				args := append(append([]string(nil), tc.args...), extra)
				if IsCommandAllowed("curl", args) {
					t.Fatalf("extra curl option was accepted: %v", args)
				}
			}
			for index, value := range tc.args[:len(tc.args)-1] {
				if value != "=https" && value != "5" && value != "20" {
					continue
				}
				args := append([]string(nil), tc.args...)
				args[index] = map[string]string{"=https": "=http,https", "5": "0", "20": "600"}[value]
				if IsCommandAllowed("curl", args) {
					t.Fatalf("HTTPS or timeout constraint was changed: %v", args)
				}
			}
			original := tc.args[len(tc.args)-1]
			for _, endpoint := range []string{
				strings.Replace(original, "https://", "http://", 1),
				strings.Replace(original, "https://", "https://user@", 1),
				strings.Replace(original, ".com/", ".com.evil.example/", 1),
				strings.Replace(original, ".com/", ".com:443/", 1),
				original + "?source=other", original + "#fragment", original + "/other",
				"https://downloads.wordpress.org/plugin/example.zip", "file:///etc/passwd",
			} {
				args := append([]string(nil), tc.args...)
				args[len(args)-1] = endpoint
				if IsCommandAllowed("curl", args) {
					t.Fatalf("non-fixed endpoint was accepted: %v", args)
				}
			}
		})
	}
	if !IsCommandAllowed("curl", []string{"-s", "-f", "-L", "https://api.wordpress.org/secret-key/1.1/salt/"}) {
		t.Fatal("existing WordPress download behavior changed")
	}
	for _, args := range [][]string{
		{"--connect-timeout", "5", "https://api.wordpress.org/secret-key/1.1/salt/"},
		{"--proto", "=https", "https://www.cloudflare.com/ips-v4/"},
		{"-fsSL", "https://www.cloudflare.com/ips-v4/"},
	} {
		if IsCommandAllowed("curl", args) {
			t.Fatalf("official exception widened general curl flags: %v", args)
		}
	}
}

func TestRedisPluginDownloadCommandIsAllowedAndHTTPSBound(t *testing.T) {
	args := []string{
		"--no-config", "-q", "--https-only", "--no-hsts",
		"-T", "30", "-O", "/tmp/ols-wpanel-redis-cache.zip",
		"https://downloads.wordpress.org/plugin/redis-cache.latest-stable.zip",
	}
	if !IsCommandAllowed("wget", args) {
		t.Fatal("hardened Redis plugin download command must be accepted")
	}

	for _, unsafe := range [][]string{
		{"--no-config", "-q", "-O", "/tmp/plugin.zip", "http://downloads.wordpress.org/plugin/redis-cache.latest-stable.zip"},
		{"--no-config", "-q", "-O", "/tmp/plugin.zip", "https://downloads.wordpress.org.evil.example/plugin.zip"},
		{"--execute=use_proxy=yes", "-q", "-O", "/tmp/plugin.zip", "https://downloads.wordpress.org/plugin/redis-cache.latest-stable.zip"},
	} {
		if IsCommandAllowed("wget", unsafe) {
			t.Fatalf("unsafe Redis plugin download command was accepted: %v", unsafe)
		}
	}
}
