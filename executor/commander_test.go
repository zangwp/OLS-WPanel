package executor

import "testing"

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
