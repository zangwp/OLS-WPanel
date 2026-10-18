//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"testing"
)

// Exercise the real fetch -> executeCommand -> Execute -> curl boundary.
// The fixture executable serves local bodies and never opens a network socket.
func TestOfficialIPFetchesUseActualDispatcher(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "curl-arguments.log")
	for name, data := range map[string]string{
		"cloudflare-v4": refreshOfficialCFV4,
		"cloudflare-v6": refreshOfficialCFV6,
		"bingbot.json":  officialBingRangesFixture,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$OLS_CURL_TEST_LOG"
for endpoint do :; done
case "$endpoint" in
  https://www.cloudflare.com/ips-v4/) file=cloudflare-v4 ;;
  https://www.cloudflare.com/ips-v6/) file=cloudflare-v6 ;;
  https://www.bing.com/toolbox/bingbot.json) file=bingbot.json ;;
  *) exit 91 ;;
esac
cat "$OLS_CURL_TEST_FIXTURES/$file"
`
	if err := os.WriteFile(filepath.Join(directory, "curl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OLS_CURL_TEST_LOG", logPath)
	t.Setenv("OLS_CURL_TEST_FIXTURES", directory)
	cloudflare, err := fetchCloudflareIPs()
	if err != nil || len(cloudflare) != 22 {
		t.Fatalf("Cloudflare could not execute its bounded official download: count=%d err=%v", len(cloudflare), err)
	}
	bing, err := fetchBingbotIPs()
	if err != nil || len(bing) != 2 {
		t.Fatalf("Bing could not execute its bounded official download: count=%d err=%v", len(bing), err)
	}
	if result, err := Execute("curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "5", "--max-time", "20", "https://www.cloudflare.com/ips-v4/", "--insecure"); err == nil || result != nil {
		t.Fatalf("the dispatcher allowed an insecure command to execute: %+v %v", result, err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal("the dispatcher never executed the curl fixture", err)
	}
	expected := "-fsSL --proto =https --proto-redir =https --connect-timeout 5 --max-time 20 https://www.cloudflare.com/ips-v4/\n" +
		"-fsSL --proto =https --proto-redir =https --connect-timeout 5 --max-time 20 https://www.cloudflare.com/ips-v6/\n" +
		"-s -f -L --proto =https --proto-redir =https --connect-timeout 5 --max-time 20 https://www.bing.com/toolbox/bingbot.json\n"
	if string(data) != expected {
		t.Fatalf("the executed commands lost their HTTPS or timeout constraints: %q", data)
	}
}
