package main

import (
	"os"
	"strings"
	"testing"
)

func TestCloudflareInstallEntryVerifiesPinnedRelease(t *testing.T) {
	workerBytes, err := os.ReadFile("deploy/cloudflare/wpanel-entry.js")
	if err != nil {
		t.Fatalf("read Cloudflare Worker: %v", err)
	}
	worker := string(workerBytes)
	for _, required := range []string{
		`const RELEASE_VERSION = "v1.1.0"`,
		`https://github.com/zangwp/OLS-WPanel/releases/download/${RELEASE_VERSION}`,
		`const BOOTSTRAP_NAME = "bootstrap.sh"`,
		`MCowBQYDK2VwAyEA5rZthMZ8gkeCHSqxa22OlYSpYtTIRY0fBrUtnLvWW9Y=`,
		`{ name: "Ed25519" }`,
		`crypto.subtle.verify(`,
		`crypto.subtle.digest("SHA-256", script)`,
		`/^([0-9a-f]{64})  bootstrap\.sh\n?$/`,
		`BOOTSTRAP_RELEASE_VERSION="${RELEASE_VERSION}"`,
		`BOOTSTRAP_DEFAULT_PREFER_CN=0`,
		`url.pathname !== "/install"`,
		`status: 503`,
	} {
		if !strings.Contains(worker, required) {
			t.Errorf("Cloudflare install entry missing security control %q", required)
		}
	}
	for _, forbidden := range []string{
		"raw.githubusercontent.com/zangwp/OLS-WPanel/main",
		"cdn.jsdelivr.net/gh/zangwp/OLS-WPanel@main",
	} {
		if strings.Contains(worker, forbidden) {
			t.Errorf("Cloudflare install entry contains mutable source %q", forbidden)
		}
	}
	verify := strings.Index(worker, "const signatureValid = await crypto.subtle.verify(")
	hash := strings.Index(worker, `const actualDigest = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", script)))`)
	serve := strings.Index(worker, "return script;")
	if verify < 0 || hash < 0 || serve < 0 || !(verify < hash && hash < serve) {
		t.Fatalf("Cloudflare bootstrap verification order is invalid: signature=%d hash=%d serve=%d", verify, hash, serve)
	}
}

func TestReadmesPromoteShortInstallerBeforeMinimalImageFallback(t *testing.T) {
	const shortCommand = "curl -fsSL https://ols.zangyubin.top/install | bash"
	const compatibilityCommand = "apt-get update && apt-get install -y --no-install-recommends curl wget ca-certificates openssl"
	for _, path := range []string{"README.md", "README.en.md"} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		readme := strings.ReplaceAll(string(contents), "\r\n", "\n")
		short := strings.Index(readme, "```bash\n"+shortCommand+"\n```")
		fallback := strings.Index(readme, compatibilityCommand)
		if short < 0 {
			t.Errorf("%s does not prominently show the short installer", path)
		}
		if fallback < 0 {
			t.Errorf("%s does not document the minimal-image compatibility command", path)
		}
		if short >= 0 && fallback >= 0 && short >= fallback {
			t.Errorf("%s shows the compatibility command before the short installer", path)
		}
	}
}

func TestCloudflareInstallEntryUsesExactCustomDomain(t *testing.T) {
	configBytes, err := os.ReadFile("deploy/cloudflare/wrangler.jsonc")
	if err != nil {
		t.Fatalf("read Wrangler config: %v", err)
	}
	config := string(configBytes)
	for _, required := range []string{
		`"name": "ols-wpanel-entry"`,
		`"workers_dev": false`,
		`"pattern": "ols.zangyubin.top"`,
		`"custom_domain": true`,
	} {
		if !strings.Contains(config, required) {
			t.Errorf("Wrangler config missing %q", required)
		}
	}
}
