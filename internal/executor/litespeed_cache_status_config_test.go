package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

const testLiteSpeedCacheModule = `module cache {
  ls_enabled 1
  checkPublicCache 1
  checkPrivateCache 1
  storagePath $VH_ROOT/.lscache
  enableCache 0
  enablePrivateCache 0
}
`

func liteSpeedCacheConfigFixture(t *testing.T, module string) (*config.Config, *models.Website) {
	t.Helper()
	root := t.TempDir()
	available, enabled := filepath.Join(root, "available"), filepath.Join(root, "enabled")
	for _, dir := range []string{available, enabled} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	site := &models.Website{Domain: "example.com", SiteType: "wordpress", Status: models.StatusActive, WebRoot: filepath.Join(root, "www", "example.com"), OLSVHostConfigPath: filepath.Join(available, "example.conf"), LSCacheEnabled: true}
	content := "# OLS-WPanel-Format: 1\n# OLS-WPanel-VHost: olsw_example\n# OLS-WPanel-Domains: example.com\n# OLS-WPanel-VHRoot: " + site.WebRoot + "\ndocRoot " + site.WebRoot + "\nvhDomain example.com\n" + module
	if err := os.WriteFile(site.OLSVHostConfigPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(site.OLSVHostConfigPath, filepath.Join(enabled, "example.conf")); err != nil {
		t.Skipf("test requires symlinks: %v", err)
	}
	return &config.Config{Paths: config.PathsConfig{OLSVHostsAvailable: available, OLSVHostsEnabled: enabled}}, site
}

func TestLiteSpeedServerCacheReadsActualSelectiveModuleNotDBFlag(t *testing.T) {
	cfg, site := liteSpeedCacheConfigFixture(t, testLiteSpeedCacheModule)
	for _, legacyFlag := range []bool{false, true} {
		site.LSCacheEnabled = legacyFlag
		state, reason, configured := observeLiteSpeedServerCache(cfg, site)
		if state != "configured" || reason != "module_ready" || configured == nil || !*configured {
			t.Fatalf("legacy flag=%t actual configuration=%s/%s/%v", legacyFlag, state, reason, configured)
		}
	}
}

func TestLiteSpeedModuleConfigurationIsNotDisabledBySelectiveDefault(t *testing.T) {
	for _, tc := range []struct {
		name, content, state, reason string
		configured                   bool
	}{
		{"plugin controlled public cache", testLiteSpeedCacheModule, "configured", "module_ready", true},
		{"missing", "# module cache is not configured", "misconfigured", "cache_module_missing", false},
		{"disabled module", strings.Replace(testLiteSpeedCacheModule, "ls_enabled 1", "ls_enabled 0", 1), "misconfigured", "cache_module_invalid", false},
		{"no lookup", strings.Replace(testLiteSpeedCacheModule, "checkPublicCache 1", "checkPublicCache 0", 1), "misconfigured", "cache_module_invalid", false},
		{"missing private lookup", strings.Replace(testLiteSpeedCacheModule, "checkPrivateCache 1", "", 1), "misconfigured", "cache_module_invalid", false},
		{"legacy default policy", strings.Replace(testLiteSpeedCacheModule, "enableCache 0", "enableCache 1", 1), "misconfigured", "unsafe_public_cache_default", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, reason, configured := classifyLiteSpeedCacheModule(tc.content)
			if state != tc.state || reason != tc.reason || configured == nil || *configured != tc.configured {
				t.Fatalf("configuration=%s/%s/%v", state, reason, configured)
			}
		})
	}
}

func TestLiteSpeedCacheVHostMetadataMustMatchActualDomainAndDocumentRoot(t *testing.T) {
	root := t.TempDir()
	content := "docRoot " + root + "\nvhDomain example.com\n"
	if !liteSpeedCacheVHostIdentityMatches(content, "example.com", root) {
		t.Fatal("valid managed identity rejected")
	}
	for _, altered := range []string{
		strings.Replace(content, "example.com", "other.example.com", 1),
		strings.Replace(content, root, filepath.Join(root, "other"), 1),
		content + "vhDomain other.example.com\n",
		"# " + content,
	} {
		if liteSpeedCacheVHostIdentityMatches(altered, "example.com", root) {
			t.Fatalf("accepted ambiguous/wrong configuration identity:\n%s", altered)
		}
	}
}

func TestLiteSpeedServerCacheReportsMissingInvalidAndLegacyBlanketPolicy(t *testing.T) {
	for _, tc := range []struct{ name, content, reason string }{
		{"missing", "", "cache_module_missing"},
		{"disabled module", strings.Replace(testLiteSpeedCacheModule, "ls_enabled 1", "ls_enabled 0", 1), "cache_module_invalid"},
		{"no public lookup", strings.Replace(testLiteSpeedCacheModule, "checkPublicCache 1", "checkPublicCache 0", 1), "cache_module_invalid"},
		{"wrong storage", strings.Replace(testLiteSpeedCacheModule, "$VH_ROOT/.lscache", "/other/site", 1), "cache_module_invalid"},
		{"blanket policy", strings.Replace(testLiteSpeedCacheModule, "enableCache 0", "enableCache 1", 1), "unsafe_public_cache_default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, site := liteSpeedCacheConfigFixture(t, tc.content)
			state, reason, configured := observeLiteSpeedServerCache(cfg, site)
			if state != "misconfigured" || reason != tc.reason || configured == nil || *configured {
				t.Fatalf("got %s/%s/%v", state, reason, configured)
			}
		})
	}
}

func TestLiteSpeedServerCacheRejectsUnknownOrInactiveConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(*config.Config, *models.Website)
	}{
		{"missing config", "config_unavailable", func(cfg *config.Config, _ *models.Website) {
			cfg.Paths.OLSVHostsAvailable = filepath.Join(t.TempDir(), "other")
		}},
		{"wrong domain", "untrusted_vhost", func(_ *config.Config, site *models.Website) { site.Domain = "other.example.com" }},
		{"wrong root", "untrusted_vhost", func(_ *config.Config, site *models.Website) { site.WebRoot = t.TempDir() }},
		{"disabled vhost", "inactive_vhost", func(cfg *config.Config, _ *models.Website) { cfg.Paths.OLSVHostsEnabled = t.TempDir() }},
		{"paused", "inactive_site", func(_ *config.Config, site *models.Website) { site.Status = models.StatusPaused }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, site := liteSpeedCacheConfigFixture(t, testLiteSpeedCacheModule)
			tc.change(cfg, site)
			state, reason, configured := observeLiteSpeedServerCache(cfg, site)
			if state != "unknown" || reason != tc.reason || configured != nil {
				t.Fatalf("got %s/%s/%v", state, reason, configured)
			}
		})
	}
}

func TestLiteSpeedCacheModuleParserDoesNotGuessFromCommentsOrDuplicateSettings(t *testing.T) {
	for _, content := range []string{
		"# module cache {\n# ls_enabled 1\n# }\n",
		"rewrite {\nrules <<<END_rules\n" + testLiteSpeedCacheModule + "END_rules\n}\n",
		testLiteSpeedCacheModule + testLiteSpeedCacheModule,
		strings.Replace(testLiteSpeedCacheModule, "enableCache 0", "enableCache 0\n enableCache 1", 1),
		strings.TrimSuffix(testLiteSpeedCacheModule, "}\n"),
	} {
		if values, err := liteSpeedCacheModuleValues(content); err == nil {
			t.Fatalf("ambiguous configuration was accepted: %#v\n%s", values, content)
		}
	}
}
