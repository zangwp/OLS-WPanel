package executor

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func testOLSVHostData(root string) *OLSVHostData {
	return &OLSVHostData{
		Domain:         "example.com",
		Aliases:        []string{"www.example.com"},
		WebRoot:        filepath.Join(root, "www", "example.com"),
		LogDir:         filepath.Join(root, "logs", "example.com"),
		SystemUser:     "wp_example",
		SiteType:       "wordpress",
		PHPProxy:       "unix:" + filepath.Join(root, "run", "example.sock"),
		TemplateVer:    "v1.0",
		AccessLogMode:  "all",
		LSCacheEnabled: true,
		LSCacheTTL:     7200,
		PHPMaxChildren: 12,
	}
}

// Tests of registry behavior do not need a host www-data account or permission
// to change file ownership. The owner validation tests below supply their own
// lookup and chown behavior so they still exercise those failure branches.
func stubOLSDefaultVHostOwnership(t *testing.T) {
	t.Helper()
	oldLookup := lookupOLSDefaultVHostUser
	oldChown := chownOLSDefaultVHostRoot
	lookupOLSDefaultVHostUser = func(string) (*user.User, error) {
		return &user.User{Username: "www-data", Uid: "33", Gid: "33"}, nil
	}
	chownOLSDefaultVHostRoot = func(string, int, int) error { return nil }
	t.Cleanup(func() {
		lookupOLSDefaultVHostUser = oldLookup
		chownOLSDefaultVHostRoot = oldChown
	})
}

func TestRenderOLSVHostIncludesLSPHPAndLiteSpeedCache(t *testing.T) {
	old := config.AppConfig
	config.AppConfig = nil
	t.Cleanup(func() { config.AppConfig = old })

	content, err := renderOLSVHostConfig(testOLSVHostData(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# OLS-WPanel-Format: 1",
		"# OLS-WPanel-Domains: example.com,www.example.com",
		"indexFiles             index.php,index.html\n",
		"type                   lsapi",
		"address                uds://",
		"path                   /usr/local/lsws/lsphp85/bin/lsphp",
		"extUser                wp_example",
		"autoLoadHtaccess       1",
		"module cache {",
		"enableCache            0",
		"expireInSeconds        7200",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("generated vhost missing %q\n%s", want, content)
		}
	}
}

func TestWordPressLegacyCacheFlagNeverEnablesDefaultPublicCache(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		data := testOLSVHostData(t.TempDir())
		data.LSCacheEnabled = enabled
		content := mustRenderOLSVHost(t, data)
		for _, expected := range []string{"module cache {", "ls_enabled             1", "checkPublicCache       1", "storagePath            $VH_ROOT/.lscache", "enableCache            0"} {
			if !strings.Contains(content, expected) {
				t.Fatalf("legacy flag %t lost selective plugin cache support %q", enabled, expected)
			}
		}
		if strings.Contains(content, "enableCache            1") {
			t.Fatalf("legacy flag %t enables default public caching", enabled)
		}
	}
}

func TestRenderOLSVHostTLSRetainsSNIPathsAndModernProtocols(t *testing.T) {
	data := testOLSVHostData(t.TempDir())
	data.UseSSL = true
	data.SSLCertPath = filepath.Join(t.TempDir(), "fullchain.pem")
	data.SSLKeyPath = filepath.Join(t.TempDir(), "privkey.pem")
	content := mustRenderOLSVHost(t, data)
	for _, want := range []string{
		"# OLS-WPanel-Domains: example.com,www.example.com",
		"keyFile                " + data.SSLKeyPath,
		"certFile               " + data.SSLCertPath,
		"certChain              1",
		"sslProtocol            24\n",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("TLS vhost missing %q\n%s", want, content)
		}
	}
	if olsTLSProtocols != 8|16 || strings.Contains(content, "sslProtocol            30") {
		t.Fatal("TLS defaults must allow only TLS 1.2 and TLS 1.3")
	}
	data.UseSSL = false
	if strings.Contains(mustRenderOLSVHost(t, data), "vhssl {") {
		t.Fatal("HTTP-only vhost must not gain a TLS certificate block")
	}
}

func TestLSPHPServerAndCLIPathsRemainSeparate(t *testing.T) {
	oldCfg := config.AppConfig
	config.AppConfig = &config.Config{Paths: config.PathsConfig{
		LSPHPBinary: "/opt/ols/bin/lsphp",
		LSPHPCLI:    "/opt/ols/bin/php",
	}}
	t.Cleanup(func() { config.AppConfig = oldCfg })

	if got := LSPHPBinaryPath(); got != "/opt/ols/bin/php" {
		t.Fatalf("CLI PHP path = %q", got)
	}
	content := mustRenderOLSVHost(t, testOLSVHostData(t.TempDir()))
	if !strings.Contains(content, "path                   /opt/ols/bin/lsphp") {
		t.Fatalf("vhost did not retain LSAPI server binary:\n%s", content)
	}
}

func TestRenderOLSVHostGenericPHPDoesNotEnableLSCache(t *testing.T) {
	data := testOLSVHostData(t.TempDir())
	data.SiteType = "php"
	content, err := renderOLSVHostConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(content, "module cache {") {
		t.Fatal("generic PHP vhost unexpectedly contains LiteSpeed Cache module")
	}
}

func TestRenderOLSVHostCanonicalAliasRedirectPreservesPathAndQuery(t *testing.T) {
	data := testOLSVHostData(t.TempDir())
	data.AliasRedirectMode = AliasRedirectPermanent
	data.UseSSL = true
	data.SSLCertPath = filepath.Join(t.TempDir(), "fullchain.pem")
	data.SSLKeyPath = filepath.Join(t.TempDir(), "privkey.pem")
	content := mustRenderOLSVHost(t, data)
	for _, want := range []string{
		`RewriteCond %{HTTP_HOST} ^(?:www\.example\.com)(?::[0-9]+)?$ [NC]`,
		`RewriteRule ^/?(.*)$ https://example.com/$1 [R=301,L]`,
		`RewriteCond %{HTTP_HOST} ^example\.com(?::[0-9]+)?$ [NC]`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("canonical redirect missing %q\n%s", want, content)
		}
	}
	if strings.Contains(content, "https://%{HTTP_HOST}") {
		t.Fatal("generated redirect must not reflect an untrusted Host header")
	}
}

func TestRenderOLSVHostTemporaryAliasRedirectWithoutSSL(t *testing.T) {
	data := testOLSVHostData(t.TempDir())
	data.AliasRedirectMode = AliasRedirectTemporary
	content := mustRenderOLSVHost(t, data)
	if !strings.Contains(content, `RewriteRule ^/?(.*)$ http://example.com/$1 [R=302,L]`) {
		t.Fatalf("temporary redirect missing:\n%s", content)
	}
}

func TestRenderOLSVHostLoadsGlobalSQLiPolicyAtEveryRender(t *testing.T) {
	old := loadOLSSQLiProtectionSettings
	t.Cleanup(func() { loadOLSSQLiProtectionSettings = old })
	for _, enabled := range []bool{true, false} {
		loadOLSSQLiProtectionSettings = func() (bool, bool) { return enabled, false }
		data := testOLSVHostData(t.TempDir())
		// A caller's obsolete booleans must not override the current global policy.
		data.SQLiBlockEnabled, data.SQLiAutoBanLog = !enabled, true
		content := mustRenderOLSVHost(t, data)
		expected := *data
		expected.SQLiBlockEnabled, expected.SQLiAutoBanLog = enabled, false
		if !OLSVHostSecurityRulesMatch(content, &expected) {
			t.Fatalf("render did not use current global SQLi policy enabled=%v", enabled)
		}
		if data.SQLiBlockEnabled != !enabled || !data.SQLiAutoBanLog {
			t.Fatal("render mutated the caller's vhost data")
		}
	}
}

func TestRenderOLSVHostDeniesBeforeRedirectAndRetainsHtaccess(t *testing.T) {
	data := testOLSVHostData(t.TempDir())
	data.AliasRedirectMode, data.UseSSL = AliasRedirectPermanent, true
	data.SSLCertPath, data.SSLKeyPath = filepath.Join(t.TempDir(), "cert.pem"), filepath.Join(t.TempDir(), "key.pem")
	content := mustRenderOLSVHost(t, data)
	deny := strings.Index(content, "E=OLS_WPANEL_SECURITY:uploads_php")
	redirect := strings.Index(content, "RewriteCond %{HTTP_HOST}")
	if deny < 0 || redirect <= deny {
		t.Fatal("security rules must run before canonical/HTTPS redirects")
	}
	if strings.Count(content, "rules                  <<<END_rules") != 1 || !strings.Contains(content, "autoLoadHtaccess       1") {
		t.Fatal("security and redirects must share one vhost rewrite block and preserve WordPress .htaccess")
	}
}

func TestRenderOLSVHostSecurityLoggingMinimizesDisabledAccessLogs(t *testing.T) {
	for _, mode := range []string{"off", "error_only", "", "full"} {
		t.Run(mode, func(t *testing.T) {
			data := testOLSVHostData(t.TempDir())
			data.AccessLogMode = mode
			content := mustRenderOLSVHost(t, data)
			if strings.Count(content, "accesslog ") != 1 {
				t.Fatal("WordPress security logging must use exactly one access log")
			}
			if !strings.Contains(content, `ols_security=\"%{OLS_WPANEL_SECURITY}e\" ols_autoban=\"%{OLS_WPANEL_SQLI_AUTOBAN}e\"`) {
				t.Fatal("trusted terminal environment markers missing")
			}
			if mode == "full" {
				if !strings.Contains(content, `%r`) || !strings.Contains(content, `%{User-Agent}i`) {
					t.Fatal("full access logging must retain request and user agent")
				}
			} else if strings.Contains(content, "%r") || strings.Contains(content, "%{Referer}i") || strings.Contains(content, "%{User-Agent}i") || !strings.Contains(content, `%m %U %H`) {
				t.Fatal("minimal security logging must omit query/referrer/user-agent data")
			}
		})
	}
	data := testOLSVHostData(t.TempDir())
	data.SiteType, data.AccessLogMode = "php", "off"
	if strings.Contains(mustRenderOLSVHost(t, data), "accesslog ") {
		t.Fatal("generic PHP access logging must remain disabled")
	}
}

func TestOLSVHostSecurityRulesMatchRejectsIncompleteOrStalePolicy(t *testing.T) {
	old := loadOLSSQLiProtectionSettings
	loadOLSSQLiProtectionSettings = func() (bool, bool) { return true, true }
	t.Cleanup(func() { loadOLSSQLiProtectionSettings = old })
	data := testOLSVHostData(t.TempDir())
	data.SQLiBlockEnabled, data.SQLiAutoBanLog = true, true
	content := mustRenderOLSVHost(t, data)
	if !OLSVHostSecurityRulesMatch(content, data) {
		t.Fatal("current complete policy was rejected")
	}
	for _, tampered := range []string{
		olsSiteSecurityBegin + olsSiteSecurityEnd,
		strings.ReplaceAll(content, "E=OLS_WPANEL_SECURITY:sqli", "E=OLS_WPANEL_SECURITY:none"),
		strings.ReplaceAll(content, `%{OLS_WPANEL_SECURITY}e`, `%{OLS_WPANEL_SECURITY}i`),
		strings.ReplaceAll(content, "autoLoadHtaccess       1", "autoLoadHtaccess       0"),
	} {
		if OLSVHostSecurityRulesMatch(tampered, data) {
			t.Fatal("incomplete or untrusted security configuration accepted")
		}
	}
	expected := *data
	expected.XMLRPCEnabled = true
	if OLSVHostSecurityRulesMatch(content, &expected) {
		t.Fatal("stale XML-RPC policy accepted")
	}
}

func TestRenderOLSVHostAllowsOnlyOwnSiteLogDirectoryInPHP(t *testing.T) {
	data := testOLSVHostData(t.TempDir())
	content := mustRenderOLSVHost(t, data)
	want := sitePHPOpenBaseDir(data.WebRoot, data.Domain) + ":" + data.LogDir
	if !strings.Contains(content, `open_basedir "`+want+`"`) {
		t.Fatal("WordPress login hook must have access to only its own site's log directory")
	}
	data.SiteType = "php"
	if strings.Contains(mustRenderOLSVHost(t, data), `open_basedir "`+want+`"`) {
		t.Fatal("generic PHP site must not gain the WordPress security-log permission")
	}
}

func TestNormalizeAliasRedirectModeRejectsUnknownValue(t *testing.T) {
	if _, err := NormalizeAliasRedirectMode("javascript"); err == nil {
		t.Fatal("unknown alias redirect mode accepted")
	}
	if got, err := NormalizeAliasRedirectMode(""); err != nil || got != AliasRedirectServe {
		t.Fatalf("empty mode = %q, %v", got, err)
	}
}

func TestRenderOLSManagedRegistryKeepsServerRunnableWithoutSites(t *testing.T) {
	oldIPv6 := olsIPv6Available
	olsIPv6Available = func() bool { return false }
	t.Cleanup(func() { olsIPv6Available = oldIPv6 })
	root := t.TempDir()
	enabled := filepath.Join(root, "sites-enabled")
	managed := filepath.Join(root, "sites.conf")
	if err := os.MkdirAll(enabled, 0750); err != nil {
		t.Fatal(err)
	}
	old := config.AppConfig
	config.AppConfig = &config.Config{Paths: config.PathsConfig{
		OLSRoot:          root,
		OLSManagedConfig: managed,
		OLSListenerCert:  filepath.Join(root, "default.crt"),
		OLSListenerKey:   filepath.Join(root, "default.key"),
	}}
	t.Cleanup(func() { config.AppConfig = old })
	oldLookup := lookupOLSDefaultVHostUser
	oldChown := chownOLSDefaultVHostRoot
	var chownPath string
	var chownUID, chownGID int
	lookupOLSDefaultVHostUser = func(name string) (*user.User, error) {
		if name != "www-data" {
			t.Fatalf("lookup user = %q", name)
		}
		return &user.User{Username: name, Uid: "33", Gid: "33"}, nil
	}
	chownOLSDefaultVHostRoot = func(path string, uid, gid int) error {
		chownPath, chownUID, chownGID = path, uid, gid
		return nil
	}
	t.Cleanup(func() {
		lookupOLSDefaultVHostUser = oldLookup
		chownOLSDefaultVHostRoot = oldChown
	})

	content, err := renderOLSManagedRegistry(enabled)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"virtualHost olsw_default {",
		"enableScript           0",
		"configFile             " + filepath.ToSlash(filepath.Join(root, "default-vhost.conf")),
		"map                    olsw_default *",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("empty registry missing %q:\n%s", want, content)
		}
	}
	if got := strings.Count(content, "map                    olsw_default *"); got != 2 {
		t.Fatalf("default listener mappings = %d, want 2", got)
	}

	paths := currentOLSRuntimePaths()
	if err := ensureOLSDefaultVHost(paths); err != nil {
		t.Fatal(err)
	}
	defaultRoot, defaultConfig := olsDefaultVHostPaths(paths)
	if info, err := os.Stat(defaultRoot); err != nil || !info.IsDir() {
		t.Fatalf("default root was not created: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(filepath.Join(defaultRoot, ".well-known", "acme-challenge")); err != nil || !info.IsDir() {
		t.Fatalf("ACME context directory was not created: info=%v err=%v", info, err)
	}
	if chownPath != defaultRoot || chownUID != 33 || chownGID != 33 {
		t.Fatalf("default root owner repair = (%q,%d,%d), want (%q,33,33)", chownPath, chownUID, chownGID, defaultRoot)
	}
	data, err := os.ReadFile(defaultConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "vhDomain                ols-wpanel.invalid") || !strings.Contains(string(data), "allowBrowse            0") {
		t.Fatalf("unsafe or incomplete default vhost:\n%s", data)
	}
}

func TestEnsureOLSDefaultVHostRejectsPrivilegedOwner(t *testing.T) {
	root := t.TempDir()
	paths := olsRuntimePaths{root: root, managed: filepath.Join(root, "sites.conf")}
	oldLookup := lookupOLSDefaultVHostUser
	oldChown := chownOLSDefaultVHostRoot
	lookupOLSDefaultVHostUser = func(string) (*user.User, error) {
		return &user.User{Username: "www-data", Uid: "0", Gid: "33"}, nil
	}
	chownOLSDefaultVHostRoot = func(string, int, int) error {
		t.Fatal("chown must not run for an unsafe identity")
		return nil
	}
	t.Cleanup(func() {
		lookupOLSDefaultVHostUser = oldLookup
		chownOLSDefaultVHostRoot = oldChown
	})

	err := ensureOLSDefaultVHost(paths)
	if err == nil || !strings.Contains(err.Error(), "UID") {
		t.Fatalf("unsafe UID error = %v", err)
	}
}

func TestEnsureOLSDefaultVHostReportsOwnerRepairFailure(t *testing.T) {
	root := t.TempDir()
	paths := olsRuntimePaths{root: root, managed: filepath.Join(root, "sites.conf")}
	oldLookup := lookupOLSDefaultVHostUser
	oldChown := chownOLSDefaultVHostRoot
	lookupOLSDefaultVHostUser = func(string) (*user.User, error) {
		return &user.User{Username: "www-data", Uid: "33", Gid: "33"}, nil
	}
	chownOLSDefaultVHostRoot = func(string, int, int) error {
		return errors.New("permission denied")
	}
	t.Cleanup(func() {
		lookupOLSDefaultVHostUser = oldLookup
		chownOLSDefaultVHostRoot = oldChown
	})

	err := ensureOLSDefaultVHost(paths)
	if err == nil || !strings.Contains(err.Error(), "目录所有者") {
		t.Fatalf("owner repair error = %v", err)
	}
}

func TestRenderOLSManagedRegistryRejectsDuplicateDomain(t *testing.T) {
	root := t.TempDir()
	available := filepath.Join(root, "sites-available")
	enabled := filepath.Join(root, "sites-enabled")
	if err := os.MkdirAll(available, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(enabled, 0750); err != nil {
		t.Fatal(err)
	}
	old := config.AppConfig
	config.AppConfig = &config.Config{Paths: config.PathsConfig{OLSVHostsAvailable: available}}
	t.Cleanup(func() { config.AppConfig = old })

	for i, name := range []string{"one", "two"} {
		content := strings.ReplaceAll(mustRenderOLSVHost(t, testOLSVHostData(root)), "olsw_example_com", "olsw_"+name)
		path := filepath.Join(available, name+".conf")
		if err := os.WriteFile(path, []byte(content), 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path, filepath.Join(enabled, name+".conf")); err != nil {
			t.Fatal(err)
		}
		_ = i
	}
	if _, err := renderOLSManagedRegistry(enabled); err == nil || !strings.Contains(err.Error(), "域名映射重复") {
		t.Fatalf("duplicate domain error = %v", err)
	}
}

func TestRenderOLSManagedRegistryRejectsEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	available := filepath.Join(root, "sites-available")
	enabled := filepath.Join(root, "sites-enabled")
	outside := filepath.Join(root, "outside.conf")
	if err := os.MkdirAll(available, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(enabled, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte(mustRenderOLSVHost(t, testOLSVHostData(root))), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(enabled, "escape.conf")); err != nil {
		t.Fatal(err)
	}
	old := config.AppConfig
	config.AppConfig = &config.Config{Paths: config.PathsConfig{OLSVHostsAvailable: available}}
	t.Cleanup(func() { config.AppConfig = old })
	if _, err := renderOLSManagedRegistry(enabled); err == nil {
		t.Fatal("escaping enabled-site symlink was accepted")
	}
}

func TestApplyOLSVHostRollsBackWhenOLSTestFails(t *testing.T) {
	oldIPv6 := olsIPv6Available
	olsIPv6Available = func() bool { return false }
	t.Cleanup(func() { olsIPv6Available = oldIPv6 })
	root := t.TempDir()
	available := filepath.Join(root, "sites-available")
	enabled := filepath.Join(root, "sites-enabled")
	managed := filepath.Join(root, "sites.conf")
	if err := os.MkdirAll(available, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(enabled, 0750); err != nil {
		t.Fatal(err)
	}

	oldCfg := config.AppConfig
	config.AppConfig = &config.Config{Paths: config.PathsConfig{
		OLSVHostsAvailable: available, OLSVHostsEnabled: enabled,
		OLSManagedConfig: managed, OLSBinary: filepath.Join(root, "openlitespeed"),
		LSPHPBinary:     "/usr/local/lsws/lsphp83/bin/lsphp",
		OLSListenerCert: filepath.Join(root, "default.crt"), OLSListenerKey: filepath.Join(root, "default.key"),
	}}
	t.Cleanup(func() { config.AppConfig = oldCfg })

	target := filepath.Join(available, "example.com.conf")
	link := filepath.Join(enabled, "example.com.conf")
	oldContent := mustRenderOLSVHost(t, testOLSVHostData(root))
	newData := testOLSVHostData(root)
	newData.LSCacheTTL = 3333
	newContent := mustRenderOLSVHost(t, newData)
	if err := os.WriteFile(target, []byte(oldContent), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed, []byte("old registry\n"), 0640); err != nil {
		t.Fatal(err)
	}

	oldRun := runOLSCommand
	testCalls := 0
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if name == config.AppConfig.Paths.OLSBinary {
			testCalls++
			if testCalls == 1 {
				return []byte("invalid"), errors.New("exit 1")
			}
		}
		return []byte("ok"), nil
	}
	t.Cleanup(func() { runOLSCommand = oldRun })

	if err := applyOLSVHostConfig(NewTemplateEngine(""), newContent, target, link); err == nil {
		t.Fatal("apply unexpectedly succeeded")
	}
	restored, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != oldContent {
		t.Fatal("vhost content was not rolled back")
	}
	linked, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(linked) != filepath.Clean(target) {
		t.Fatalf("enabled link = %s, want %s", linked, target)
	}
}

func mustRenderOLSVHost(t *testing.T, data *OLSVHostData) string {
	t.Helper()
	content, err := renderOLSVHostConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	return content
}
