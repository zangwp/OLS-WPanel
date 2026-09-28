package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/config"
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
		"type                   lsapi",
		"address                uds://",
		"path                   /usr/local/lsws/lsphp83/bin/lsphp",
		"extUser                wp_example",
		"autoLoadHtaccess       1",
		"module cache {",
		"enableCache            1",
		"expireInSeconds        7200",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("generated vhost missing %q\n%s", want, content)
		}
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
