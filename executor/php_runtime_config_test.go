package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/config"
)

func TestPHPRuntimeConfigPathFollowsConfiguredPrimaryRuntime(t *testing.T) {
	oldPath := phpRuntimeConfigPath
	previousConfig := config.AppConfig
	phpRuntimeConfigPath = ""
	config.AppConfig = &config.Config{Paths: config.PathsConfig{
		LSPHPCLI: "/usr/local/lsws/lsphp84/bin/php",
	}}
	t.Cleanup(func() {
		phpRuntimeConfigPath = oldPath
		config.AppConfig = previousConfig
	})

	want := filepath.Join("/usr/local/lsws", "lsphp84", "etc", "php", "8.4", "litespeed", "conf.d", "99-ols-wpanel.ini")
	if got := PHPRuntimeConfigPath(); got != want {
		t.Fatalf("PHPRuntimeConfigPath() = %q, want %q", got, want)
	}
}

func TestEnsurePHPRuntimeConfigFileAddsMissingKeys(t *testing.T) {
	oldPath := phpRuntimeConfigPath
	phpRuntimeConfigPath = filepath.Join(t.TempDir(), "99-olswpanel.ini")
	t.Cleanup(func() { phpRuntimeConfigPath = oldPath })

	original := "memory_limit = 512M\nupload_max_filesize = 128M\npost_max_size = 128M\nmax_execution_time = 100\nmax_input_vars = 3000\n"
	if err := os.WriteFile(phpRuntimeConfigPath, []byte(original), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	changed, err := EnsurePHPRuntimeConfigFile()
	if err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	if !changed {
		t.Fatal("expected missing max_input_time to be added")
	}

	data, err := os.ReadFile(phpRuntimeConfigPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "max_input_time = 300") {
		t.Fatalf("expected max_input_time default, got:\n%s", content)
	}
	if !strings.Contains(content, "upload_max_filesize = 128M") {
		t.Fatalf("expected existing values to be preserved, got:\n%s", content)
	}
	for _, want := range []string{
		"expose_php = Off",
		"opcache.enable = 1",
		"opcache.interned_strings_buffer = 8",
		"opcache.validate_timestamps = 1",
		"opcache.revalidate_freq = 5",
		"opcache.save_comments = 1",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected new static default %q to be added, got:\n%s", want, content)
		}
	}
	if findIniValue(content, "opcache.memory_consumption") == "" {
		t.Fatalf("expected opcache.memory_consumption to be added, got:\n%s", content)
	}
	if findIniValue(content, "opcache.max_accelerated_files") == "" {
		t.Fatalf("expected opcache.max_accelerated_files to be added, got:\n%s", content)
	}
}

func TestEnsurePHPRuntimeConfigFileDoesNotOverwriteExistingOpcacheValues(t *testing.T) {
	oldPath := phpRuntimeConfigPath
	phpRuntimeConfigPath = filepath.Join(t.TempDir(), "99-olswpanel.ini")
	t.Cleanup(func() { phpRuntimeConfigPath = oldPath })

	original := "opcache.memory_consumption = 999\nopcache.max_accelerated_files = 777\nexpose_php = On\n"
	if err := os.WriteFile(phpRuntimeConfigPath, []byte(original), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := EnsurePHPRuntimeConfigFile(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	data, err := os.ReadFile(phpRuntimeConfigPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	content := string(data)
	if findIniValue(content, "opcache.memory_consumption") != "999" {
		t.Fatalf("expected admin-set opcache.memory_consumption to be preserved, got:\n%s", content)
	}
	if findIniValue(content, "opcache.max_accelerated_files") != "777" {
		t.Fatalf("expected admin-set opcache.max_accelerated_files to be preserved, got:\n%s", content)
	}
	if findIniValue(content, "expose_php") != "On" {
		t.Fatalf("expected admin-set expose_php to be preserved, got:\n%s", content)
	}
}

func TestEnsurePHPRuntimeConfigFileFreshInstallIncludesOpcacheDefaults(t *testing.T) {
	oldPath := phpRuntimeConfigPath
	phpRuntimeConfigPath = filepath.Join(t.TempDir(), "99-olswpanel.ini")
	t.Cleanup(func() { phpRuntimeConfigPath = oldPath })

	changed, err := EnsurePHPRuntimeConfigFile()
	if err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	if !changed {
		t.Fatal("expected fresh install to write the config file")
	}

	data, err := os.ReadFile(phpRuntimeConfigPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	content := string(data)
	if findIniValue(content, "max_input_vars") != "10000" {
		t.Fatalf("expected fresh install to use the new max_input_vars default, got:\n%s", content)
	}
	if findIniValue(content, "opcache.memory_consumption") == "" {
		t.Fatalf("expected fresh install to include opcache.memory_consumption, got:\n%s", content)
	}
}

func TestRenderOLSVHostUsesRuntimeConfig(t *testing.T) {
	oldPath := phpRuntimeConfigPath
	phpRuntimeConfigPath = filepath.Join(t.TempDir(), "99-olswpanel.ini")
	t.Cleanup(func() { phpRuntimeConfigPath = oldPath })

	content := "memory_limit = 512M\nupload_max_filesize = 128M\npost_max_size = 128M\nmax_execution_time = 100\nmax_input_time = 100\nmax_input_vars = 3000\n"
	if err := os.WriteFile(phpRuntimeConfigPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	rendered, err := renderOLSVHostConfig(&OLSVHostData{
		Domain: "example.com", SystemUser: "wp_example",
		WebRoot: "/www/wwwroot/example.com", LogDir: "/www/wwwlogs/example.com",
		PHPProxy: "unix:/tmp/lshttpd/example.sock", TemplateVer: "v1.0", SiteType: "wordpress",
	})
	if err != nil {
		t.Fatalf("render pool: %v", err)
	}

	for _, want := range []string{
		"php_admin_value upload_max_filesize 128M",
		"php_admin_value post_max_size 128M",
		"php_admin_value max_execution_time 100",
		"php_admin_value max_input_time 100",
		"php_admin_value memory_limit 512M",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered vhost missing %q:\n%s", want, rendered)
		}
	}
}

func TestRenderOLSVHostUsesPersistedMaxChildren(t *testing.T) {
	rendered, err := renderOLSVHostConfig(&OLSVHostData{
		Domain: "example.com", SystemUser: "wp_example",
		WebRoot: "/www/wwwroot/example.com", LogDir: "/www/wwwlogs/example.com",
		PHPProxy: "unix:/tmp/lshttpd/example.sock", TemplateVer: "v1.0", SiteType: "wordpress", PHPMaxChildren: 6,
	})
	if err != nil {
		t.Fatalf("render pool: %v", err)
	}
	if !strings.Contains(rendered, "maxConns               6") || !strings.Contains(rendered, "PHP_LSAPI_CHILDREN=6") {
		t.Fatalf("expected persisted MaxChildren to be rendered, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "pm.max_children") {
		t.Fatalf("expected legacy pool directives to be absent, got:\n%s", rendered)
	}
}

func TestRenderOLSVHostFallsBackWhenMaxChildrenInvalid(t *testing.T) {
	for _, bad := range []int{0, -5, 1001} {
		rendered, err := renderOLSVHostConfig(&OLSVHostData{
			Domain: "example.com", SystemUser: "wp_example",
			WebRoot: "/www/wwwroot/example.com", LogDir: "/www/wwwlogs/example.com",
			PHPProxy: "unix:/tmp/lshttpd/example.sock", TemplateVer: "v1.0", SiteType: "wordpress", PHPMaxChildren: bad,
		})
		if err != nil {
			t.Fatalf("render vhost with PHPMaxChildren=%d: %v", bad, err)
		}
		if !strings.Contains(rendered, "maxConns               10") || !strings.Contains(rendered, "PHP_LSAPI_CHILDREN=10") {
			t.Fatalf("expected PHPMaxChildren=%d to fall back to 10, got:\n%s", bad, rendered)
		}
	}
}
