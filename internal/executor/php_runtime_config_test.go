package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
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

	want := filepath.Join("/usr/local/lsws", "lsphp84", "etc", "php", "8.4", "mods-available", "99-ols-wpanel.ini")
	if got := PHPRuntimeConfigPath(); got != want {
		t.Fatalf("PHPRuntimeConfigPath() = %q, want %q", got, want)
	}
}

func TestPHPRuntimeConfigMigrationPreservesValuesAndRollbackCopy(t *testing.T) {
	root := t.TempDir()
	for _, version := range []string{"8.3", "8.4", "8.5"} {
		branch := filepath.Join(root, "lsphp"+strings.ReplaceAll(version, ".", ""), "etc", "php", version)
		legacy := filepath.Join(branch, "litespeed", "conf.d", "99-ols-wpanel.ini")
		actual := filepath.Join(branch, "mods-available", "99-ols-wpanel.ini")
		original := "; administrator configuration for " + version + "\nmemory_limit = 512M\nopcache.memory_consumption = 320\nopcache.enable = 0\n"
		if err := os.MkdirAll(filepath.Dir(legacy), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(legacy, []byte(original), 0644); err != nil {
			t.Fatal(err)
		}
		// Windows exposes writable files as 0666. A read-only source models a
		// trusted ini on both hosts without weakening production trust checks.
		if err := os.Chmod(legacy, 0400); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(legacy, 0644) })
		changed, err := migratePHPRuntimeConfig(legacy, actual)
		if err != nil || !changed {
			t.Fatalf("migration for %s: changed=%v err=%v", version, changed, err)
		}
		for _, path := range []string{legacy, actual} {
			content, err := os.ReadFile(path)
			if err != nil || string(content) != original {
				t.Fatalf("migration altered %s: %s, %v", path, content, err)
			}
		}
		if changed, err := migratePHPRuntimeConfig(legacy, actual); err != nil || changed {
			t.Fatalf("repeat migration for %s: changed=%v err=%v", version, changed, err)
		}
		updated := "memory_limit = 768M\n"
		if err := os.WriteFile(actual, []byte(updated), 0644); err != nil {
			t.Fatal(err)
		}
		if changed, err := migratePHPRuntimeConfig(legacy, actual); err != nil || changed {
			t.Fatalf("existing configuration for %s overwritten: %v, %v", version, changed, err)
		}
		content, _ := os.ReadFile(actual)
		if string(content) != updated {
			t.Fatalf("newer administrator configuration replaced for %s", version)
		}
	}
}

func TestPHPRuntimeConfigMigrationWithoutLegacyDoesNotCreateConfig(t *testing.T) {
	root := t.TempDir()
	actual := filepath.Join(root, "mods-available", "99-ols-wpanel.ini")
	changed, err := migratePHPRuntimeConfig(filepath.Join(root, "missing.ini"), actual)
	if err != nil || changed {
		t.Fatalf("missing legacy configuration: %v, %v", changed, err)
	}
	if _, err := os.Stat(actual); !os.IsNotExist(err) {
		t.Fatalf("missing legacy unexpectedly created configuration: %v", err)
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
