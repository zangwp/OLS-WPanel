package executor

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestSupportedLSPHPVersionAllowlist(t *testing.T) {
	got, err := normalizeLSPHPVersion("")
	if err != nil || got != "8.5" {
		t.Fatalf("blank LSPHP version = %q, %v; want fresh-install default 8.5", got, err)
	}
	for _, version := range []string{"8.3", "8.4", "8.5"} {
		got, err := normalizeLSPHPVersion(version)
		if err != nil || got != version {
			t.Fatalf("normalizeLSPHPVersion(%q) = %q, %v", version, got, err)
		}
	}
	for _, version := range []string{"7.4", "8.2", "8.6", "latest", "8.5;id"} {
		if _, err := normalizeLSPHPVersion(version); err == nil {
			t.Errorf("normalizeLSPHPVersion(%q) unexpectedly succeeded", version)
		}
	}
}

func TestPrimaryLSPHPVersionPreservesConfiguredExistingRuntime(t *testing.T) {
	previous := config.AppConfig
	config.AppConfig = &config.Config{Paths: config.PathsConfig{
		LSPHPBinary: "/usr/local/lsws/lsphp83/bin/lsphp",
		LSPHPCLI:    "/usr/local/lsws/lsphp83/bin/php",
	}}
	t.Cleanup(func() { config.AppConfig = previous })

	if got := PrimaryLSPHPVersion(); got != "8.3" {
		t.Fatalf("PrimaryLSPHPVersion() = %q, want configured 8.3", got)
	}
	runtime, err := lsphpRuntimeForVersion("8.3")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.LSAPIBinary != config.AppConfig.Paths.LSPHPBinary || runtime.CLIBinary != config.AppConfig.Paths.LSPHPCLI {
		t.Fatalf("configured primary runtime paths were not preserved: %+v", runtime)
	}
	if !runtime.Primary {
		t.Fatal("configured LSPHP 8.3 must be marked as the panel primary runtime")
	}
}

func TestPrimaryLSPHPVersionDefaultsToLatestVerifiedRuntime(t *testing.T) {
	previous := config.AppConfig
	config.AppConfig = nil
	t.Cleanup(func() { config.AppConfig = previous })

	if got := PrimaryLSPHPVersion(); got != "8.5" {
		t.Fatalf("PrimaryLSPHPVersion() = %q, want 8.5", got)
	}
	runtime, err := lsphpRuntimeForVersion("8.5")
	if err != nil {
		t.Fatal(err)
	}
	if !runtime.Recommended {
		t.Fatal("LSPHP 8.5 must be marked as the recommended fresh-install runtime")
	}
	if !runtime.Primary {
		t.Fatal("default LSPHP 8.5 must be marked as the panel primary runtime")
	}
}

func TestLSPHPRuntimePathsAreDerivedFromAllowlist(t *testing.T) {
	for _, version := range []string{"8.4", "8.5"} {
		runtime, err := lsphpRuntimeForVersion(version)
		if err != nil {
			t.Fatal(err)
		}
		suffix := version[:1] + version[2:]
		root := filepath.Join("/usr/local/lsws", "lsphp"+suffix, "bin")
		if runtime.Package != "lsphp"+suffix || runtime.LSAPIBinary != filepath.Join(root, "lsphp") || runtime.CLIBinary != filepath.Join(root, "php") {
			t.Fatalf("unexpected runtime descriptor for %s: %+v", version, runtime)
		}
	}
}

func TestLSPHPRuntimePackagesMatchLiteSpeedRepository(t *testing.T) {
	for _, version := range []string{"8.3", "8.4"} {
		packages, err := lsphpRuntimePackages(version)
		if err != nil {
			t.Fatal(err)
		}
		suffix := version[:1] + version[2:]
		if !slices.Contains(packages, "lsphp"+suffix+"-opcache") {
			t.Fatalf("LSPHP %s should install its separate OPcache package: %v", version, packages)
		}
	}

	packages, err := lsphpRuntimePackages("8.5")
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(packages, "lsphp85-opcache") {
		t.Fatalf("LiteSpeed does not publish lsphp85-opcache: %v", packages)
	}
	for _, required := range []string{"lsphp85", "lsphp85-common", "lsphp85-mysql", "lsphp85-curl", "lsphp85-intl", "lsphp85-redis", "lsphp85-imagick"} {
		if !slices.Contains(packages, required) {
			t.Fatalf("LSPHP 8.5 package list missing %s: %v", required, packages)
		}
	}
}
