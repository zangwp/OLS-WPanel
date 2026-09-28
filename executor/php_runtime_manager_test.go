package executor

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestSupportedLSPHPVersionAllowlist(t *testing.T) {
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
