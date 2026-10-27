package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func lsphpAPTTestSimulation(versions map[string]string) []byte {
	var output strings.Builder
	output.WriteString("Reading package lists...\nBuilding dependency tree...\nReading state information...\n")
	fmt.Fprintf(&output, "0 upgraded, %d newly installed, 0 to remove and 0 not upgraded.\n", len(versions))
	for _, action := range []string{"Inst", "Conf"} {
		for _, name := range backupDependencySortedPackages(versions) {
			fmt.Fprintf(&output, "%s %s (%s LiteSpeed:trixie [amd64])\n", action, name, versions[name])
		}
	}
	return []byte(output.String())
}

func TestLSPHPPackageCompatibilityRequiresMatchingRuntimeAndBundledModules(t *testing.T) {
	const oldVersion = "8.3.35-1+trixie"
	const newVersion = "8.3.36-1+trixie"
	installed := map[string]string{"lsphp83": oldVersion, "lsphp83-common": oldVersion}
	for _, test := range []struct {
		name    string
		planned map[string]string
		valid   bool
	}{
		{"matching old OPcache", map[string]string{"lsphp83-opcache": oldVersion}, true},
		{"new OPcache against old core", map[string]string{"lsphp83-opcache": newVersion}, false},
		{"new curl against old core", map[string]string{"lsphp83-curl": newVersion}, false},
		{"different binary rebuild", map[string]string{"lsphp83-intl": "8.3.35-2+trixie"}, false},
		{"PECL independent versions", map[string]string{"lsphp83-redis": "6.3.0-1+trixie", "lsphp83-igbinary": "3.2.16-3+trixie", "lsphp83-imagick": "3.8.1-1+trixie"}, true},
		{"wrong PHP branch in module version", map[string]string{"lsphp83-mysql": "8.4.27-1+trixie"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateLSPHPPackageVersions(installed, test.planned, []string{"lsphp83-opcache"})
			if (err == nil) != test.valid {
				t.Fatalf("compatibility=%v, want valid=%v", err, test.valid)
			}
			if err != nil {
				var mismatch *LSPHPPackageVersionMismatchError
				if !errors.Is(err, ErrLSPHPPackageVersionMismatch) || !errors.As(err, &mismatch) || mismatch.Branch != "8.3" || mismatch.RuntimeVersion != oldVersion {
					t.Fatalf("mismatch lost safe structured information: %v", err)
				}
			}
		})
	}
}

func TestLSPHPPackageCompatibilityHandlesCommonArchitectureAllAndNewRuntimes(t *testing.T) {
	for _, branch := range []string{"83", "84", "85"} {
		version := branch[:1] + "." + branch[1:] + ".36"
		core := "lsphp" + branch
		planned := map[string]string{core: version + "-1+trixie", core + "-curl": version + "-1+trixie", core + "-common": version + "-2+trixie"}
		if err := validateLSPHPPackageVersions(nil, planned, []string{core}); err != nil {
			t.Fatalf("official Architecture:all common rebuild combination rejected: %v", err)
		}
		installed := map[string]string{core + ":arm64": version + "-2+trixie", core + "-common": version + "-1+trixie", core + "-intl:arm64": version + "-2+trixie"}
		if err := validateLSPHPPackageVersions(installed, nil, []string{core + "-intl"}); err != nil {
			t.Fatalf("architecture-qualified coherent binary packages rejected: %v", err)
		}
		installed[core+"-common"] = branch[:1] + "." + branch[1:] + ".35-1+trixie"
		if err := validateLSPHPPackageVersions(installed, nil, []string{core}); !errors.Is(err, ErrLSPHPPackageVersionMismatch) {
			t.Fatalf("different upstream PHP patch in common accepted: %v", err)
		}
	}
	if err := validateLSPHPPackageVersions(nil, map[string]string{"lsphp83-opcache": "8.3.36-1+trixie"}, []string{"lsphp83-opcache"}); !errors.Is(err, ErrLSPHPPackageVersionMismatch) {
		t.Fatalf("bundled module installed without any runtime package: %v", err)
	}
}

func TestLSPHPPackageCompatibilityOnlyChecksRequestedBranches(t *testing.T) {
	installed := map[string]string{"lsphp83": "8.3.35-1+trixie", "lsphp83-opcache": "8.3.36-1+trixie", "lsphp85": "8.5.12-1+trixie", "lsphp85-curl": "8.5.12-1+trixie"}
	for _, requested := range [][]string{{"lsphp85", "lsphp85-redis"}, {"mariadb-client-compat"}, {"nodejs"}, {"rsync"}} {
		if err := validateLSPHPPackageVersions(installed, nil, requested); err != nil {
			t.Fatalf("unused broken PHP branch blocked unrelated request %v: %v", requested, err)
		}
	}
	if err := validateLSPHPPackageVersions(installed, nil, []string{"lsphp83-redis"}); !errors.Is(err, ErrLSPHPPackageVersionMismatch) {
		t.Fatalf("existing mismatch was ignored during repair of that branch: %v", err)
	}
}

func TestLSPHPAlreadyInstalledMismatchIsRejectedBeforeNoOpOrAPT(t *testing.T) {
	backupDependencyInstallTestHooks(t)
	backupDependencyLookPath = backupDependencyTestLookup()
	backupDependencyReadCommand = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name != "dpkg-query" {
			t.Fatal("broken installed cohort reached APT planning")
		}
		return []byte("lsphp83\t8.3.35-1+trixie\tinstalled\nlsphp83-common\t8.3.35-1+trixie\tinstalled\nlsphp83-opcache\t8.3.36-1+trixie\tinstalled\n"), nil
	}
	backupDependencyAPT = func(context.Context, ...string) error { t.Fatal("broken installed cohort reached APT"); return nil }
	if err := installMissingAPTPackages(context.Background(), []string{"lsphp83", "lsphp83-common", "lsphp83-opcache"}); !errors.Is(err, ErrLSPHPPackageVersionMismatch) {
		t.Fatalf("all-installed mismatch became a successful no-op: %v", err)
	}
}

func TestLSPHPNewOnlyAPTPlanCannotMixOldCoreAndNewOPcache(t *testing.T) {
	backupDependencyInstallTestHooks(t)
	backupDependencyLookPath = backupDependencyTestLookup()
	backupDependencyReadCommand = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "dpkg-query" {
			return []byte("lsphp83\t8.3.35-1+trixie\tinstalled\nlsphp83-common\t8.3.35-1+trixie\tinstalled\n"), nil
		}
		// This simulation is valid according to the vendor's unversioned
		// common dependency, yet the new OPcache requires a newer Zend symbol.
		return lsphpAPTTestSimulation(map[string]string{"lsphp83-opcache": "8.3.36-1+trixie"}), nil
	}
	updates := 0
	backupDependencyAPT = func(_ context.Context, args ...string) error {
		if args[len(args)-1] != "update" {
			t.Fatal("incompatible module reached real APT installation")
		}
		updates++
		return nil
	}
	if err := installMissingAPTPackages(context.Background(), []string{"lsphp83-opcache"}); !errors.Is(err, ErrLSPHPPackageVersionMismatch) || updates != 1 {
		t.Fatalf("new-only package plan bypassed runtime compatibility: %v", err)
	}
}

func TestLSPHPPackageMismatchNeverIncludesRawUnverifiedVersionText(t *testing.T) {
	err := validateLSPHPPackageVersions(map[string]string{"lsphp83": "8.3.35-1+trixie", "lsphp83-opcache": "private-password\nconfig-value"}, nil, []string{"lsphp83"})
	if !errors.Is(err, ErrLSPHPPackageVersionMismatch) || strings.Contains(err.Error(), "private-password") || strings.Contains(err.Error(), "config-value") {
		t.Fatalf("unsafe version text reached diagnostics: %v", err)
	}
}
