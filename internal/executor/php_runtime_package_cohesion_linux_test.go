//go:build linux

package executor

import (
	"context"
	"os"
	"testing"
	"time"
)

// The surrounding CI script installs the current LSPHP 8.3 cohort through the
// installer's authenticated APT repository inside a disposable Debian container.
// This test only reads the installed package inventory and invokes LSAPI -i.
func TestLSPHPPackageCohesionRuntimeLinux(t *testing.T) {
	if os.Getenv("OLS_WPANEL_PACKAGE_COHESION_TEST") != "1" {
		t.Skip("requires the disposable LSPHP package runtime container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the package runtime container must run as root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("refusing the package runtime check outside a Docker container")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	output, err := runBackupDependencyReadCommand(ctx, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n", "lsphp83*")
	if err != nil {
		t.Fatal(err)
	}
	installed, err := parseBackupDependencyInstalledPackages(output)
	if err != nil {
		t.Fatal(err)
	}
	packages, err := lsphpRuntimePackages("8.3")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range packages {
		if !backupDependencyPackageIsInstalled(installed, name) {
			t.Fatalf("authenticated runtime cohort is incomplete: %s", name)
		}
	}
	if err := validateLSPHPPackageVersions(installed, nil, packages); err != nil {
		t.Fatalf("current official package cohort was rejected: %v", err)
	}
	runtime, err := ResolveLSPHPRuntime("8.3", true)
	if err != nil {
		t.Fatal(err)
	}
	health := ReadLSPHPRuntimeHealth(ctx, runtime)
	if !lsphpRuntimeHealthReady(health) {
		t.Fatalf("current official cohort did not load all extensions: state=%s reason=%s diagnostic=%+v", health.State, health.Reason, health.Diagnostic)
	}
	t.Logf("LSPHP83_PACKAGE_COHESION_RUNTIME_OK core=%s common=%s opcache=%s", installed["lsphp83"], installed["lsphp83-common"], installed["lsphp83-opcache"])
}
