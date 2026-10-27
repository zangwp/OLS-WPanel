package executor

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

const aptAutoremoveAdvice = "The following packages were automatically installed and are no longer required:\n  linux-image-6.12.48+deb13-amd64 libmagickcore-7.q16-10-extra\nUse 'apt autoremove' to remove them.\n"

func TestMissingAPTPlanAcceptsAutoremoveAdviceWithoutAuthorizingRemoval(t *testing.T) {
	installed := map[string]string{"base-files": "13.8", "lsphp83": "8.3.35-1+trixie", "lsphp83-common": "8.3.35-1+trixie"}
	clean := string(backupDependencyTestSimulation([]string{"lsphp83-curl", "lsphp83-igbinary"}))
	plan := strings.Replace(clean, "Reading state information...\n", "Reading state information...\n"+aptAutoremoveAdvice, 1)
	planned, err := parseBackupDependencyPackagePlan([]byte(plan), installed, []string{"lsphp83-curl", "lsphp83-igbinary"})
	if err != nil || len(planned) != 2 {
		t.Fatalf("new-only extension plan with harmless APT advice rejected: %v, %v", planned, err)
	}
	for _, unsafe := range []string{
		plan + "Remv linux-image-6.12.48+deb13-amd64 [6.12.48-1]\n",
		plan + "Purg libmagickcore-7.q16-10-extra [8:7.1.1.43+dfsg1-1]\n",
		plan + "Inst lsphp83 [8.3.35-1+trixie] (8.3.36-1+trixie LiteSpeed:trixie [amd64])\n",
		strings.Replace(plan, "0 upgraded,", "1 upgraded,", 1),
		strings.Replace(plan, "Use 'apt autoremove' to remove them.\n", "", 1),
		strings.Replace(plan, "  linux-image-6.12.48+deb13-amd64 libmagickcore-7.q16-10-extra", "  Remv lsphp83 [8.3.35-1+trixie]", 1),
		strings.Replace(plan, "Use 'apt autoremove' to remove them.", "Use 'apt autoremove --purge' to remove them.", 1),
		plan + aptAutoremoveAdvice,
	} {
		if _, err := parseBackupDependencyPackagePlan([]byte(unsafe), installed, []string{"lsphp83-curl", "lsphp83-igbinary"}); err == nil {
			t.Fatalf("unsafe or incomplete plan accepted: %s", unsafe)
		}
	}
}

func TestMissingAPTPinsInstalledRuntimeDuringPlanningAndExecution(t *testing.T) {
	backupDependencyInstallTestHooks(t)
	backupDependencyLookPath = backupDependencyTestLookup()
	const inventory = "base-files\t13.8\tinstalled\nlsphp83\t8.3.35-1+trixie\tinstalled\nlsphp83-common\t8.3.35-1+trixie\tinstalled\nlsphp85\t8.5.10-1+trixie\tinstalled\n"
	var simulations, installs, updates int
	readPreferences := func(args []string) string {
		t.Helper()
		for _, arg := range args {
			if path, found := strings.CutPrefix(arg, "Dir::Etc::preferences="); found {
				content, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("private APT pins unavailable: %v", err)
				}
				for _, installed := range []string{
					"Package: lsphp83\nPin: version 8.3.35-1+trixie\nPin-Priority: 999",
					"Package: lsphp83\nPin: version *\nPin-Priority: -1",
					"Package: lsphp85\nPin: version 8.5.10-1+trixie\nPin-Priority: 999",
				} {
					if !strings.Contains(string(content), installed) {
						t.Fatalf("installed version not frozen before resolving dependencies: %q", installed)
					}
				}
				return string(content)
			}
		}
		t.Fatal("APT did not receive private preference file")
		return ""
	}
	backupDependencyReadCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "dpkg-query" {
			return []byte(inventory), nil
		}
		simulations++
		preferences := readPreferences(args)
		if strings.Contains(preferences, "Package: *\n") || strings.Contains(strings.Join(args, " "), "APT::Default-Release=") {
			t.Fatalf("preview replaced administrator policy for new packages: %s, %v", preferences, args)
		}
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "--no-remove --no-upgrade --no-install-recommends install lsphp83-curl lsphp83-igbinary") {
			t.Fatalf("repair included installed runtime or lost package safeguards: %s", joined)
		}
		plan := string(backupDependencyTestSimulation([]string{"lsphp83-curl", "lsphp83-igbinary"}))
		return []byte(strings.Replace(plan, "Reading state information...\n", "Reading state information...\n"+aptAutoremoveAdvice, 1)), nil
	}
	backupDependencyAPT = func(_ context.Context, args ...string) error {
		if args[len(args)-1] == "update" {
			updates++
			return nil
		}
		installs++
		preferences := readPreferences(args)
		if !strings.HasSuffix(preferences, "Package: *\nPin: release *\nPin-Priority: -1\n") ||
			!strings.Contains(preferences, "Package: lsphp83-curl\nPin: version 1.2-1\nPin-Priority: 999") {
			t.Fatalf("execution did not freeze the new package versions: %s", preferences)
		}
		joined := strings.Join(args, " ")
		if !strings.HasSuffix(joined, " install lsphp83-curl=1.2-1 lsphp83-igbinary=1.2-1") {
			t.Fatalf("execution included unexpected packages: %s", joined)
		}
		return nil
	}
	if err := installMissingAPTPackages(context.Background(), []string{"lsphp83", "lsphp83-common", "lsphp83-curl", "lsphp83-igbinary"}); err != nil {
		t.Fatal(err)
	}
	if simulations != 1 || installs != 1 || updates != 1 {
		t.Fatalf("unexpected APT operations: simulations=%d, installs=%d, updates=%d", simulations, installs, updates)
	}
}

func TestMissingAPTIncompatibleDependenciesNeverTriggerUpgradeFallback(t *testing.T) {
	backupDependencyInstallTestHooks(t)
	backupDependencyLookPath = backupDependencyTestLookup()
	backupDependencyReadCommand = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "dpkg-query" {
			return []byte("base-files\t13.8\tinstalled\nlsphp83\t8.3.35-1+trixie\tinstalled\n"), nil
		}
		return nil, errors.New("held packages or incompatible dependency versions")
	}
	updates := 0
	backupDependencyAPT = func(_ context.Context, args ...string) error {
		if args[len(args)-1] != "update" {
			t.Fatal("incompatible extensions triggered installation or upgrade fallback")
		}
		updates++
		return nil
	}
	if err := installMissingAPTPackages(context.Background(), []string{"lsphp83-curl"}); !errors.Is(err, ErrPackagePlanChangesInstalled) || updates != 1 || !strings.Contains(err.Error(), "held packages or incompatible dependency versions") {
		t.Fatalf("incompatible extension did not fail safely: %v", err)
	}
}

func TestMissingAPTPreflightDiagnosticsAreBoundedAndRedacted(t *testing.T) {
	cause := errors.New("exit status 100")
	diagnostics := "E: Failed to fetch https://private-user:private-password@packages.example.invalid/php.deb\n" + strings.Repeat("dependency conflict ", 400)
	err := backupDependencyPreflightError(cause, "Reading package lists...\n", diagnostics, false)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "[redacted]@packages.example.invalid") ||
		strings.Contains(err.Error(), "private-user") || strings.Contains(err.Error(), "private-password") || len(err.Error()) > 2200 {
		t.Fatalf("preflight diagnostic was lost, exposed credentials or exceeded its bound: %v", err)
	}
	if err := backupDependencyPreflightError(nil, "complete plan", "W: repository diagnostics", false); err == nil || !strings.Contains(err.Error(), "contains diagnostics") {
		t.Fatalf("stderr diagnostic was ignored: %v", err)
	}
	if err := backupDependencyPreflightError(nil, strings.Repeat("x", 3000), "", true); err == nil || !strings.Contains(err.Error(), "incomplete") || len(err.Error()) > 2200 {
		t.Fatalf("truncated preflight output was accepted or unbounded: %v", err)
	}
}

func TestLSPHPRepairRequestsIgbinaryEvenWhenRedisIsAlreadyInstalled(t *testing.T) {
	for _, version := range []string{"8.3", "8.4", "8.5"} {
		packages, err := lsphpRuntimePackages(version)
		if err != nil {
			t.Fatal(err)
		}
		want := "lsphp" + strings.ReplaceAll(version, ".", "") + "-igbinary"
		found := false
		for _, name := range packages {
			found = found || name == want
		}
		if !found {
			t.Fatalf("missing %s cannot be repaired when Redis is already installed: %v", want, packages)
		}
	}
}
