package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func runtimeRepairHooks(t *testing.T) {
	t.Helper()
	read, health, ensure, install := lsphpRuntimeRead, lsphpRuntimeHealthRead, lsphpRuntimeConfigEnsure, lsphpRuntimePackageInstall
	t.Cleanup(func() {
		lsphpRuntimeRead, lsphpRuntimeHealthRead, lsphpRuntimeConfigEnsure, lsphpRuntimePackageInstall = read, health, ensure, install
	})
}

func completeRuntimeHealth(version string) LSPHPRuntimeHealth {
	health := newLSPHPRuntimeHealth(version)
	health.State = "ok"
	for i := range health.Extensions {
		health.Extensions[i].State = "loaded"
	}
	return health
}

func TestLSPHPRepairHealthyRuntimeDoesNotInstallOrRewrite(t *testing.T) {
	runtimeRepairHooks(t)
	lsphpRuntimeRead = func(version string) (LSPHPRuntime, error) {
		return LSPHPRuntime{Version: version, Installed: true}, nil
	}
	lsphpRuntimeHealthRead = func(_ context.Context, runtime LSPHPRuntime) LSPHPRuntimeHealth {
		return completeRuntimeHealth(runtime.Version)
	}
	lsphpRuntimePackageInstall = func(context.Context, []string) error { t.Fatal("healthy runtime triggered APT"); return nil }
	lsphpRuntimeConfigEnsure = func(string) error { t.Fatal("existing configuration was rewritten"); return nil }
	if runtime, err := InstallLSPHPRuntime(context.Background(), "8.5"); err != nil || runtime.Version != "8.5" {
		t.Fatalf("healthy runtime: %+v %v", runtime, err)
	}
}

func TestLSPHPRepairCompletesSelectedBranchAndPreservesConfiguration(t *testing.T) {
	runtimeRepairHooks(t)
	lsphpRuntimeRead = func(version string) (LSPHPRuntime, error) {
		return LSPHPRuntime{Version: version, Installed: true}, nil
	}
	installed := false
	lsphpRuntimeHealthRead = func(_ context.Context, runtime LSPHPRuntime) LSPHPRuntimeHealth {
		health := completeRuntimeHealth(runtime.Version)
		if !installed {
			health.State = "warning"
			health.Extensions[3].State = "missing"
		}
		return health
	}
	lsphpRuntimePackageInstall = func(_ context.Context, packages []string) error {
		for _, name := range packages {
			if !strings.HasPrefix(name, "lsphp83") {
				t.Fatalf("other branch was requested: %v", packages)
			}
		}
		installed = true
		return nil
	}
	lsphpRuntimeConfigEnsure = func(string) error { t.Fatal("existing PHP configuration was rewritten"); return nil }
	if _, err := InstallLSPHPRuntime(context.Background(), "8.3"); err != nil || !installed {
		t.Fatalf("incomplete runtime not repaired: %v", err)
	}
}

func TestLSPHPRepairCannotClaimSuccessForUnverifiedOrStillMissingModules(t *testing.T) {
	for _, state := range []string{"unknown", "warning"} {
		t.Run(state, func(t *testing.T) {
			runtimeRepairHooks(t)
			lsphpRuntimeRead = func(version string) (LSPHPRuntime, error) {
				return LSPHPRuntime{Version: version, Installed: true}, nil
			}
			lsphpRuntimeHealthRead = func(_ context.Context, runtime LSPHPRuntime) LSPHPRuntimeHealth {
				health := completeRuntimeHealth(runtime.Version)
				health.State = state
				health.Extensions[3].State = "missing"
				return health
			}
			lsphpRuntimePackageInstall = func(context.Context, []string) error { return nil }
			lsphpRuntimeConfigEnsure = func(string) error { t.Fatal("unverified configuration rewritten"); return nil }
			if _, err := InstallLSPHPRuntime(context.Background(), "8.3"); !errors.Is(err, ErrLSPHPRuntimeNotReady) {
				t.Fatalf("false success: %v", err)
			}
		})
	}
}

func TestLSPHPRepairPropagatesBlockedPackagePlan(t *testing.T) {
	runtimeRepairHooks(t)
	lsphpRuntimeRead = func(version string) (LSPHPRuntime, error) {
		return LSPHPRuntime{Version: version, Installed: true}, nil
	}
	lsphpRuntimeHealthRead = func(_ context.Context, runtime LSPHPRuntime) LSPHPRuntimeHealth {
		return newLSPHPRuntimeHealth(runtime.Version)
	}
	lsphpRuntimePackageInstall = func(context.Context, []string) error { return ErrPackagePlanChangesInstalled }
	lsphpRuntimeConfigEnsure = func(string) error { t.Fatal("blocked package plan wrote configuration"); return nil }
	if _, err := InstallLSPHPRuntime(context.Background(), "8.3"); !errors.Is(err, ErrPackagePlanChangesInstalled) {
		t.Fatalf("blocked plan: %v", err)
	}
}

func TestRuntimeHealthGateAllowsOnlyFullyLoadedExtensions(t *testing.T) {
	runtimeRepairHooks(t)
	health := completeRuntimeHealth("8.3")
	lsphpRuntimeHealthRead = func(context.Context, LSPHPRuntime) LSPHPRuntimeHealth { return health }
	for _, change := range []struct {
		state, module string
		ready         bool
	}{
		{"ok", "loaded", true}, {"warning", "loaded", true}, {"warning", "missing", false}, {"unknown", "loaded", false}, {"ok", "unknown", false},
	} {
		health.State, health.Extensions[3].State = change.state, change.module
		err := requireLSPHPRuntimeHealth(context.Background(), LSPHPRuntime{Version: "8.3", Installed: true})
		if (err == nil) != change.ready {
			t.Fatalf("gate %+v: %v", change, err)
		}
	}
}

func TestMissingAPTPlanSkipsInstalledPHPAndRejectsDependencyUpgrade(t *testing.T) {
	backupDependencyInstallTestHooks(t)
	backupDependencyLookPath = backupDependencyTestLookup()
	base := "base-files\t1.0\tinstalled\nlsphp83\t8.3.0\tinstalled\nlsphp83-common\t8.3.0\tinstalled\n"
	updates, installs := 0, 0
	backupDependencyAPT = func(_ context.Context, args ...string) error {
		if args[len(args)-1] == "update" {
			updates++
		} else {
			installs++
		}
		return nil
	}
	backupDependencyReadCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "dpkg-query" {
			return []byte(base), nil
		}
		joined := strings.Join(args, " ")
		if strings.Contains(joined, " install lsphp83 ") || strings.Contains(joined, "lsphp83-common") {
			t.Fatalf("existing packages included: %s", joined)
		}
		return lsphpAPTTestSimulation(map[string]string{"lsphp83-curl": "8.3.0"}), nil
	}
	if err := installMissingAPTPackages(context.Background(), []string{"lsphp83", "lsphp83-common"}); err != nil || updates+installs != 0 {
		t.Fatalf("no-op altered APT: %v", err)
	}
	if err := installMissingAPTPackages(context.Background(), []string{"lsphp83", "lsphp83-common", "lsphp83-curl"}); err != nil || updates != 1 || installs != 1 {
		t.Fatalf("missing extension: %v", err)
	}
	backupDependencyReadCommand = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "dpkg-query" {
			return []byte(base), nil
		}
		return backupDependencyTestSimulation([]string{"lsphp83", "lsphp83-curl"}), nil
	}
	if err := installMissingAPTPackages(context.Background(), []string{"lsphp83-curl"}); !errors.Is(err, ErrPackagePlanChangesInstalled) || installs != 1 {
		t.Fatalf("upgrade executed: %v", err)
	}
}
