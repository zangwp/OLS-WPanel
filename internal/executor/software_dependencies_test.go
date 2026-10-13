package executor

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func backupDependencyTestLookup(missing ...string) func(string) (string, error) {
	return func(command string) (string, error) {
		for _, name := range missing {
			if command == name {
				return "", &exec.Error{Name: command, Err: exec.ErrNotFound}
			}
		}
		return "/usr/bin/" + command, nil
	}
}

func TestBackupDependencyRequirementsMatchActiveTransport(t *testing.T) {
	for _, test := range []struct {
		name     string
		settings backupDependencySettings
		missing  []string
	}{
		{"disabled", backupDependencySettings{}, []string{}},
		{"s3", backupDependencySettings{remoteEnabled: true, remoteType: "s3", authType: "password"}, []string{}},
		{"SSH key", backupDependencySettings{remoteEnabled: true, remoteType: "rsync", authType: "key"}, []string{"rsync", "ssh"}},
		{"SSH password defaults", backupDependencySettings{remoteEnabled: true}, []string{"rsync", "ssh", "sshpass"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := backupDependencyHealth(context.Background(), test.settings, nil, backupDependencyTestLookup("rsync", "ssh", "sshpass"))
			if !reflect.DeepEqual(report.MissingRequired, test.missing) {
				t.Fatalf("required missing = %v, want %v", report.MissingRequired, test.missing)
			}
			if report.Ready != (len(test.missing) == 0) {
				t.Fatalf("ready = %v with required missing %v", report.Ready, report.MissingRequired)
			}
			packages, err := backupDependencyInstallPackages(report)
			if err != nil {
				t.Fatal(err)
			}
			for _, pkg := range packages {
				if pkg == "sshpass" && test.settings.authType == "key" {
					t.Fatal("key authentication must not install sshpass")
				}
			}
		})
	}
}

func TestBackupDependencyErrorsAreNotMissing(t *testing.T) {
	report := backupDependencyHealth(context.Background(), backupDependencySettings{}, nil, func(command string) (string, error) {
		if command == "tar" {
			return "", errors.New("permission or inspection failure")
		}
		return backupDependencyTestLookup("gzip")(command)
	})
	if report.Status != "error" || report.Ready || !reflect.DeepEqual(report.MissingRequired, []string{"gzip"}) {
		t.Fatalf("inspection error became a missing dependency: %+v", report)
	}
	if report.Dependencies[0].Status != "error" || report.Dependencies[0].Error == "" {
		t.Fatalf("tar inspection error was lost: %+v", report.Dependencies[0])
	}
	if _, err := backupDependencyInstallPackages(report); err == nil {
		t.Fatal("unknown availability must prevent an installation plan")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report = backupDependencyHealth(ctx, backupDependencySettings{}, nil, backupDependencyTestLookup("tar"))
	if len(report.MissingRequired) != 0 || report.Status != "error" {
		t.Fatalf("cancelled detection was reported as missing: %+v", report)
	}
}

func TestBackupDependencyConfigurationErrorsAreSanitized(t *testing.T) {
	report := backupDependencyHealth(context.Background(), backupDependencySettings{}, errors.New("private SQL or password"), backupDependencyTestLookup())
	if report.Status != "error" || report.Ready || report.ConfigurationStatus != "error" {
		t.Fatalf("configuration failure was hidden: %+v", report)
	}
	if strings.Contains(report.ConfigurationError, "private") || strings.Contains(report.ConfigurationError, "password") {
		t.Fatalf("configuration failure exposed internal details: %s", report.ConfigurationError)
	}
	if _, err := backupDependencyInstallPackages(report); err == nil {
		t.Fatal("configuration failure must prevent installation")
	}
}

func TestBackupDependencyPlansAreScopedAndDeduplicated(t *testing.T) {
	report := backupDependencyHealth(context.Background(), backupDependencySettings{}, nil, backupDependencyTestLookup("tar", "gzip", "mysql", "mysqldump", "sshpass"))
	packages, err := backupDependencyInstallPackages(report)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"tar", "gzip", "mariadb-client-compat"}; !reflect.DeepEqual(packages, want) {
		t.Fatalf("packages = %v, want %v", packages, want)
	}
	for _, dependency := range []BackupDependency{
		{ID: "tar", Package: "arbitrary-package", Required: true, Status: "missing"},
		{ID: "arbitrary-id", Package: "tar", Required: true, Status: "missing"},
		{ID: "tar", Package: "tar", Required: true, Status: "unknown"},
	} {
		report.Dependencies = []BackupDependency{dependency}
		if _, err := backupDependencyInstallPackages(report); err == nil {
			t.Fatalf("unsupported dependency was accepted: %+v", dependency)
		}
	}
}

func TestBackupDependencyReportRequiresActualMySQLCommands(t *testing.T) {
	report := backupDependencyHealth(context.Background(), backupDependencySettings{}, nil, backupDependencyTestLookup("mysql", "mysqldump"))
	if !reflect.DeepEqual(report.MissingRequired, []string{"mysql", "mysqldump"}) {
		t.Fatalf("MariaDB aliases must not hide absent commands used by backups: %+v", report)
	}
	packages, err := backupDependencyInstallPackages(report)
	if err != nil || !reflect.DeepEqual(packages, []string{"mariadb-client-compat"}) {
		t.Fatalf("missing compatibility names require the alias package: %v, %v", packages, err)
	}
}

func TestBackupDependencyCompatibilityPlanAllowsNewNativeClientButNeverUpgradesOne(t *testing.T) {
	requested := []string{"mariadb-client-compat"}
	installed := map[string]string{"base-files": "1.0", "mariadb-server": "1:11.8.9-1"}
	simulation := backupDependencyTestSimulation([]string{"mariadb-client-compat", "mariadb-client", "mariadb-client-core"})
	planned, err := parseBackupDependencyPackagePlan(simulation, installed, requested)
	if err != nil || len(planned) != 3 {
		t.Fatalf("new native dependencies rejected: %v, %v", planned, err)
	}
	installed["mariadb-client"] = "1:11.8.9-1"
	if _, err := parseBackupDependencyPackagePlan(simulation, installed, requested); err == nil {
		t.Fatal("compatibility package must not permit reinstalling or upgrading the existing client")
	}
	planned, err = parseBackupDependencyPackagePlan(backupDependencyTestSimulation(requested), installed, requested)
	if err != nil || len(planned) != 1 || planned["mariadb-client-compat"] == "" {
		t.Fatalf("compatibility links without a client upgrade rejected: %v, %v", planned, err)
	}
}

func TestInstallBackupDependenciesRestoresCompatibilityNamesWithoutChangingClient(t *testing.T) {
	backupDependencyInstallTestHooks(t)
	backupDependencyLoadSettings = func(context.Context) (backupDependencySettings, error) {
		return backupDependencySettings{}, nil
	}
	aliasesInstalled := false
	backupDependencyLookPath = func(command string) (string, error) {
		if !aliasesInstalled {
			return backupDependencyTestLookup("mysql", "mysqldump")(command)
		}
		return backupDependencyTestLookup()(command)
	}
	backupDependencyReadCommand = func(_ context.Context, command string, args ...string) ([]byte, error) {
		if command == "dpkg-query" {
			return []byte("base-files\t1.0\tinstalled\nmariadb-server\t1:11.8.9-1\tinstalled\nmariadb-client\t1:11.8.9-1\tinstalled\n"), nil
		}
		if args[len(args)-1] != "mariadb-client-compat" {
			t.Fatalf("wrong package simulated: %v", args)
		}
		return backupDependencyTestSimulation([]string{"mariadb-client-compat"}), nil
	}
	var calls [][]string
	backupDependencyAPT = func(_ context.Context, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		if args[len(args)-1] == "mariadb-client-compat=1.2-1" {
			aliasesInstalled = true
		}
		return nil
	}
	report, err := InstallBackupDependencies(context.Background())
	if err != nil || !report.Ready || len(calls) != 2 {
		t.Fatalf("compatibility commands were not restored: %+v, %v, calls=%v", report, err, calls)
	}
	if strings.Contains(strings.Join(calls[1], " "), "mariadb-client=") {
		t.Fatal("an already installed native client was included in the install transaction")
	}
}

func backupDependencyInstallTestHooks(t *testing.T) {
	t.Helper()
	oldLookup, oldSettings, oldAPT, oldRead := backupDependencyLookPath, backupDependencyLoadSettings, backupDependencyAPT, backupDependencyReadCommand
	t.Cleanup(func() {
		backupDependencyLookPath, backupDependencyLoadSettings, backupDependencyAPT, backupDependencyReadCommand = oldLookup, oldSettings, oldAPT, oldRead
	})
	backupDependencyLoadSettings = func(context.Context) (backupDependencySettings, error) {
		return backupDependencySettings{remoteEnabled: true, authType: "key"}, nil
	}
	backupDependencyReadCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "dpkg-query" {
			return []byte("base-files\t1.0\tinstalled\n"), nil
		}
		requested := []string{}
		for i, argument := range args {
			if argument == "install" {
				requested = args[i+1:]
				break
			}
		}
		return backupDependencyTestSimulation(requested), nil
	}
}

func backupDependencyTestSimulation(packages []string) []byte {
	var output strings.Builder
	output.WriteString("Reading package lists...\nBuilding dependency tree...\nReading state information...\n")
	fmt.Fprintf(&output, "0 upgraded, %d newly installed, 0 to remove and 0 not upgraded.\n", len(packages))
	for _, name := range packages {
		fmt.Fprintf(&output, "Inst %s (1.2-1 Debian:13/stable [amd64])\n", name)
	}
	for _, name := range packages {
		fmt.Fprintf(&output, "Conf %s (1.2-1 Debian:13/stable [amd64])\n", name)
	}
	return []byte(output.String())
}

func TestInstallBackupDependenciesOnlyInstallsRequiredPackagesAndVerifies(t *testing.T) {
	backupDependencyInstallTestHooks(t)
	installed := false
	backupDependencyLookPath = func(command string) (string, error) {
		if !installed {
			return backupDependencyTestLookup("rsync", "ssh", "sshpass")(command)
		}
		return backupDependencyTestLookup("sshpass")(command)
	}
	var calls [][]string
	backupDependencyAPT = func(ctx context.Context, args ...string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("installation has no deadline")
		}
		calls = append(calls, append([]string{}, args...))
		if strings.Contains(strings.Join(args, " "), " install ") {
			installed = true
		}
		return nil
	}
	report, err := InstallBackupDependencies(context.Background())
	if err != nil || !report.Ready {
		t.Fatalf("verified install failed: %+v, %v", report, err)
	}
	if len(calls) != 2 {
		t.Fatalf("APT calls = %v", calls)
	}
	install := strings.Join(calls[1], " ")
	for _, required := range []string{"--no-remove", "--no-upgrade", "--no-install-recommends", "DPkg::Lock::Timeout=60", "Dir::Etc::preferences=", "Dir::Etc::preferencesparts=/dev/null", "APT::Default-Release=", "APT::Get::allow-downgrades=false", "openssh-client=1.2-1", "rsync=1.2-1"} {
		if !strings.Contains(install, required) {
			t.Fatalf("scoped install lacks %q: %s", required, install)
		}
	}
	if strings.Contains(install, "sshpass") || strings.Contains(install, "mariadb-client") {
		t.Fatalf("installation included unused or installed packages: %s", install)
	}
	if _, err := InstallBackupDependencies(context.Background()); err != nil || len(calls) != 2 {
		t.Fatalf("healthy dependencies caused another APT operation: calls=%v, err=%v", calls, err)
	}
}

func TestBackupDependencyPlanRejectsInstalledServerUpgradeAndRemovals(t *testing.T) {
	installed := map[string]string{"base-files": "1.0", "mariadb-server": "1:11.8.2-1", "libc6:amd64": "2.40-1"}
	clean := string(backupDependencyTestSimulation([]string{"mariadb-client"}))
	for _, simulation := range []string{
		strings.Replace(clean, "0 upgraded, 1 newly installed", "1 upgraded, 1 newly installed", 1),
		clean + "Inst mariadb-server [1:11.8.2-1] (1:11.8.3-1 MariaDB:11.8 [amd64])\n",
		clean + "Inst mariadb-server (1:11.8.3-1 MariaDB:11.8 [amd64])\n",
		clean + "Inst libc6 (2.41-1 Debian:13/stable [amd64])\n",
		clean + "Remv mariadb-server [1:11.8.2-1]\n",
		clean + "Conf mariadb-server (1:11.8.2-1 MariaDB:11.8 [amd64])\n",
		strings.TrimSuffix(clean, "\n"),
		clean + "Unrecognized package operation\n",
		strings.Replace(clean, "Conf mariadb-client", "Conf arbitrary-package", 1),
	} {
		if _, err := parseBackupDependencyPackagePlan([]byte(simulation), installed, []string{"mariadb-client"}); err == nil {
			t.Fatalf("unsafe or incomplete plan accepted: %s", simulation)
		}
	}
	planned, err := parseBackupDependencyPackagePlan([]byte(clean), installed, []string{"mariadb-client"})
	if err != nil || planned["mariadb-client"] != "1.2-1" {
		t.Fatalf("new-only package plan rejected: %v %v", planned, err)
	}
	preferences := backupDependencyVersionPreferences(installed, planned)
	for _, required := range []string{
		"Package: mariadb-server\nPin: version 1:11.8.2-1\nPin-Priority: 999",
		"Package: mariadb-server\nPin: version *\nPin-Priority: -1",
		"Package: libc6:amd64\nPin: version 2.40-1\nPin-Priority: 999",
		"Package: libc6:amd64\nPin: version *\nPin-Priority: -1",
		"Package: mariadb-client\nPin: version 1.2-1\nPin-Priority: 999",
		"Package: *\nPin: release *\nPin-Priority: -1",
	} {
		if !strings.Contains(preferences, required) {
			t.Fatalf("execution does not freeze the simulated versions: missing %q", required)
		}
	}
}

func TestInstallBackupDependenciesRejectsUnsafePlanBeforeInstallation(t *testing.T) {
	backupDependencyInstallTestHooks(t)
	backupDependencyLookPath = backupDependencyTestLookup("mysqldump")
	backupDependencyReadCommand = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "dpkg-query" {
			return []byte("base-files\t1.0\tinstalled\nmariadb-server\t1:11.8.2-1\tinstalled\n"), nil
		}
		return []byte("1 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\nInst mariadb-server [1:11.8.2-1] (1:11.8.3-1 MariaDB:11.8 [amd64])\n"), nil
	}
	backupDependencyAPT = func(_ context.Context, args ...string) error {
		if args[len(args)-1] != "update" {
			t.Fatal("unsafe simulation reached a real installation step")
		}
		return nil
	}
	if _, err := InstallBackupDependencies(context.Background()); err == nil {
		t.Fatal("a transitive MariaDB server upgrade was accepted")
	}
}

func TestBackupDependencyInventoryAndOutputFailClosed(t *testing.T) {
	for _, output := range []string{
		"", "base-files\t1.0\tinstalled", "base-files\t1.0\thalf-configured\n",
		"base-files\t1.0\tinstalled\nbase-files\t1.0\tinstalled\n", "unsafe name\t1.0\tinstalled\n",
	} {
		if _, err := parseBackupDependencyInstalledPackages([]byte(output)); err == nil {
			t.Fatalf("incomplete or unfinished inventory accepted: %q", output)
		}
	}
	output := backupDependencyOutput{maximum: 8}
	if written, err := output.Write([]byte("123456789")); err != nil || written != 9 || !output.truncated || output.Len() != 8 {
		t.Fatalf("truncation was not tracked: %+v %d %v", output, written, err)
	}
}

func TestInstallBackupDependenciesRejectsUnrestoredCommands(t *testing.T) {
	backupDependencyInstallTestHooks(t)
	backupDependencyLookPath = backupDependencyTestLookup("rsync")
	backupDependencyAPT = func(context.Context, ...string) error { return nil }
	report, err := InstallBackupDependencies(context.Background())
	if err == nil || report.Ready || !reflect.DeepEqual(report.MissingRequired, []string{"rsync"}) {
		t.Fatalf("install claimed success without restoring rsync: %+v, %v", report, err)
	}
}

func TestSSHBackupPreflightMatchesAuthentication(t *testing.T) {
	backupDependencyInstallTestHooks(t)
	backupDependencyLookPath = backupDependencyTestLookup("sshpass")
	if err := RequireSSHBackupDependencies("key"); err != nil {
		t.Fatalf("key authentication was blocked by sshpass: %v", err)
	}
	if err := RequireSSHBackupDependencies(""); err == nil || !strings.Contains(err.Error(), "sshpass") {
		t.Fatalf("default password authentication skipped sshpass: %v", err)
	}
	backupDependencyLookPath = backupDependencyTestLookup("rsync")
	if err := RequireSSHBackupDependencies("key"); err == nil || !strings.Contains(err.Error(), "rsync") {
		t.Fatalf("preflight skipped rsync: %v", err)
	}
}
