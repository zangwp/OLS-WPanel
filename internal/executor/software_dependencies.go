package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

// BackupDependency describes a local command used by a backup operation.
// RequiredFor names the operations that need it; Required reflects the active
// remote configuration, so an unused SSH transport never blocks local or S3 backups.
type BackupDependency struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Package     string   `json:"package"`
	Commands    []string `json:"commands"` // Alternative names for the same operation.
	Status      string   `json:"status"`
	Required    bool     `json:"required"`
	RequiredFor []string `json:"required_for"`
	Error       string   `json:"error,omitempty"`
}

type BackupDependencyHealth struct {
	Status              string             `json:"status"`
	Ready               bool               `json:"ready"`
	RemoteEnabled       bool               `json:"remote_enabled"`
	RemoteType          string             `json:"remote_type"`
	AuthType            string             `json:"auth_type"`
	ConfigurationStatus string             `json:"configuration_status"`
	ConfigurationError  string             `json:"configuration_error,omitempty"`
	Dependencies        []BackupDependency `json:"dependencies"`
	MissingRequired     []string           `json:"missing_required"`
}

type backupDependencySettings struct {
	remoteEnabled bool
	remoteType    string
	authType      string
}

var (
	backupDependencyLookPath       = exec.LookPath
	backupDependencyLoadSettings   = readBackupDependencySettings
	backupDependencyAPT            = runBackupDependencyAPT
	backupDependencyReadCommand    = runBackupDependencyReadCommand
	backupDependencyInstallMu      sync.Mutex
	ErrBackupDependencyInstallBusy = errors.New("backup dependency installation is already running")
)

func readBackupDependencySettings(ctx context.Context) (backupDependencySettings, error) {
	db := database.GetDB()
	if db == nil {
		return backupDependencySettings{}, errors.New("backup configuration unavailable")
	}
	var settings backupDependencySettings
	var enabled int
	// No credentials or remote paths are needed for dependency detection.
	if err := db.QueryRowContext(ctx, `SELECT enabled, backup_type, auth_type FROM remote_backup_settings WHERE id = 1`).Scan(
		&enabled, &settings.remoteType, &settings.authType); err != nil {
		return backupDependencySettings{}, errors.New("backup configuration unavailable")
	}
	settings.remoteEnabled = enabled == 1
	return settings, nil
}

func backupDependencyDefinitions() []BackupDependency {
	return []BackupDependency{
		{ID: "tar", Name: "tar", Package: "tar", Commands: []string{"tar"}, RequiredFor: []string{"local_files"}},
		{ID: "gzip", Name: "gzip", Package: "gzip", Commands: []string{"gzip"}, RequiredFor: []string{"local_files"}},
		{ID: "mysql", Name: "MySQL/MariaDB restore client", Package: "mariadb-client-compat", Commands: backupCommandCandidates("mysql"), RequiredFor: []string{"local_database_restore"}},
		{ID: "mysqldump", Name: "MySQL/MariaDB dump", Package: "mariadb-client-compat", Commands: backupCommandCandidates("mysqldump"), RequiredFor: []string{"local_database"}},
		{ID: "rsync", Name: "rsync", Package: "rsync", Commands: []string{"rsync"}, RequiredFor: []string{"remote_ssh"}},
		{ID: "ssh", Name: "OpenSSH client", Package: "openssh-client", Commands: []string{"ssh"}, RequiredFor: []string{"remote_ssh"}},
		{ID: "sshpass", Name: "sshpass", Package: "sshpass", Commands: []string{"sshpass"}, RequiredFor: []string{"remote_ssh_password"}},
	}
}

// ReadBackupDependencyHealth only reads settings and looks up fixed commands.
// It performs no package operations, network probes, or backup configuration changes.
func ReadBackupDependencyHealth(ctx context.Context) BackupDependencyHealth {
	if ctx == nil {
		ctx = context.Background()
	}
	settings, err := backupDependencyLoadSettings(ctx)
	return backupDependencyHealth(ctx, settings, err, backupDependencyLookPath)
}

func backupDependencyHealth(ctx context.Context, settings backupDependencySettings, settingsErr error, lookPath func(string) (string, error)) BackupDependencyHealth {
	if settings.remoteType == "" {
		settings.remoteType = "rsync"
	}
	if settings.authType == "" {
		settings.authType = "password"
	}
	report := BackupDependencyHealth{
		Status: "installed", Ready: true,
		RemoteEnabled: settings.remoteEnabled, RemoteType: settings.remoteType, AuthType: settings.authType,
		ConfigurationStatus: "ok", Dependencies: backupDependencyDefinitions(), MissingRequired: []string{},
	}
	if settingsErr != nil {
		report.ConfigurationStatus, report.ConfigurationError = "error", "backup configuration unavailable"
	} else if settings.remoteEnabled && settings.remoteType != "rsync" && settings.remoteType != "s3" {
		report.ConfigurationStatus, report.ConfigurationError = "error", "unsupported remote backup type"
	} else if settings.remoteEnabled && settings.remoteType == "rsync" && settings.authType != "key" && settings.authType != "password" {
		report.ConfigurationStatus, report.ConfigurationError = "error", "unsupported SSH authentication type"
	}
	sshActive := report.ConfigurationStatus == "ok" && settings.remoteEnabled && settings.remoteType == "rsync"
	for i := range report.Dependencies {
		dependency := &report.Dependencies[i]
		switch dependency.ID {
		case "rsync", "ssh":
			dependency.Required = sshActive
		case "sshpass":
			dependency.Required = sshActive && settings.authType == "password"
		default:
			dependency.Required = true
		}
		dependency.Status = "installed"
		if err := ctx.Err(); err != nil {
			dependency.Status, dependency.Error = "error", "dependency detection interrupted"
		} else {
			_, err := findBackupCommand(dependency.Commands, lookPath)
			if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
				dependency.Status = "missing"
			} else if err != nil {
				dependency.Status, dependency.Error = "error", "command availability could not be checked"
			}
		}
		if dependency.Required && dependency.Status == "missing" {
			report.MissingRequired = append(report.MissingRequired, dependency.ID)
			if report.Status != "error" {
				report.Status = "missing"
			}
			report.Ready = false
		} else if dependency.Required && dependency.Status == "error" {
			report.Status, report.Ready = "error", false
		}
	}
	if report.ConfigurationStatus == "error" {
		report.Status, report.Ready = "error", false
	}
	return report
}

func backupDependencyInstallPackages(report BackupDependencyHealth) ([]string, error) {
	if report.ConfigurationStatus != "ok" {
		return nil, errors.New("backup configuration could not be checked")
	}
	allowed := make(map[string]string)
	for _, dependency := range backupDependencyDefinitions() {
		allowed[dependency.ID] = dependency.Package
	}
	packages := []string{}
	seen := make(map[string]bool)
	for _, dependency := range report.Dependencies {
		if !dependency.Required {
			continue
		}
		if expected, ok := allowed[dependency.ID]; !ok || expected != dependency.Package {
			return nil, errors.New("unsupported backup dependency")
		}
		switch dependency.Status {
		case "installed":
			continue
		case "missing":
			if !seen[dependency.Package] {
				packages = append(packages, dependency.Package)
				seen[dependency.Package] = true
			}
		default:
			return nil, errors.New("backup dependency availability could not be checked")
		}
	}
	return packages, nil
}

// InstallBackupDependencies installs only missing packages for active backup
// operations. A complete APT simulation must contain only new packages. Private
// version pins then prevent installed-package upgrades during execution; the
// caller should use a server-owned context.
func InstallBackupDependencies(ctx context.Context) (BackupDependencyHealth, error) {
	if !backupDependencyInstallMu.TryLock() {
		return BackupDependencyHealth{}, ErrBackupDependencyInstallBusy
	}
	defer backupDependencyInstallMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	report := ReadBackupDependencyHealth(ctx)
	packages, err := backupDependencyInstallPackages(report)
	if err != nil || len(packages) == 0 {
		return report, err
	}
	if err := installMissingAPTPackages(ctx, packages); err != nil {
		return ReadBackupDependencyHealth(ctx), err
	}
	report = ReadBackupDependencyHealth(ctx)
	if !report.Ready {
		return report, errors.New("backup commands remain unavailable after installation")
	}
	return report, nil
}

var ErrPackagePlanChangesInstalled = errors.New("package plan would change installed software")

// Shared by backup and PHP repair. Only missing packages from a caller-owned
// allowlist may be added; existing versions are pinned throughout execution.
func installMissingAPTPackages(ctx context.Context, packages []string) error {
	if _, err := backupDependencyLookPath("apt-get"); err != nil {
		return errors.New("APT is unavailable")
	}
	installedOutput, err := backupDependencyReadCommand(ctx, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n")
	if err != nil {
		return errors.New("installed package inventory could not be checked")
	}
	installed, err := parseBackupDependencyInstalledPackages(installedOutput)
	if err != nil {
		return err
	}
	missing := []string{}
	for _, name := range packages {
		if !backupDependencyPackageNameRE.MatchString(name) {
			return errors.New("invalid package name")
		}
		if !backupDependencyPackageIsInstalled(installed, name) {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	aptOptions := []string{"-o", "Acquire::Retries=2", "-o", "Acquire::http::Timeout=30", "-o", "Acquire::https::Timeout=30", "-o", "DPkg::Lock::Timeout=60"}
	if err := backupDependencyAPT(ctx, append(append([]string{}, aptOptions...), "update")...); err != nil {
		return err
	}
	prefsDir, err := os.MkdirTemp("", "ols-backup-dependencies-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(prefsDir)
	prefsPath := filepath.Join(prefsDir, "preferences")
	// Freeze installed versions before solving dependencies, not only before
	// execution. Otherwise APT may prefer an unnecessary newer PHP common
	// package even when the missing extensions work with the installed one.
	originalPreferences, err := backupDependencyPreferencesRead(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPackagePlanChangesInstalled, err)
	}
	if err := os.WriteFile(prefsPath, []byte(backupDependencyPlanningPreferences(installed)+originalPreferences), 0600); err != nil {
		return err
	}
	pinOptions := []string{"-o", "Dir::Etc::preferences=" + prefsPath, "-o", "Dir::Etc::preferencesparts=/dev/null", "-o", "APT::Get::allow-downgrades=false"}
	simulateArgs := append([]string{}, aptOptions...)
	simulateArgs = append(simulateArgs, pinOptions...)
	simulateArgs = append(simulateArgs, "--simulate", "--no-remove", "--no-upgrade", "--no-install-recommends", "install")
	simulateArgs = append(simulateArgs, missing...)
	simulation, err := backupDependencyReadCommand(ctx, "apt-get", simulateArgs...)
	if err != nil {
		return fmt.Errorf("%w: package plan could not be checked: %v", ErrPackagePlanChangesInstalled, err)
	}
	planned, err := parseBackupDependencyPackagePlan(simulation, installed, missing)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPackagePlanChangesInstalled, err)
	}
	if err := os.WriteFile(prefsPath, []byte(backupDependencyVersionPreferences(installed, planned)), 0600); err != nil {
		return err
	}
	args := append([]string{}, aptOptions...)
	args = append(args, pinOptions...)
	args = append(args, "-o", "APT::Default-Release=")
	args = append(args, "-y", "--no-remove", "--no-upgrade", "--no-install-recommends", "-o", "Dpkg::Options::=--force-confold", "install")
	for _, packageName := range backupDependencySortedPackages(planned) {
		args = append(args, packageName+"="+planned[packageName])
	}
	if err := backupDependencyAPT(ctx, args...); err != nil {
		return err
	}
	return nil
}

// RequireSSHBackupDependencies provides a cheap, explicit local preflight for
// SSH uploads and connection tests. S3 paths must not call this function.
func RequireSSHBackupDependencies(authType string) error {
	if authType == "" {
		authType = "password"
	}
	if authType != "key" && authType != "password" {
		return errors.New("unsupported SSH authentication type")
	}
	commands := []string{"rsync", "ssh"}
	if authType == "password" {
		commands = append(commands, "sshpass")
	}
	for _, command := range commands {
		if _, err := backupDependencyLookPath(command); err != nil {
			if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("SSH backup dependency %s is missing", command)
			}
			return fmt.Errorf("SSH backup dependency %s could not be checked", command)
		}
	}
	return nil
}

type backupDependencyOutput struct {
	bytes.Buffer
	maximum   int
	truncated bool
}

func (output *backupDependencyOutput) Write(data []byte) (int, error) {
	maximum := output.maximum
	if maximum == 0 {
		maximum = 64 * 1024
	}
	written := len(data)
	if available := maximum - output.Len(); available > 0 {
		if len(data) > available {
			output.truncated = true
			data = data[:available]
		}
		_, _ = output.Buffer.Write(data)
	} else if len(data) > 0 {
		output.truncated = true
	}
	return written, nil
}

var backupDependencyPackageNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?$`)
var backupDependencyPackageVersionRE = regexp.MustCompile(`^[0-9][A-Za-z0-9.+:~\-]*$`)
var backupDependencyPlanActionRE = regexp.MustCompile(`^(Inst|Conf) ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?)(?: \[([^]]+)\])? \(([0-9][A-Za-z0-9.+:~\-]*) [^\r\n]+\)$`)
var backupDependencyPlanSummaryRE = regexp.MustCompile(`^([0-9]+) upgraded, ([0-9]+) newly installed, ([0-9]+) to remove and ([0-9]+) not upgraded\.$`)

func parseBackupDependencyInstalledPackages(output []byte) (map[string]string, error) {
	installed := map[string]string{}
	if len(output) == 0 || output[len(output)-1] != '\n' {
		return nil, errors.New("installed package inventory is incomplete")
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || !backupDependencyPackageNameRE.MatchString(fields[0]) || !backupDependencyPackageVersionRE.MatchString(fields[1]) {
			return nil, errors.New("installed package inventory is invalid")
		}
		switch fields[2] {
		case "config-files", "not-installed":
			continue
		case "installed":
			if _, duplicate := installed[fields[0]]; duplicate {
				return nil, errors.New("installed package inventory contains duplicate packages")
			}
			installed[fields[0]] = fields[1]
		default:
			return nil, errors.New("existing packages require repair before backup dependency installation")
		}
	}
	if len(installed) == 0 {
		return nil, errors.New("installed package inventory is empty")
	}
	return installed, nil
}

func backupDependencyPackageIsInstalled(installed map[string]string, name string) bool {
	base, _, _ := strings.Cut(name, ":")
	for packageName := range installed {
		installedBase, _, _ := strings.Cut(packageName, ":")
		if base == installedBase {
			return true
		}
	}
	return false
}

func parseBackupDependencyPackagePlan(output []byte, installed map[string]string, requested []string) (map[string]string, error) {
	reject := func(reason string) (map[string]string, error) {
		return nil, errors.New(reason)
	}
	fail := func() (map[string]string, error) {
		return reject("package plan contains unrecognized output or is incomplete")
	}
	if len(output) == 0 || output[len(output)-1] != '\n' {
		return fail()
	}
	planned, configured := map[string]string{}, map[string]string{}
	summarySeen, expectedNew, listAllowed := false, 0, false
	autoremoveSeen, autoremoveList, autoremoveCount := false, false, 0
	autoremoveSingular := false
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		if line == "" {
			continue
		}
		// This is advice, not a requested removal. Accept only the complete
		// apt-get stanza; actual Remv/Purg actions remain forbidden below.
		if autoremoveList {
			if strings.HasPrefix(line, "  ") {
				for _, name := range strings.Fields(line) {
					if !backupDependencyPackageNameRE.MatchString(name) {
						return fail()
					}
					autoremoveCount++
				}
				continue
			}
			if (autoremoveSingular && autoremoveCount == 1 && line == "Use 'apt autoremove' to remove it.") ||
				(!autoremoveSingular && autoremoveCount > 1 && line == "Use 'apt autoremove' to remove them.") {
				autoremoveList = false
				continue
			}
			return fail()
		}
		if strings.HasPrefix(line, "Remv ") || strings.HasPrefix(line, "Purg ") {
			return reject("package plan would remove installed software")
		}
		if action := backupDependencyPlanActionRE.FindStringSubmatch(line); action != nil {
			listAllowed = false
			name, previous, version := action[2], action[3], action[4]
			if previous != "" || backupDependencyPackageIsInstalled(installed, name) {
				return reject("package plan would modify installed software: " + name)
			}
			destination := planned
			if action[1] == "Conf" {
				destination = configured
			}
			if _, duplicate := destination[name]; duplicate {
				return fail()
			}
			destination[name] = version
			continue
		}
		if summary := backupDependencyPlanSummaryRE.FindStringSubmatch(line); summary != nil {
			if summarySeen {
				return fail()
			}
			if summary[1] != "0" || summary[3] != "0" {
				return reject("package plan includes upgrades or removals")
			}
			expectedNew, _ = strconv.Atoi(summary[2])
			summarySeen, listAllowed = true, false
			continue
		}
		switch line {
		case "The following packages were automatically installed and are no longer required:", "The following package was automatically installed and is no longer required:":
			if autoremoveSeen || summarySeen {
				return fail()
			}
			autoremoveSeen, autoremoveList, listAllowed = true, true, false
			autoremoveSingular = line == "The following package was automatically installed and is no longer required:"
			continue
		case "Reading package lists...", "Building dependency tree...", "Reading state information...":
			listAllowed = false
			continue
		case "The following additional packages will be installed:", "The following NEW packages will be installed:", "Suggested packages:", "Recommended packages:", "The following packages have been kept back:":
			listAllowed = true
			continue
		}
		if listAllowed && strings.HasPrefix(line, "  ") {
			for _, name := range strings.Fields(line) {
				if !backupDependencyPackageNameRE.MatchString(name) {
					return fail()
				}
			}
			continue
		}
		return fail()
	}
	if autoremoveList || !summarySeen || expectedNew == 0 || expectedNew != len(planned) || len(configured) != len(planned) {
		return fail()
	}
	for name, version := range planned {
		if configured[name] != version {
			return fail()
		}
	}
	for _, name := range requested {
		if _, found := planned[name]; !found {
			return fail()
		}
	}
	return planned, nil
}

func backupDependencySortedPackages(packages map[string]string) []string {
	names := make([]string, 0, len(packages))
	for name := range packages {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func backupDependencyVersionPreferences(installed, planned map[string]string) string {
	var preferences strings.Builder
	for _, packages := range []map[string]string{installed, planned} {
		for _, name := range backupDependencySortedPackages(packages) {
			// Stay below 1000 so an external package update cannot make these
			// pins automatically downgrade a newer installed version. Deny
			// all other versions explicitly, including foreign architectures.
			fmt.Fprintf(&preferences, "Package: %s\nPin: version %s\nPin-Priority: 999\n\n", name, packages[name])
			fmt.Fprintf(&preferences, "Package: %s\nPin: version *\nPin-Priority: -1\n\n", name)
		}
	}
	preferences.WriteString("Package: *\nPin: release *\nPin-Priority: -1\n")
	return preferences.String()
}

func backupDependencyPlanningPreferences(installed map[string]string) string {
	// Freeze installed packages without changing policy for new dependencies.
	// The administrator's main/fragment preferences are appended in their
	// original order, and the simulation retains APT::Default-Release.
	preferences := backupDependencyVersionPreferences(installed, nil)
	return strings.TrimSuffix(preferences, "Package: *\nPin: release *\nPin-Priority: -1\n")
}

func runBackupDependencyReadCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
	configureBackupCommandCancellation(cmd)
	output := backupDependencyOutput{maximum: 2 * 1024 * 1024}
	var stderr backupDependencyOutput
	cmd.Stdout, cmd.Stderr = &output, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("package preflight interrupted: %w", ctx.Err())
		}
		return nil, backupDependencyPreflightError(err, output.String(), stderr.String(), output.truncated || stderr.truncated)
	}
	if output.truncated || stderr.truncated || strings.TrimSpace(stderr.String()) != "" {
		return nil, backupDependencyPreflightError(nil, output.String(), stderr.String(), output.truncated || stderr.truncated)
	}
	return output.Bytes(), nil
}

func backupDependencyPreflightError(cause error, stdout, stderr string, truncated bool) error {
	// Keep APT's dependency-conflict diagnostics useful in operation logs while
	// bounding output and redacting credentials in private repository URLs.
	detail := systemPackageUpdateErrorDetail(errors.New(strings.TrimSpace(stderr + "\n" + stdout)))
	if truncated {
		return fmt.Errorf("package preflight output is incomplete: %s", detail)
	}
	if cause != nil {
		return fmt.Errorf("package preflight failed: %w: %s", cause, detail)
	}
	return fmt.Errorf("package preflight contains diagnostics: %s", detail)
}

func runBackupDependencyAPT(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "apt-get", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	configureBackupCommandCancellation(cmd)
	var output backupDependencyOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("backup dependency installation interrupted: %w", ctx.Err())
		}
		detail := systemPackageUpdateErrorDetail(errors.New(strings.TrimSpace(output.String())))
		return fmt.Errorf("backup dependency APT operation failed: %w: %s", err, detail)
	}
	return nil
}
