package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Exercise the real APT solver entirely in a private fixture. The only update
// reads a file:// repository; every install command is a simulation. All APT
// state, caches, sources, preferences, hooks and logs are redirected so this
// test never changes host packages or uses the host's repository configuration.
func TestMissingAPTNativeSolverPreservesInstalledRuntime(t *testing.T) {
	apt, err := exec.LookPath("apt-get")
	if err != nil {
		t.Skip("native APT is unavailable")
	}
	currentUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, directory := range []string{"repo", "state/lists/partial", "cache/archives/partial", "etc/apt.conf.d", "etc/sources.list.d", "etc/preferences.d", "etc/trusted.gpg.d", "log"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	const oldVersion = "8.3.35-1+fixture"
	const newVersion = "8.3.36-1+fixture"
	arch := runtime.GOARCH
	status := func(name, version, dependency string) string {
		dependencyField := ""
		if dependency != "" {
			dependencyField = "Depends: " + dependency + "\n"
		}
		return fmt.Sprintf("Package: %s\nStatus: install ok installed\nPriority: optional\nSection: php\nArchitecture: %s\nVersion: %s\nMaintainer: Fixture <fixture@example.invalid>\n%sDescription: private APT test fixture\n\n", name, arch, version, dependencyField)
	}
	installedStatus := status("lsphp83", oldVersion, "lsphp83-common") + status("lsphp83-common", oldVersion, "") + status("lsphp83-oldhelper", "1.0-1", "")
	write("state/status", installedStatus)
	write("state/extended_states", "Package: lsphp83-oldhelper\nArchitecture: "+arch+"\nAuto-Installed: 1\n\n")
	packageRecord := func(name, version, dependency string) string {
		dependencyField := ""
		if dependency != "" {
			dependencyField = "Depends: " + dependency + "\n"
		}
		return fmt.Sprintf("Package: %s\nSource: php8.3\nVersion: %s\nArchitecture: %s\nMaintainer: Fixture <fixture@example.invalid>\n%sFilename: pool/%s_%s_%s.deb\nSize: 1\nSHA256: %s\nDescription: private APT test fixture\n\n", name, version, arch, dependencyField, name, version, arch, strings.Repeat("0", 64))
	}
	write("repo/Packages", packageRecord("lsphp83-common", oldVersion, "")+
		packageRecord("lsphp83-common", newVersion, "")+
		packageRecord("lsphp83-curl", oldVersion, "lsphp83-common (>= "+oldVersion+")")+
		packageRecord("lsphp83-opcache", newVersion, "lsphp83-common")+
		packageRecord("lsphp83-intl", newVersion, "lsphp83-common (>= "+newVersion+")"))
	repositoryURL := (&url.URL{Scheme: "file", Path: filepath.Join(root, "repo")}).String()
	write("etc/sources.list", "deb [trusted=yes] "+repositoryURL+" ./\n")
	write("etc/preferences", "")
	var configuration strings.Builder
	for _, setting := range [][2]string{
		{"Dir", root},
		{"Dir::State", filepath.Join(root, "state")},
		{"Dir::State::status", filepath.Join(root, "state/status")},
		{"Dir::State::extended_states", filepath.Join(root, "state/extended_states")},
		{"Dir::State::lists", filepath.Join(root, "state/lists")},
		{"Dir::Cache", filepath.Join(root, "cache")},
		{"Dir::Cache::archives", filepath.Join(root, "cache/archives")},
		{"Dir::Cache::pkgcache", ""}, {"Dir::Cache::srcpkgcache", ""},
		{"Dir::Etc", filepath.Join(root, "etc")},
		{"Dir::Etc::main", filepath.Join(root, "etc/apt.conf")},
		{"Dir::Etc::parts", filepath.Join(root, "etc/apt.conf.d")},
		{"Dir::Etc::sourcelist", filepath.Join(root, "etc/sources.list")},
		{"Dir::Etc::sourceparts", filepath.Join(root, "etc/sources.list.d")},
		{"Dir::Etc::preferences", filepath.Join(root, "etc/preferences")},
		{"Dir::Etc::preferencesparts", filepath.Join(root, "etc/preferences.d")},
		{"Dir::Etc::trusted", filepath.Join(root, "etc/trusted.gpg")},
		{"Dir::Etc::trustedparts", filepath.Join(root, "etc/trusted.gpg.d")},
		{"Dir::Log", filepath.Join(root, "log")},
		{"APT::Architecture", arch},
		{"APT::Sandbox::User", currentUser.Username},
		{"APT::Get::Show-User-Simulation-Note", "false"},
		{"Acquire::Languages", "none"},
	} {
		fmt.Fprintf(&configuration, "%s %s;\n", setting[0], strconv.Quote(setting[1]))
	}
	write("etc/apt.conf", configuration.String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	runProgram := func(program string, args ...string) ([]byte, []byte, error) {
		t.Helper()
		command := exec.CommandContext(ctx, program, args...)
		command.Env = append(os.Environ(), "APT_CONFIG="+filepath.Join(root, "etc/apt.conf"), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		return stdout.Bytes(), stderr.Bytes(), err
	}
	run := func(args ...string) ([]byte, []byte, error) { return runProgram(apt, args...) }
	fixturePreferences := func() string {
		t.Helper()
		snapshot, err := backupDependencyPreferenceSnapshot(ctx, func(_ context.Context, name string, args ...string) ([]byte, error) {
			stdout, stderr, err := runProgram(name, args...)
			if err != nil || len(bytes.TrimSpace(stderr)) != 0 {
				return nil, fmt.Errorf("fixture apt-config: %v: %s", err, stderr)
			}
			return stdout, nil
		}, fileOwnerIDs, os.Getuid(), root)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	installed := map[string]string{"lsphp83": oldVersion, "lsphp83-common": oldVersion, "lsphp83-oldhelper": "1.0-1"}
	previewPath := filepath.Join(root, "cache/preview.preferences")
	write("cache/preview.preferences", backupDependencyPlanningPreferences(installed)+fixturePreferences())
	if stdout, stderr, err := run("update"); err != nil {
		t.Fatalf("private file-repository update: %v\n%s\n%s", err, stdout, stderr)
	}
	arguments := []string{"-o", "Dir::Etc::preferences=" + previewPath, "-o", "Dir::Etc::preferencesparts=/dev/null", "--simulate", "--no-remove", "--no-upgrade", "--no-install-recommends", "install", "lsphp83-curl"}
	stdout, stderr, err := run(arguments...)
	if err != nil || len(bytes.TrimSpace(stderr)) != 0 {
		t.Fatalf("compatible extension simulation: %v\n%s\n%s", err, stdout, stderr)
	}
	planned, err := parseBackupDependencyPackagePlan(stdout, installed, []string{"lsphp83-curl"})
	if err != nil || len(planned) != 1 || planned["lsphp83-curl"] != oldVersion {
		t.Fatalf("real new-only extension plan rejected: %v, %v\n%s", planned, err, stdout)
	}
	if err := validateLSPHPPackageVersions(installed, planned, []string{"lsphp83-curl"}); err != nil {
		t.Fatalf("coherent extension/runtime build rejected: %v", err)
	}
	if !bytes.Contains(stdout, []byte("automatically installed and are no longer required")) &&
		!bytes.Contains(stdout, []byte("automatically installed and is no longer required")) {
		t.Fatalf("native fixture did not reproduce the autoremove advice: %s", stdout)
	}
	// The final, stricter preferences must still solve exactly the validated
	// package, with the existing PHP packages excluded from the transaction.
	write("cache/preview.preferences", backupDependencyVersionPreferences(installed, planned))
	arguments[len(arguments)-1] = "lsphp83-curl=" + oldVersion
	stdout, stderr, err = run(arguments...)
	if err != nil || len(bytes.TrimSpace(stderr)) != 0 {
		t.Fatalf("frozen execution plan no longer solves: %v\n%s\n%s", err, stdout, stderr)
	}
	if _, err := parseBackupDependencyPackagePlan(stdout, installed, []string{"lsphp83-curl"}); err != nil {
		t.Fatalf("frozen execution changed installed software: %v\n%s", err, stdout)
	}
	write("cache/preview.preferences", backupDependencyPlanningPreferences(installed)+fixturePreferences())
	// Reproduce the real vendor metadata gap: unversioned common lets APT
	// accept new OPcache with the old engine, although the module requires a
	// Zend symbol introduced by the newer PHP patch. The panel must reject it.
	arguments[len(arguments)-1] = "lsphp83-opcache"
	stdout, stderr, err = run(arguments...)
	if err != nil || len(bytes.TrimSpace(stderr)) != 0 {
		t.Fatalf("fixture did not reproduce the loose vendor dependency: %v\n%s\n%s", err, stdout, stderr)
	}
	unsafePlan, err := parseBackupDependencyPackagePlan(stdout, installed, []string{"lsphp83-opcache"})
	if err != nil || unsafePlan["lsphp83-opcache"] != newVersion {
		t.Fatalf("expected new-only OPcache plan was not produced: %v, %v\n%s", unsafePlan, err, stdout)
	}
	if err := validateLSPHPPackageVersions(installed, unsafePlan, []string{"lsphp83-opcache"}); !errors.Is(err, ErrLSPHPPackageVersionMismatch) {
		t.Fatalf("real APT plan bypassed the PHP patch compatibility guard: %v", err)
	}
	arguments[len(arguments)-1] = "lsphp83-intl"
	if stdout, stderr, err := run(arguments...); err == nil {
		t.Fatalf("extension requiring an installed-runtime upgrade was accepted:\n%s\n%s", stdout, stderr)
	}
	// Preserve both the configured main file and sorted fragments. Their
	// negative pins must still prohibit a new extension in the private preview.
	for _, location := range []string{"etc/preferences", "etc/preferences.d/40-deny.pref"} {
		write("etc/preferences", "")
		write("etc/preferences.d/40-deny.pref", "")
		write(location, "Package: lsphp83-curl\nPin: version *\nPin-Priority: -1\n")
		write("cache/preview.preferences", backupDependencyPlanningPreferences(installed)+fixturePreferences())
		arguments[len(arguments)-1] = "lsphp83-curl"
		if stdout, stderr, err := run(arguments...); err == nil {
			t.Fatalf("administrator negative pin in %s was bypassed:\n%s\n%s", location, stdout, stderr)
		}
	}
	if actual, err := os.ReadFile(filepath.Join(root, "state/status")); err != nil || string(actual) != installedStatus {
		t.Fatalf("APT simulations changed the private installed inventory: %v", err)
	}
}

func TestAPTPreferenceSnapshotPreservesOrderAndRejectsUntrustedFiles(t *testing.T) {
	root := t.TempDir()
	main, parts := filepath.Join(root, "preferences"), filepath.Join(root, "preferences.d")
	if err := os.Mkdir(parts, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	const mainPolicy = "Package: lsphp83-curl\nPin: version *\nPin-Priority: -1\n"
	const firstPolicy = "Package: lsphp83-intl\nPin: version *\nPin-Priority: -1\n"
	const secondPolicy = "Package: lsphp83-imagick\nPin: version *\nPin-Priority: -1\n"
	write(main, mainPolicy)
	first := filepath.Join(parts, "10-first.pref")
	write(first, firstPolicy)
	write(filepath.Join(parts, "20-second"), secondPolicy)
	write(filepath.Join(parts, "30-ignored.save"), "Package: ignored-backup\nPin: version *\nPin-Priority: 999\n")
	readPaths := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "apt-config" || strings.Join(args, " ") != "shell MAIN Dir::Etc::preferences/f PARTS Dir::Etc::preferencesparts/d" {
			t.Fatalf("unexpected configuration probe: %s %v", name, args)
		}
		return []byte("MAIN='" + main + "'\nPARTS='" + parts + "/'\n"), nil
	}
	snapshot := func() (string, error) {
		return backupDependencyPreferenceSnapshot(context.Background(), readPaths, fileOwnerIDs, os.Getuid(), root)
	}
	actual, err := snapshot()
	if err != nil || actual != mainPolicy+"\n\n"+firstPolicy+"\n\n"+secondPolicy+"\n\n" {
		t.Fatalf("main and sorted fragment policy changed order or loaded an ignored backup: %q, %v", actual, err)
	}
	link := filepath.Join(parts, "40-linked.pref")
	if err := os.Symlink(main, link); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot(); err == nil {
		t.Fatal("symlinked preference fragment was accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(first, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot(); err == nil {
		t.Fatal("writable preference fragment was accepted")
	}
	if err := os.Chmod(first, 0644); err != nil {
		t.Fatal(err)
	}
	write(main, strings.Repeat("x", backupDependencyPreferenceLimit+1))
	if _, err := snapshot(); err == nil {
		t.Fatal("oversized preference file was accepted")
	}
	write(main, mainPolicy)
	wrongOwner := func(info os.FileInfo) (int, int, error) {
		uid, gid, err := fileOwnerIDs(info)
		return uid + 1, gid, err
	}
	if _, err := backupDependencyPreferenceSnapshot(context.Background(), readPaths, wrongOwner, os.Getuid(), root); err == nil {
		t.Fatal("untrusted preference file owner was accepted")
	}
}
