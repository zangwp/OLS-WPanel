package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPTPreferencePathsAreDataAndNeverShellCommands(t *testing.T) {
	base := filepath.ToSlash(t.TempDir())
	valid := "MAIN='" + base + "/preferences'\nPARTS='" + base + "/preferences.d/'\n"
	main, parts, err := parseBackupDependencyPreferencePaths([]byte(valid))
	if err != nil || main != filepath.FromSlash(base+"/preferences") || parts != filepath.FromSlash(base+"/preferences.d") {
		t.Fatalf("normalized apt-config file/directory paths rejected: %q, %q, %v", main, parts, err)
	}
	for _, output := range []string{
		"", strings.TrimSuffix(valid, "\n"), valid + "EXTRA='/tmp/other'\n",
		valid + "MAIN='/tmp/duplicate'\n", strings.Replace(valid, "MAIN='", "MAIN=$(touch /tmp/unsafe); '", 1),
		strings.Replace(valid, "/preferences'\n", "/preferences'; touch /tmp/unsafe\n", 1),
		strings.Replace(valid, "/preferences'", "/quoted'\\''path'", 1),
		strings.Replace(valid, "/preferences'", "/bad\x00path'", 1),
		"MAIN='relative/preferences'\nPARTS='relative/parts'\n",
	} {
		if _, _, err := parseBackupDependencyPreferencePaths([]byte(output)); err == nil {
			t.Fatalf("unsupported apt-config assignments accepted as paths: %q", output)
		}
	}
}

func TestMissingAPTPreviewRetainsAdministratorNegativePins(t *testing.T) {
	backupDependencyInstallTestHooks(t)
	backupDependencyLookPath = backupDependencyTestLookup()
	const administratorPolicy = "Package: lsphp83-curl\nPin: version *\nPin-Priority: -1\n"
	backupDependencyPreferencesRead = func(context.Context) (string, error) { return administratorPolicy, nil }
	backupDependencyReadCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "dpkg-query" {
			return []byte("base-files\t13.8\tinstalled\nlsphp83\t8.3.35-1+trixie\tinstalled\n"), nil
		}
		for _, arg := range args {
			if strings.HasPrefix(arg, "APT::Default-Release=") {
				t.Fatal("preview cleared the administrator's default release")
			}
			if path, found := strings.CutPrefix(arg, "Dir::Etc::preferences="); found {
				content, err := os.ReadFile(path)
				if err != nil || !strings.HasSuffix(string(content), administratorPolicy) {
					t.Fatalf("administrator negative pin was discarded: %s, %v", content, err)
				}
			}
		}
		return nil, errors.New("lsphp83-curl has no installation candidate due to administrator policy")
	}
	backupDependencyAPT = func(_ context.Context, args ...string) error {
		if args[len(args)-1] != "update" {
			t.Fatal("administrator-blocked package reached installation")
		}
		return nil
	}
	if err := installMissingAPTPackages(context.Background(), []string{"lsphp83-curl"}); !errors.Is(err, ErrPackagePlanChangesInstalled) || !strings.Contains(err.Error(), "administrator policy") {
		t.Fatalf("administrator-blocked package was not stopped: %v", err)
	}
}
