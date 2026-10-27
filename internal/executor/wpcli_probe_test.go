package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testWPCLIProbe() wpCLIVersionProbe {
	return wpCLIVersionProbe{
		stat: func(path string) (os.FileInfo, error) {
			info, err := os.Lstat(path)
			if err == nil && runtime.GOOS == "windows" {
				// Windows has no POSIX write bits. Ownership/path trust is already
				// injected below; model a normal read-only-to-other-users file.
				return wpCLIProbePOSIXInfo{info}, nil
			}
			return info, err
		},
		runtime:  func() (string, error) { return "/trusted/lsphp/bin/php", nil },
		validate: func(string) error { return nil },
		run: func(context.Context, string, string) ([]byte, error) {
			return []byte("WP-CLI " + wpCLIVersion + "\n"), nil
		},
	}
}

type wpCLIProbePOSIXInfo struct{ os.FileInfo }

func (info wpCLIProbePOSIXInfo) Mode() os.FileMode { return info.FileInfo.Mode() &^ 0022 }

func writeWPCLIProbeFixture(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWPCLIProbeStatesAndIdentity(t *testing.T) {
	phar := writeWPCLIProbeFixture(t, "wp", "#!/usr/bin/env php\n<?php // PHAR fixture\n")
	probe := testWPCLIProbe()
	if version, state := probe.version(context.Background(), phar); state != "installed" || version != "WP-CLI "+wpCLIVersion {
		t.Fatalf("version=%q state=%q", version, state)
	}
	for _, test := range []struct {
		name  string
		path  string
		setup func(*wpCLIVersionProbe)
		state string
	}{
		{name: "missing PHAR", path: filepath.Join(t.TempDir(), "missing"), state: "missing"},
		{name: "directory", path: t.TempDir(), state: "error"},
		{name: "empty file", path: writeWPCLIProbeFixture(t, "empty", ""), state: "error"},
		{name: "PHP unavailable", path: phar, setup: func(p *wpCLIVersionProbe) {
			p.runtime = func() (string, error) { return "", os.ErrNotExist }
		}, state: "error"},
		{name: "untrusted PHAR", path: phar, setup: func(p *wpCLIVersionProbe) {
			p.validate = func(string) error { return errors.New("untrusted owner") }
		}, state: "error"},
		{name: "failed PHP", path: phar, setup: func(p *wpCLIVersionProbe) {
			p.run = func(context.Context, string, string) ([]byte, error) { return nil, errors.New("PHP failed") }
		}, state: "error"},
		{name: "arbitrary output", path: phar, setup: func(p *wpCLIVersionProbe) {
			p.run = func(context.Context, string, string) ([]byte, error) { return []byte("unrelated command v2.12.0"), nil }
		}, state: "error"},
		{name: "startup warning", path: phar, setup: func(p *wpCLIVersionProbe) {
			p.run = func(context.Context, string, string) ([]byte, error) {
				return []byte("PHP Warning: extension failed\nWP-CLI 2.12.0"), nil
			}
		}, state: "error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := testWPCLIProbe()
			if test.setup != nil {
				test.setup(&p)
			}
			if _, state := p.version(context.Background(), test.path); state != test.state {
				t.Fatalf("state=%q want %q", state, test.state)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, state := probe.version(ctx, phar); state != "error" {
		t.Fatalf("canceled probe state=%q", state)
	}
}

func TestWPCLIProbeRejectsWritableAndLinkedFilesBeforeExecution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX modes and symlinks")
	}
	phar := writeWPCLIProbeFixture(t, "wp", "<?php // existing PHAR\n")
	link := filepath.Join(t.TempDir(), "wp-link")
	if err := os.Symlink(phar, link); err != nil {
		t.Fatal(err)
	}
	probe := testWPCLIProbe()
	probe.run = func(context.Context, string, string) ([]byte, error) {
		t.Fatal("an untrusted file must not execute")
		return nil, nil
	}
	if _, state := probe.version(context.Background(), link); state != "error" {
		t.Fatalf("symlink state=%q", state)
	}
	if err := os.Chmod(phar, 0666); err != nil {
		t.Fatal(err)
	}
	if _, state := probe.version(context.Background(), phar); state != "error" {
		t.Fatalf("writable file state=%q", state)
	}
}

func TestWPCLIProbeUsesConfiguredPHPWithoutExecutablePHAR(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell fixture")
	}
	phar := writeWPCLIProbeFixture(t, "wp", "#!/nonexistent/system-php\n<?php // non-executable PHAR\n")
	php := writeWPCLIProbeFixture(t, "php", `#!/bin/sh
[ "$1" = "-d" ] && [ "$2" = "auto_prepend_file=" ] || exit 11
[ "$3" = "-d" ] && [ "$4" = "auto_append_file=" ] || exit 12
[ "$5" = "-d" ] && [ "$6" = "display_errors=stderr" ] || exit 13
[ -f "$7" ] && [ "$8" = "--allow-root" ] || exit 14
[ "$9" = "--skip-packages" ] && [ "${10}" = "--skip-plugins" ] || exit 15
[ "${11}" = "--skip-themes" ] && [ "${12}" = "--version" ] || exit 18
[ "$WP_CLI_CONFIG_PATH" = "/dev/null" ] && [ "$WP_CLI_PACKAGES_DIR" = "/dev/null" ] || exit 16
[ -z "$PHPRC$PHP_INI_SCAN_DIR$BASH_ENV" ] && [ "$PWD" = "/" ] || exit 17
printf 'WP-CLI 2.12.0\n'
`)
	if err := os.Chmod(php, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PHPRC", "/untrusted/php.ini")
	t.Setenv("PHP_INI_SCAN_DIR", "/untrusted/modules")
	t.Setenv("BASH_ENV", "/untrusted/environment")
	probe := testWPCLIProbe()
	probe.runtime = func() (string, error) { return php, nil }
	probe.run = runWPCLIProbe
	if version, state := probe.version(context.Background(), phar); state != "installed" || version != "WP-CLI "+wpCLIVersion {
		t.Fatalf("version=%q state=%q", version, state)
	}
	if err := os.WriteFile(php, []byte("#!/bin/sh\nprintf 'PHP Deprecated: test compatibility notice\\n' >&2\nprintf 'WP-CLI 2.12.0\\n'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if version, state := probe.version(context.Background(), phar); state != "installed" || version != "WP-CLI "+wpCLIVersion {
		t.Fatalf("nonfatal PHP deprecation changed availability: version=%q state=%q", version, state)
	}
}

func TestWPCLIProbeBoundsOutputAndHonorsCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell fixture")
	}
	phar := writeWPCLIProbeFixture(t, "wp", "<?php // PHAR fixture\n")
	for _, channel := range []string{"stdout", "stderr"} {
		t.Run(channel, func(t *testing.T) {
			redirect := ""
			if channel == "stderr" {
				redirect = " >&2"
			}
			php := writeWPCLIProbeFixture(t, "php", "#!/bin/sh\ni=0; while [ $i -lt 8192 ]; do printf 'too-much-output'"+redirect+"; i=$((i+1)); done\n")
			if err := os.Chmod(php, 0755); err != nil {
				t.Fatal(err)
			}
			if _, err := runWPCLIProbe(context.Background(), php, phar); err == nil {
				t.Fatal("oversized output must fail")
			}
		})
	}
	php := writeWPCLIProbeFixture(t, "php", "#!/bin/sh\nwhile :; do :; done\n")
	if err := os.Chmod(php, 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := runWPCLIProbe(ctx, php, phar); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled command error=%v", err)
	}
}

func TestInstallWPCLIPreservesExistingFile(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprintf("valid=%t", valid), func(t *testing.T) {
			path := writeWPCLIProbeFixture(t, "wp", "existing PHAR content")
			probe := testWPCLIProbe()
			if !valid {
				probe.run = func(context.Context, string, string) ([]byte, error) { return nil, errors.New("broken PHAR") }
			}
			err := installWPCLIAt(context.Background(), path, probe, func(context.Context, *os.File) error {
				t.Fatal("existing files must never be downloaded over")
				return nil
			})
			if (err == nil) != valid {
				t.Fatalf("install error=%v", err)
			}
			body, err := os.ReadFile(path)
			if err != nil || string(body) != "existing PHAR content" {
				t.Fatalf("existing file changed: body=%q error=%v", body, err)
			}
		})
	}
}

func TestInstallWPCLIRequiresPHPAndVerifiedVersionBeforePublication(t *testing.T) {
	for _, test := range []struct {
		name    string
		version string
		phpErr  error
		wantErr bool
	}{
		{name: "correct package", version: "WP-CLI " + wpCLIVersion},
		{name: "wrong version", version: "WP-CLI 2.11.0", wantErr: true},
		{name: "unrelated output", version: "unrelated WP-CLI " + wpCLIVersion, wantErr: true},
		{name: "missing PHP", phpErr: os.ErrNotExist, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wp")
			probe := testWPCLIProbe()
			probe.runtime = func() (string, error) { return "/trusted/php", test.phpErr }
			probe.run = func(context.Context, string, string) ([]byte, error) { return []byte(test.version), nil }
			err := installWPCLIAt(context.Background(), path, probe, func(_ context.Context, dst *os.File) error {
				if test.phpErr != nil {
					t.Fatal("must check PHP before downloading")
				}
				_, err := dst.WriteString("downloaded verified PHAR")
				return err
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("install error=%v", err)
			}
			body, readErr := os.ReadFile(path)
			if test.wantErr && !errors.Is(readErr, os.ErrNotExist) {
				t.Fatalf("failed package was published: %q, %v", body, readErr)
			}
			if !test.wantErr && (readErr != nil || string(body) != "downloaded verified PHAR") {
				t.Fatalf("published package=%q error=%v", body, readErr)
			}
			staging, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".wp-cli-*"))
			if len(staging) != 0 {
				t.Fatalf("temporary downloads leaked: %v", staging)
			}
		})
	}
}

func TestInstallWPCLIPreservesFileCreatedDuringDownload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wp")
	err := installWPCLIAt(context.Background(), path, testWPCLIProbe(), func(_ context.Context, dst *os.File) error {
		if _, err := dst.WriteString("new verified PHAR"); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("concurrent installation"), 0644)
	})
	if err == nil {
		t.Fatal("publishing over a concurrent installation must fail")
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil || strings.TrimSpace(string(body)) != "concurrent installation" {
		t.Fatalf("concurrent file changed: body=%q error=%v", body, readErr)
	}
}
