package executor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const wpCLIProbeTimeout = 5 * time.Second

var wpCLIProbeVersionPattern = regexp.MustCompile(`^WP-CLI [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)

type wpCLIVersionProbe struct {
	stat     func(string) (os.FileInfo, error)
	runtime  func() (string, error)
	validate func(string) error
	run      func(context.Context, string, string) ([]byte, error)
}

func defaultWPCLIProbe() wpCLIVersionProbe {
	return wpCLIVersionProbe{
		stat: os.Lstat,
		runtime: func() (string, error) {
			php := LSPHPBinaryPath()
			if !lsphpHealthTrustedPath(php, filepath.Dir(php), "executable", fileOwnerIDs) {
				return "", errors.New("configured PHP CLI is missing or untrusted")
			}
			return filepath.EvalSymlinks(php)
		},
		validate: func(path string) error {
			if !lsphpHealthTrustedPath(path, filepath.VolumeName(path)+string(filepath.Separator), "file", fileOwnerIDs) {
				return errors.New("WP-CLI file or parent directory is untrusted")
			}
			return nil
		},
		run: runWPCLIProbe,
	}
}

func (probe wpCLIVersionProbe) version(ctx context.Context, path string) (string, string) {
	info, err := probe.stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", "missing"
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || info.Size() <= 0 || info.Size() > wpCLIMaxDownload || !filepath.IsAbs(path) {
		return "", "error"
	}
	if err := probe.validate(path); err != nil {
		return "", "error"
	}
	php, err := probe.runtime()
	if err != nil {
		return "", "error"
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, wpCLIProbeTimeout)
	defer cancel()
	output, err := probe.run(ctx, php, path)
	version := strings.TrimSpace(string(output))
	if err != nil || ctx.Err() != nil || !wpCLIProbeVersionPattern.MatchString(version) {
		return "", "error"
	}
	return version, "installed"
}

func runWPCLIProbe(ctx context.Context, php, phar string) ([]byte, error) {
	// The PHAR's /usr/bin/env php shebang is unsuitable for an OLS-only host.
	// Use the trusted CLI explicitly and avoid loading per-directory WP-CLI
	// configuration, third-party packages, plugins or themes as root.
	cmd := exec.CommandContext(ctx, php, "-d", "auto_prepend_file=", "-d", "auto_append_file=", "-d", "display_errors=stderr", phar,
		"--allow-root", "--skip-packages", "--skip-plugins", "--skip-themes", "--version")
	cmd.Dir = string(filepath.Separator)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "WP_CLI_CONFIG_PATH=/dev/null", "WP_CLI_PACKAGES_DIR=/dev/null"}
	cmd.WaitDelay = time.Second
	stdout := &lsphpHealthBoundedWriter{limit: 16 * 1024}
	stderr := &lsphpHealthBoundedWriter{limit: 4 * 1024}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	// Nonfatal PHP deprecations may accompany a valid version, particularly on
	// a newer PHP branch. Exit status and the exact stdout version establish
	// availability; stderr remains bounded without turning warnings into failure.
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}
