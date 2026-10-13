package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	lsphpHealthTimeout     = 4 * time.Second
	lsphpHealthOutputLimit = 512 * 1024
)

// LSPHPExtensionHealth reports a module loaded by a fresh LSAPI invocation
// using the runtime's server configuration. It is not a per-site worker probe.
type LSPHPExtensionHealth struct {
	Name       string `json:"name"`
	Importance string `json:"importance"`
	State      string `json:"state"`
}

// LSPHPOPCacheHealth deliberately contains configuration only. A command-line
// invocation cannot observe the cache instance used by existing web workers.
type LSPHPOPCacheHealth struct {
	ConfigurationState string `json:"configuration_state"`
	Enabled            *bool  `json:"enabled"`
	MemoryMB           *int   `json:"memory_mb"`
	MaxFiles           *int   `json:"max_files"`
	MetricsState       string `json:"metrics_state"`
	MetricsReason      string `json:"metrics_reason"`
}

type LSPHPRuntimeHealth struct {
	Version            string                 `json:"version"`
	State              string                 `json:"state"`
	Reason             string                 `json:"reason,omitempty"`
	Extensions         []LSPHPExtensionHealth `json:"extensions"`
	MissingRequired    int                    `json:"missing_required"`
	MissingRecommended int                    `json:"missing_recommended"`
	OPcache            LSPHPOPCacheHealth     `json:"opcache"`
}

// This list follows the WordPress Hosting Handbook's required and highly
// recommended modules. Redis and OPcache match the panel's cache baseline.
// https://make.wordpress.org/hosting/handbook/server-environment/#php-extensions
var lsphpHealthExtensions = []LSPHPExtensionHealth{
	{Name: "json", Importance: "required"},
	{Name: "hash", Importance: "required"},
	{Name: "mysqli", Importance: "required"},
	{Name: "curl", Importance: "recommended"},
	{Name: "dom", Importance: "recommended"},
	{Name: "exif", Importance: "recommended"},
	{Name: "fileinfo", Importance: "recommended"},
	{Name: "igbinary", Importance: "recommended"},
	{Name: "imagick", Importance: "recommended"},
	{Name: "intl", Importance: "recommended"},
	{Name: "mbstring", Importance: "recommended"},
	{Name: "openssl", Importance: "recommended"},
	{Name: "xml", Importance: "recommended"},
	{Name: "zip", Importance: "recommended"},
	{Name: "redis", Importance: "recommended"},
	{Name: "opcache", Importance: "recommended"},
}

func newLSPHPRuntimeHealth(version string) LSPHPRuntimeHealth {
	health := LSPHPRuntimeHealth{
		Version: version, State: "unknown",
		Extensions: append([]LSPHPExtensionHealth(nil), lsphpHealthExtensions...),
		OPcache: LSPHPOPCacheHealth{
			ConfigurationState: "unknown", MetricsState: "unavailable",
			MetricsReason: "web_worker_probe_unavailable",
		},
	}
	for i := range health.Extensions {
		health.Extensions[i].State = "unknown"
	}
	return health
}

// ReadLSPHPRuntimeHealth performs a bounded read-only check. Unsupported or
// untrusted installations and failed checks retain unknown extension states.
func ReadLSPHPRuntimeHealth(ctx context.Context, runtime LSPHPRuntime) LSPHPRuntimeHealth {
	return ReadLSPHPRuntimeHealthWithProbe(ctx, runtime, boundedLSPHPHealthRead)
}

// ReadLSPHPRuntimeHealthWithProbe lets the software handler coalesce/cache the
// raw command result. The probe must enforce its own output bound while reading;
// oversized results are also rejected here before parsing. Trust checks always
// run before the supplied probe, including on cache hits.
func ReadLSPHPRuntimeHealthWithProbe(ctx context.Context, runtime LSPHPRuntime, probe func(context.Context, string, ...string) ([]byte, error)) LSPHPRuntimeHealth {
	return readLSPHPRuntimeHealth(ctx, runtime, probe, validateLSPHPHealthRuntime)
}

func readLSPHPRuntimeHealth(ctx context.Context, runtime LSPHPRuntime, probe func(context.Context, string, ...string) ([]byte, error), validate func(LSPHPRuntime) (string, string, string)) LSPHPRuntimeHealth {
	health := newLSPHPRuntimeHealth(runtime.Version)
	if runtime.Version == "" {
		health.Reason = "unsupported_runtime"
		return health
	}
	if version, err := normalizeLSPHPVersion(runtime.Version); err != nil || version != runtime.Version {
		health.Reason = "unsupported_runtime"
		return health
	}
	if !runtime.Installed {
		health.State, health.Reason = "not_installed", "not_installed"
		return health
	}
	if ctx.Err() != nil {
		health.Reason = lsphpHealthProbeErrorReason(ctx.Err())
		return health
	}
	iniPath, scanDir, reason := validate(runtime)
	if reason != "" {
		health.Reason = reason
		return health
	}
	if probe == nil {
		probe = boundedLSPHPHealthRead
	}
	ctx, cancel := context.WithTimeout(ctx, lsphpHealthTimeout)
	defer cancel()
	// LSAPI's own CLI supports -i and -c, but not PHP CLI's -r, -m or -d.
	// -i does not execute a PHP script (including auto_prepend/auto_append).
	// A cleared environment prevents inherited PHPRC/LSPHPRC, scan directories,
	// loader variables or LSAPI socket settings from changing this invocation.
	output, err := probe(ctx, "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "PHP_INI_SCAN_DIR="+scanDir,
		runtime.LSAPIBinary, "-c", iniPath, "-i")
	if err != nil || ctx.Err() != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		health.Reason = lsphpHealthProbeErrorReason(err)
		return health
	}
	return parseLSPHPHealthOutput(runtime.Version, iniPath, scanDir, output)
}

func validateLSPHPHealthRuntime(runtime LSPHPRuntime) (string, string, string) {
	known, err := ResolveLSPHPRuntime(runtime.Version, true)
	if err != nil || known.LSAPIBinary != runtime.LSAPIBinary || !trustedLSPHPExecutable(runtime.LSAPIBinary) {
		return "", "", "untrusted_runtime"
	}
	suffix := strings.ReplaceAll(runtime.Version, ".", "")
	root := filepath.Join("/usr/local/lsws", "lsphp"+suffix)
	if !lsphpHealthTrustedPath(runtime.LSAPIBinary, root, "executable", fileOwnerIDs) ||
		!lsphpHealthTrustedPath("/usr/bin/env", string(filepath.Separator), "executable", fileOwnerIDs) {
		return "", "", "untrusted_runtime"
	}
	iniPath := filepath.Join(root, "etc", "php", runtime.Version, "litespeed", "php.ini")
	scanDir := filepath.Join(root, "etc", "php", runtime.Version, "mods-available")
	if !lsphpHealthTrustedPath(iniPath, root, "file", fileOwnerIDs) ||
		!lsphpHealthTrustedPath(scanDir, root, "directory", fileOwnerIDs) {
		return "", "", "configuration_unavailable"
	}
	entries, err := os.ReadDir(scanDir)
	if err != nil {
		return "", "", "configuration_unavailable"
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".ini") && !lsphpHealthTrustedPath(filepath.Join(scanDir, entry.Name()), root, "file", fileOwnerIDs) {
			return "", "", "configuration_unavailable"
		}
	}
	return iniPath, scanDir, ""
}

// Validate both the supplied pathname's ancestor chain and its canonical
// target. Root-owned package symlinks are allowed; a writable ancestor or an
// escape from this PHP branch is not. Ownership is mandatory on Linux.
func lsphpHealthTrustedPath(path, scope, kind string, owner func(os.FileInfo) (int, int, error)) bool {
	path, scope = filepath.Clean(path), filepath.Clean(scope)
	if !filepath.IsAbs(path) || !filepath.IsAbs(scope) || !lsphpHealthPathWithin(path, scope) {
		return false
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || !lsphpHealthPathWithin(real, scope) {
		return false
	}
	for _, candidate := range []string{path, real} {
		for current := candidate; ; current = filepath.Dir(current) {
			info, err := os.Lstat(current)
			if err != nil {
				return false
			}
			uid, _, ownerErr := owner(info)
			checkKind := "directory"
			if current == candidate {
				checkKind = kind
			}
			if !lsphpHealthSafeInfo(info, checkKind, uid, ownerErr) {
				return false
			}
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
		}
	}
	return true
}

func lsphpHealthPathWithin(path, scope string) bool {
	relative, err := filepath.Rel(scope, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func lsphpHealthSafeInfo(info os.FileInfo, kind string, uid int, ownerErr error) bool {
	if info == nil || ownerErr != nil || uid != 0 {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true // Parent and canonical target receive their own checks.
	}
	if info.Mode().Perm()&0022 != 0 {
		return false
	}
	switch kind {
	case "directory":
		return info.IsDir()
	case "executable":
		return info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
	default:
		return info.Mode().IsRegular()
	}
}

func parseLSPHPHealthOutput(version, iniPath, scanDir string, output []byte) LSPHPRuntimeHealth {
	health := newLSPHPRuntimeHealth(version)
	health.Reason = "invalid_output"
	if len(output) == 0 || len(output) > lsphpHealthOutputLimit || bytes.IndexByte(output, 0) >= 0 {
		return health
	}
	text := strings.ReplaceAll(string(output), "\r\n", "\n")
	if !strings.HasPrefix(strings.TrimSpace(text), "phpinfo()\n") || !strings.Contains(text, "\nPHP License\n") {
		return health
	}
	// PHP can return zero even when an extension failed during startup. Such a
	// result is not sufficient evidence that the remaining modules are missing.
	for _, marker := range []string{"PHP Warning:", "PHP Fatal error:", "PHP Parse error:", "Unable to load dynamic library", "Startup Failed =>"} {
		if strings.Contains(text, marker) {
			health.Reason = "probe_failed"
			return health
		}
	}
	values := make(map[string][]string)
	loaded := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.Split(line, " => ")
		if len(parts) >= 2 {
			if _, duplicate := values[parts[0]]; !duplicate {
				values[parts[0]] = parts[1:]
			}
			continue
		}
		name := strings.ToLower(line)
		if name == "zend opcache" {
			name = "opcache"
		}
		loaded[name] = true
	}
	value := func(key string) string {
		if parts := values[key]; len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
		return ""
	}
	if !strings.HasPrefix(value("PHP Version"), version+".") || !strings.HasPrefix(value("Server API"), "LiteSpeed") {
		health.Reason = "runtime_mismatch"
		return health
	}
	if filepath.Clean(value("Loaded Configuration File")) != filepath.Clean(iniPath) ||
		filepath.Clean(value("Scan this dir for additional .ini files")) != filepath.Clean(scanDir) {
		health.Reason = "configuration_mismatch"
		return health
	}
	// Modules must appear in phpinfo's module section, rather than in a
	// Configure Command or an ini directive naming an unloaded extension.
	moduleStart := strings.Index(text, "\nConfiguration\n")
	moduleEnd := strings.Index(text, "\nPHP Variables\n")
	if moduleStart < 0 || moduleEnd <= moduleStart || !loaded["core"] || !loaded["standard"] {
		return health
	}
	loaded = make(map[string]bool)
	for _, line := range strings.Split(text[moduleStart:moduleEnd], "\n") {
		name := strings.ToLower(strings.TrimSpace(line))
		if name == "zend opcache" {
			name = "opcache"
		}
		loaded[name] = true
	}
	health.State, health.Reason = "ok", ""
	for i := range health.Extensions {
		extension := &health.Extensions[i]
		extension.State = "loaded"
		if !loaded[extension.Name] {
			extension.State = "missing"
			if extension.Importance == "required" {
				health.MissingRequired++
			} else {
				health.MissingRecommended++
			}
		}
	}
	if health.MissingRequired+health.MissingRecommended > 0 {
		health.State, health.Reason = "warning", "extensions_missing"
	}
	if loaded["opcache"] {
		health.OPcache.Enabled = lsphpHealthBool(value("opcache.enable"))
		health.OPcache.MemoryMB = lsphpHealthNonnegativeInt(value("opcache.memory_consumption"))
		health.OPcache.MaxFiles = lsphpHealthNonnegativeInt(value("opcache.max_accelerated_files"))
		if health.OPcache.Enabled != nil && health.OPcache.MemoryMB != nil && health.OPcache.MaxFiles != nil {
			health.OPcache.ConfigurationState = "known"
		}
		if health.OPcache.Enabled != nil && !*health.OPcache.Enabled && health.State == "ok" {
			health.State, health.Reason = "warning", "opcache_disabled"
		}
	}
	return health
}

func lsphpHealthBool(value string) *bool {
	var result bool
	switch strings.ToLower(value) {
	case "1", "on", "true", "yes":
		result = true
	case "0", "off", "false", "no":
		result = false
	default:
		return nil
	}
	return &result
}

func lsphpHealthNonnegativeInt(value string) *int {
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed < 0 {
		return nil
	}
	result := int(parsed)
	return &result
}

func lsphpHealthProbeErrorReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "probe_timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "probe_canceled"
	}
	return "probe_failed"
}

type lsphpHealthBoundedWriter struct {
	buffer bytes.Buffer
	limit  int
}

func (writer *lsphpHealthBoundedWriter) Write(data []byte) (int, error) {
	if len(data) > writer.limit-writer.buffer.Len() {
		return 0, errors.New("PHP health probe output limit exceeded")
	}
	return writer.buffer.Write(data)
}

func boundedLSPHPHealthRead(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, lsphpHealthTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.WaitDelay = time.Second
	stdout := &lsphpHealthBoundedWriter{limit: lsphpHealthOutputLimit}
	stderr := &lsphpHealthBoundedWriter{limit: 16 * 1024}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(bytes.TrimSpace(stderr.buffer.Bytes())) != 0 {
		return nil, errors.New("PHP health probe startup diagnostic")
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}
