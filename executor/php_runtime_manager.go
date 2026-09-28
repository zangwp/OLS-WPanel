package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zangwp/OLS-WPanel/config"
	"github.com/zangwp/OLS-WPanel/database"
	"github.com/zangwp/OLS-WPanel/models"
)

const DefaultLSPHPVersion = "8.5"

var supportedLSPHPVersions = []string{"8.5", "8.4", "8.3"}

// LSPHPRuntime is a deliberately small allow-listed runtime descriptor. Paths
// are derived by the panel rather than accepted from an HTTP request.
type LSPHPRuntime struct {
	Version     string `json:"version"`
	Package     string `json:"package"`
	LSAPIBinary string `json:"lsapi_binary"`
	CLIBinary   string `json:"cli_binary"`
	Installed   bool   `json:"installed"`
	ActiveSites int    `json:"active_sites"`
	Recommended bool   `json:"recommended"`
}

var lsphpInstallMu sync.Mutex

func normalizeLSPHPVersion(version string) (string, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		version = DefaultLSPHPVersion
	}
	for _, allowed := range supportedLSPHPVersions {
		if version == allowed {
			return version, nil
		}
	}
	return "", fmt.Errorf("unsupported LSPHP version: %s", version)
}

func lsphpRuntimeForVersion(version string) (LSPHPRuntime, error) {
	version, err := normalizeLSPHPVersion(version)
	if err != nil {
		return LSPHPRuntime{}, err
	}
	suffix := strings.ReplaceAll(version, ".", "")
	root := filepath.Join("/usr/local/lsws", "lsphp"+suffix, "bin")
	runtime := LSPHPRuntime{
		Version: version, Package: "lsphp" + suffix,
		LSAPIBinary: filepath.Join(root, "lsphp"), CLIBinary: filepath.Join(root, "php"),
		Recommended: version == DefaultLSPHPVersion,
	}
	if version == PrimaryLSPHPVersion() && config.AppConfig != nil {
		if path := strings.TrimSpace(config.AppConfig.Paths.LSPHPBinary); path != "" {
			runtime.LSAPIBinary = filepath.Clean(path)
		}
		if path := strings.TrimSpace(config.AppConfig.Paths.LSPHPCLI); path != "" {
			runtime.CLIBinary = filepath.Clean(path)
		}
	}
	runtime.Installed = trustedLSPHPExecutable(runtime.LSAPIBinary) && trustedLSPHPExecutable(runtime.CLIBinary)
	return runtime, nil
}

// PrimaryLSPHPVersion returns the version configured as the panel-wide CLI
// runtime. Existing installations keep their configured branch (typically
// 8.3), while fresh v1.2+ installations fall back to the verified 8.5 default.
func PrimaryLSPHPVersion() string {
	if config.AppConfig != nil {
		for _, configured := range []string{config.AppConfig.Paths.LSPHPCLI, config.AppConfig.Paths.LSPHPBinary} {
			clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(configured)))
			for _, version := range supportedLSPHPVersions {
				suffix := strings.ReplaceAll(version, ".", "")
				if strings.Contains(clean, "/lsphp"+suffix+"/") {
					return version
				}
			}
		}
	}
	return DefaultLSPHPVersion
}

func trustedLSPHPExecutable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	// Package-managed LSPHP entry points may be symlinks. Do not apply regular
	// file permission checks to the link inode itself (symlink modes commonly
	// appear as 0777); EvalSymlinks plus the target checks below enforce that
	// execution still remains inside the allow-listed LiteSpeed tree.
	if info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0022 != 0 {
		return false
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || !strings.HasPrefix(filepath.ToSlash(clean), "/usr/local/lsws/lsphp") {
		return false
	}
	real, err := filepath.EvalSymlinks(clean)
	if err != nil || !strings.HasPrefix(filepath.ToSlash(real), "/usr/local/lsws/lsphp") {
		return false
	}
	info, err = os.Stat(real)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 && info.Mode().Perm()&0022 == 0
}

func ResolveLSPHPRuntime(version string, requireInstalled bool) (LSPHPRuntime, error) {
	runtime, err := lsphpRuntimeForVersion(version)
	if err != nil {
		return LSPHPRuntime{}, err
	}
	if requireInstalled && !runtime.Installed {
		return LSPHPRuntime{}, fmt.Errorf("LSPHP %s is not installed", runtime.Version)
	}
	return runtime, nil
}

func ListLSPHPRuntimes() []LSPHPRuntime {
	runtimes := make([]LSPHPRuntime, 0, len(supportedLSPHPVersions))
	for _, version := range supportedLSPHPVersions {
		runtime, _ := lsphpRuntimeForVersion(version)
		if db := database.GetDB(); db != nil {
			_ = db.QueryRow(`SELECT COUNT(*) FROM websites WHERE COALESCE(NULLIF(php_version,''), '8.3') = ?`, version).Scan(&runtime.ActiveSites)
		}
		runtimes = append(runtimes, runtime)
	}
	return runtimes
}

func LSPHPCLIPathForVersion(version string) (string, error) {
	runtime, err := ResolveLSPHPRuntime(version, true)
	if err != nil {
		return "", err
	}
	return runtime.CLIBinary, nil
}

func EnsureLSPHPRuntimeConfig(version string) error {
	version, err := normalizeLSPHPVersion(version)
	if err != nil {
		return err
	}
	suffix := strings.ReplaceAll(version, ".", "")
	path := filepath.Join("/usr/local/lsws", "lsphp"+suffix, "etc", "php", version, "litespeed", "conf.d", "99-ols-wpanel.ini")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(path, []byte(defaultPHPRuntimeConfigContent()), 0644)
}

func lsphpRuntimePackages(version string) ([]string, error) {
	version, err := normalizeLSPHPVersion(version)
	if err != nil {
		return nil, err
	}
	suffix := strings.ReplaceAll(version, ".", "")
	prefix := "lsphp" + suffix
	packages := []string{
		prefix,
		prefix + "-common",
		prefix + "-mysql",
		prefix + "-curl",
		prefix + "-intl",
		prefix + "-redis",
	}
	// LiteSpeed does not publish lsphp85-opcache in its Noble or Trixie
	// repositories. PHP 8.3 and 8.4 still ship OPcache as a separate package.
	if version != "8.5" {
		packages = append(packages, prefix+"-opcache")
	}
	packages = append(packages, prefix+"-imagick")
	return packages, nil
}

func InstallLSPHPRuntime(ctx context.Context, version string) (LSPHPRuntime, error) {
	version, err := normalizeLSPHPVersion(version)
	if err != nil {
		return LSPHPRuntime{}, err
	}
	lsphpInstallMu.Lock()
	defer lsphpInstallMu.Unlock()
	if runtime, _ := lsphpRuntimeForVersion(version); runtime.Installed {
		return runtime, nil
	}
	packages, err := lsphpRuntimePackages(version)
	if err != nil {
		return LSPHPRuntime{}, err
	}
	aptOptions := []string{"-o", "Acquire::Retries=3", "-o", "DPkg::Lock::Timeout=300"}
	if out, err := exec.CommandContext(ctx, "apt-get", append(aptOptions, "update")...).CombinedOutput(); err != nil {
		return LSPHPRuntime{}, fmt.Errorf("apt update failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	args := append([]string{"-y"}, aptOptions...)
	args = append(args, "-o", "Dpkg::Options::=--force-confold", "install")
	args = append(args, packages...)
	cmd := exec.CommandContext(ctx, "apt-get", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := cmd.CombinedOutput(); err != nil {
		return LSPHPRuntime{}, fmt.Errorf("LSPHP install failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	runtime, err := ResolveLSPHPRuntime(version, true)
	if err != nil {
		return LSPHPRuntime{}, err
	}
	if err := EnsureLSPHPRuntimeConfig(version); err != nil {
		return LSPHPRuntime{}, err
	}
	return runtime, nil
}

// UpdateSiteLSPHPVersion atomically persists and applies the selected runtime.
// ApplyOLSVHostConfig already validates the complete OLS configuration and
// restores the old file/registry when restart fails; this function additionally
// restores the database value.
func UpdateSiteLSPHPVersion(site *models.Website, version string) error {
	if site == nil || site.ID <= 0 || config.AppConfig == nil || database.GetDB() == nil {
		return errors.New("site runtime unavailable")
	}
	runtime, err := ResolveLSPHPRuntime(version, true)
	if err != nil {
		return err
	}
	oldVersion, err := normalizeLSPHPVersion(site.PHPVersion)
	if err != nil {
		oldVersion = DefaultLSPHPVersion
	}
	if runtime.Version == oldVersion {
		return nil
	}
	if !TryAcquireSiteOpLock(site.ID, "php_runtime") {
		return errors.New("site is busy")
	}
	defer ReleaseSiteOpLock(site.ID)
	if locked, lockErr := SiteMigrationLocked(context.Background(), site.ID, site.Domain); lockErr != nil {
		return lockErr
	} else if locked {
		return errors.New("site migration is active")
	}

	siteCopy := *site
	siteCopy.PHPVersion = runtime.Version
	data, err := olsVHostDataFromSiteChecked(&siteCopy)
	if err != nil {
		return err
	}
	engine := NewTemplateEngine(config.AppConfig.Panel.BackupDir)
	content, err := engine.RenderOLSVHostConfig(data)
	if err != nil {
		return err
	}
	result, err := database.GetDB().Exec(`UPDATE websites SET php_version=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND COALESCE(NULLIF(php_version,''), '8.3')=?`, runtime.Version, site.ID, oldVersion)
	if err != nil {
		return err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return errors.New("site PHP runtime changed concurrently")
	}
	if err := engine.ApplyOLSVHostConfig(content, site.OLSVHostConfigPath, olsVHostEnabledPath(config.AppConfig, site.OLSVHostConfigPath, site.Domain)); err != nil {
		_, rollbackErr := database.GetDB().Exec(`UPDATE websites SET php_version=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND php_version=?`, oldVersion, site.ID, runtime.Version)
		if rollbackErr != nil {
			return fmt.Errorf("apply failed: %v; database rollback failed: %w", err, rollbackErr)
		}
		return err
	}
	return nil
}
