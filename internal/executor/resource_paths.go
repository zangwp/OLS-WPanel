package executor

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

const maxUnixSocketPathLen = 107

func siteConfigBaseName(siteName string) string {
	siteName = strings.TrimSpace(siteName)
	if siteName == "" {
		return "site"
	}
	return siteName
}

func pathBaseWithoutExt(path, fallback string) string {
	base := strings.TrimSpace(filepath.Base(path))
	if base == "." || base == string(filepath.Separator) {
		base = ""
	}
	if ext := filepath.Ext(base); ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "" {
		base = fallback
	}
	return base
}

func phpSocketPath(cfg *config.Config, persistedPath, domain string) string {
	if strings.TrimSpace(persistedPath) != "" {
		return filepath.Clean(persistedPath)
	}
	return filepath.Join(cfg.Paths.LSPHPSocketDir, siteConfigBaseName(buildSiteName(domain))+".sock")
}

func olsVHostEnabledPath(cfg *config.Config, olsVHostConfigPath, domain string) string {
	confName := strings.TrimSpace(filepath.Base(olsVHostConfigPath))
	if confName == "" || confName == "." || confName == string(filepath.Separator) {
		confName = buildSiteName(domain) + ".conf"
	}
	return filepath.Join(cfg.Paths.OLSVHostsEnabled, confName)
}

func validateUnixSocketPath(path string) error {
	if len([]byte(path)) > maxUnixSocketPathLen {
		return fmt.Errorf("LSPHP socket 路径过长: %s", path)
	}
	return nil
}
