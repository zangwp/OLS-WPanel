package executor

import (
	"path/filepath"
	"strings"

	"github.com/zangwp/OLS-WPanel/config"
	"github.com/zangwp/OLS-WPanel/models"
)

func olsVHostDataFromSiteChecked(site *models.Website) (*OLSVHostData, error) {
	cfg := config.AppConfig
	runtime, err := ResolveLSPHPRuntime(site.PHPVersion, false)
	if err != nil {
		return nil, err
	}
	aliases := splitAliases(site.Aliases)
	accessLogMode := site.AccessLogMode
	if accessLogMode == "" {
		accessLogMode = "off"
	}
	templateVer := site.TemplateVersion
	if templateVer == "" {
		templateVer = "v1.0"
	}
	lsCacheTTL := site.LSCacheTTL
	if lsCacheTTL <= 0 {
		lsCacheTTL = 300
	}

	data := &OLSVHostData{
		Domain:         site.Domain,
		Aliases:        aliases,
		ServerNames:    buildServerNames(site.Domain, aliases),
		WebRoot:        EffectiveDocumentRoot(site.WebRoot, site.SiteType, site.DocumentRootSubdir),
		LogDir:         site.LogDir,
		SystemUser:     site.SystemUser,
		UseSSL:         site.SSLEnabled,
		SiteType:       site.SiteType,
		SSLCertPath:    site.SSLCertPath,
		SSLKeyPath:     site.SSLKeyPath,
		PHPProxy:       "unix:" + phpSocketPath(cfg, site.LSPHPSocketPath, site.Domain),
		LSPHPBinary:    runtime.LSAPIBinary,
		TemplateVer:    templateVer,
		AccessLogMode:  accessLogMode,
		LSCacheEnabled: site.LSCacheEnabled,
		LSCacheTTL:     lsCacheTTL,
		LSCacheKey:     site.LSCacheKey,
		XMLRPCEnabled:  site.XMLRPCEnabled,
		PHPMaxChildren: site.LSPHPMaxChildren,
	}
	if data.PHPMaxChildren <= 0 {
		data.PHPMaxChildren = 10
	}
	if runtime, err := ResolveCDNRealIPRuntime(site); err != nil {
		return nil, err
	} else if runtime.Enabled {
		data.CDNRealIPEnabled = true
		data.CDNRealIPHeader = runtime.HeaderName
		data.CDNRealIPRanges = runtime.IPRanges
		data.CDNRealIPCompat = runtime.Compatible
	}
	if data.UseSSL {
		if data.SSLCertPath == "" {
			data.SSLCertPath = filepath.Join(cfg.Paths.Certificates, site.Domain, "fullchain.pem")
		}
		if data.SSLKeyPath == "" {
			data.SSLKeyPath = filepath.Join(cfg.Paths.Certificates, site.Domain, "privkey.pem")
		}
	}
	return data, nil
}

func splitAliases(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "\n")
	aliases := make([]string, 0, len(parts))
	for _, alias := range parts {
		alias = strings.TrimSpace(alias)
		if alias != "" {
			aliases = append(aliases, alias)
		}
	}
	return aliases
}
