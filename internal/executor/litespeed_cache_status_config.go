package executor

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// This observes the managed configuration on disk, not a running worker. Only
// the independent HTTP verification can prove that a response is a cache hit.
func observeLiteSpeedServerCache(cfg *config.Config, site *models.Website) (string, string, *bool) {
	if site == nil || site.SiteType != "wordpress" {
		return "unsupported", "unsupported_site", nil
	}
	if site.Status != models.StatusActive {
		return "unknown", "inactive_site", nil
	}
	content, reason := readLiteSpeedCacheVHost(cfg, site)
	if reason != "" {
		return "unknown", reason, nil
	}
	return classifyLiteSpeedCacheModule(content)
}

func classifyLiteSpeedCacheModule(content string) (string, string, *bool) {
	values, err := liteSpeedCacheModuleValues(content)
	configured := false
	if errors.Is(err, errLiteSpeedCacheModuleMissing) {
		return "misconfigured", "cache_module_missing", &configured
	}
	if err != nil || values["ls_enabled"] != "1" || values["checkpubliccache"] != "1" || values["checkprivatecache"] != "1" || values["storagepath"] != "$VH_ROOT/.lscache" || values["enableprivatecache"] != "0" {
		return "misconfigured", "cache_module_invalid", &configured
	}
	if values["enablecache"] != "0" {
		return "misconfigured", "unsafe_public_cache_default", &configured
	}
	configured = true
	return "configured", "module_ready", &configured
}

func readLiteSpeedCacheVHost(cfg *config.Config, site *models.Website) (string, string) {
	if cfg == nil || site == nil || !IsValidDomain(site.Domain) {
		return "", "config_unavailable"
	}
	content, err := readSiteSecurityFile(cfg.Paths.OLSVHostsAvailable, site.OLSVHostConfigPath, 256*1024)
	if err != nil {
		return "", "config_unavailable"
	}
	meta, err := parseOLSVHostMetadata(string(content), site.OLSVHostConfigPath)
	if err != nil || len(meta.domains) == 0 || !strings.EqualFold(meta.domains[0], site.Domain) || filepath.Clean(meta.vhRoot) != filepath.Clean(EffectiveDocumentRoot(site.WebRoot, site.SiteType, site.DocumentRootSubdir)) || !liteSpeedCacheVHostIdentityMatches(string(content), site.Domain, meta.vhRoot) {
		return "", "untrusted_vhost"
	}
	// Active DB status alone does not prove that this vhost is in the managed
	// registry. Require its enabled entry to point to the file just inspected.
	enabledRoot := filepath.Clean(cfg.Paths.OLSVHostsEnabled)
	rootInfo, err := os.Lstat(enabledRoot)
	if !filepath.IsAbs(enabledRoot) || err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", "inactive_vhost"
	}
	enabled := filepath.Join(enabledRoot, filepath.Base(site.OLSVHostConfigPath))
	info, err := os.Lstat(enabled)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", "inactive_vhost"
	}
	target, err := filepath.EvalSymlinks(enabled)
	if err != nil || filepath.Clean(target) != filepath.Clean(site.OLSVHostConfigPath) {
		return "", "inactive_vhost"
	}
	return string(content), ""
}

func liteSpeedCacheVHostIdentityMatches(content, domain, root string) bool {
	domainValues := regexp.MustCompile(`(?im)^vhDomain[ \t]+([^\r\n]+)$`).FindAllStringSubmatch(content, -1)
	rootValues := regexp.MustCompile(`(?im)^docRoot[ \t]+([^\r\n]+)$`).FindAllStringSubmatch(content, -1)
	return len(domainValues) == 1 && len(rootValues) == 1 && strings.EqualFold(strings.TrimSpace(domainValues[0][1]), domain) && filepath.Clean(strings.TrimSpace(rootValues[0][1])) == filepath.Clean(root)
}

var errLiteSpeedCacheModuleMissing = errors.New("cache module missing")
var liteSpeedCacheModuleStart = regexp.MustCompile(`(?i)^module\s+cache\s*\{$`)

// Managed vhosts render the cache block at top level with one scalar per line.
// Reject duplicates/complex blocks rather than guessing their effective value.
func liteSpeedCacheModuleValues(content string) (map[string]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	values := make(map[string]string)
	inBlock, found, closed := false, false, false
	heredoc := ""
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if heredoc != "" {
			if line == heredoc {
				heredoc = ""
			}
			continue
		}
		if !inBlock && strings.Contains(line, "<<<") {
			heredoc = strings.TrimSpace(strings.SplitN(line, "<<<", 2)[1])
			continue
		}
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if !inBlock {
			if raw == strings.TrimLeft(raw, " \t") && liteSpeedCacheModuleStart.MatchString(line) {
				if found {
					return nil, errors.New("duplicate cache modules")
				}
				found, inBlock = true, true
			}
			continue
		}
		if line == "}" {
			inBlock, closed = false, true
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.ContainsAny(line, "{}<>\"'") {
			return nil, errors.New("complex cache configuration")
		}
		key := strings.ToLower(fields[0])
		if _, duplicate := values[key]; duplicate {
			return nil, errors.New("duplicate cache scalar")
		}
		values[key] = fields[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !found {
		return nil, errLiteSpeedCacheModuleMissing
	}
	if !closed || inBlock {
		return nil, errors.New("unclosed cache module")
	}
	return values, nil
}
