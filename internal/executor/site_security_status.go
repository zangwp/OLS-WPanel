package executor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var siteSecurityKeys = []string{"https", "login_protection", "xmlrpc", "application_passwords", "sensitive_files", "uploads_php", "file_editing", "file_lock", "debug_display", "uptime_monitor", "anomaly_monitor", "wp_updates", "backup", "sql_injection"}

// A saved setting is not proof that a live worker has loaded it. Only an
// observed deny response or recent trusted audit evidence earns "effective".
func SetWebsiteSecurityCheck(report *models.WebsiteSecurityStatus, key, state string, configured, effective *bool) {
	for i := range report.Checks {
		if report.Checks[i].Key == key {
			if state == "effective" && (effective == nil || !*effective) {
				state = "unknown"
			}
			report.Checks[i] = models.WebsiteSecurityCheck{Key: key, State: state, Configured: configured, Effective: effective}
			return
		}
	}
}

func securityBool(value bool) *bool { return &value }

func CollectWebsiteSecurityStatus(ctx context.Context, site *models.Website) models.WebsiteSecurityStatus {
	report := models.WebsiteSecurityStatus{SiteID: site.ID, CheckedAt: time.Now().UTC().Format(time.RFC3339), Checks: make([]models.WebsiteSecurityCheck, 0, len(siteSecurityKeys))}
	for _, key := range siteSecurityKeys {
		report.Checks = append(report.Checks, models.WebsiteSecurityCheck{Key: key, State: "unknown"})
	}
	set := func(key, state string, configured bool) {
		SetWebsiteSecurityCheck(&report, key, state, securityBool(configured), nil)
	}
	desired := func(key string, enabled bool) {
		if enabled {
			set(key, "configured", true)
		} else {
			SetWebsiteSecurityCheck(&report, key, "disabled", securityBool(false), securityBool(false))
		}
	}
	desired("https", site.SSLEnabled)
	desired("uptime_monitor", site.MonitoringEnabled)
	desired("file_lock", site.FileLockEnabled)
	if site.FileLockEnabled && site.FileLockApplyStatus != FileLockApplyStatusReady {
		set("file_lock", "error", false)
	}
	if site.SiteType != "wordpress" {
		for _, key := range []string{"login_protection", "xmlrpc", "application_passwords", "uploads_php", "file_editing", "debug_display", "anomaly_monitor", "wp_updates", "sql_injection"} {
			SetWebsiteSecurityCheck(&report, key, "unsupported", nil, nil)
		}
	}
	cfg := config.AppConfig
	if cfg == nil {
		return report
	}
	vhost, readErr := readSiteSecurityFile(cfg.Paths.OLSVHostsAvailable, site.OLSVHostConfigPath, 256*1024)
	var vhostChangedAt time.Time
	if info, err := os.Stat(site.OLSVHostConfigPath); err == nil {
		vhostChangedAt = info.ModTime()
	}
	loginReady := false
	blockSQLi, banSQLi := GetSQLiProtectionSettings()
	rulesMatch := readErr == nil && OLSVHostSecurityRulesMatch(string(vhost), &OLSVHostData{SiteType: site.SiteType, XMLRPCEnabled: site.XMLRPCEnabled, SQLiBlockEnabled: blockSQLi, SQLiAutoBanLog: banSQLi})
	set("sensitive_files", "error", false)
	if rulesMatch {
		set("sensitive_files", "configured", true)
	}
	if site.SiteType == "wordpress" {
		desired("xmlrpc", !site.XMLRPCEnabled)
		desired("sql_injection", blockSQLi)
		for _, key := range []string{"uploads_php", "login_protection", "application_passwords", "file_editing", "debug_display", "wp_updates"} {
			set(key, "error", false)
		}
		if rulesMatch {
			set("uploads_php", "configured", true)
		} else {
			if !site.XMLRPCEnabled {
				set("xmlrpc", "error", false)
			}
			if blockSQLi {
				set("sql_injection", "error", false)
			}
		}
		wpConfig, wpErr := readSiteSecurityFile(cfg.Paths.WWWRoot, filepath.Join(site.WebRoot, "wp-config.php"), 1024*1024)
		if wpErr == nil {
			content := string(wpConfig)
			checkConstant := func(key, name string, enabled bool) {
				desired(key, enabled)
				if enabled && !siteSecurityBoolConstant(content, name, true) {
					set(key, "error", false)
				}
			}
			checkConstant("file_editing", "DISALLOW_FILE_EDIT", site.DisableFileEditing)
			// An explicit false prevents PHP warnings from being printed to visitors.
			if siteSecurityBoolConstant(content, "WP_DEBUG_DISPLAY", false) {
				set("debug_display", "configured", true)
			} else if siteSecurityBoolConstant(content, "WP_DEBUG_DISPLAY", true) {
				desired("debug_display", false)
			} else {
				SetWebsiteSecurityCheck(&report, "debug_display", "unknown", nil, nil)
			}
			desired("application_passwords", site.DisableApplicationPasswords)
			if site.DisableApplicationPasswords {
				if !siteSecurityNativePolicyMatches(content, site.DisableWPUpdates, true) {
					set("application_passwords", "error", false)
				}
			}
			desired("wp_updates", !site.DisableWPUpdates)
			if !site.DisableWPUpdates && (strings.Contains(siteSecurityPHPWithoutComments(content), "ols_wpanel_policy_disable_checks") || siteSecurityBoolConstant(content, "DISALLOW_FILE_MODS", true)) {
				set("wp_updates", "error", false)
			}
			if site.FileLockEnabled && (!siteSecurityBoolConstant(content, "DISALLOW_FILE_MODS", true) || site.FileLockApplyStatus != FileLockApplyStatusReady) {
				set("file_lock", "error", false)
			}
			// Installation + a running jail still needs real WordPress evidence.
			if WPLoginFailureLoggingConfigured(site.WebRoot, site.LogDir, site.SystemUser) && rulesMatch && strings.Contains(string(vhost), ":"+site.LogDir+"\"") {
				loginReady = true
				set("login_protection", "configured", true)
			}
		}
	}
	// Read-only HEADs target only this host on loopback, never user URLs, DNS,
	// redirects, query payloads or authentication attempts. A control path guards
	// against reporting a blanket 403/default virtual host as successful protection.
	if rulesMatch && site.Status == models.StatusActive && validSiteSecurityHost(site.Domain) {
		probes := observeSiteSecurityDenials(ctx, site.Domain, site.SiteType == "wordpress", !site.XMLRPCEnabled)
		for key, verified := range probes {
			if verified {
				SetWebsiteSecurityCheck(&report, key, "effective", securityBool(true), securityBool(true))
			}
		}
		if probes["_reachable"] && site.SiteType == "wordpress" {
			if blockSQLi && !vhostChangedAt.IsZero() && HasRecentWPSecurityEvidence(site.LogDir, "sqli", vhostChangedAt) {
				SetWebsiteSecurityCheck(&report, "sql_injection", "effective", securityBool(true), securityBool(true))
			}
			if loginReady && HasRecentWPSecurityEvidence(site.LogDir, "login") && WPLoginFailureJailMatches(ctx, filepath.Join(site.LogDir, wpLoginFailureLogName)) {
				SetWebsiteSecurityCheck(&report, "login_protection", "effective", securityBool(true), securityBool(true))
			}
		}
	}
	return report
}

func siteSecurityNativePolicyMatches(content string, noUpdates, noApplicationPasswords bool) bool {
	expected := nativePolicyBlock.FindString(renderWPNativePolicy("<?php\n", noUpdates, noApplicationPasswords))
	if expected == "" || nativePolicyBlock.FindString(content) != expected {
		return false
	}
	// A copied policy example in a string or heredoc is not installed code.
	return strings.Contains(siteSecurityPHPWithoutComments(content), siteSecurityPHPWithoutComments(expected))
}

func siteSecurityBoolConstant(content, name string, value bool) bool {
	active := siteSecurityPHPWithoutComments(content)
	// PHP names are case sensitive. Function names and boolean literals are not.
	// A const declaration or any second define, including a dynamic value, makes
	// this limited inspection ambiguous rather than selecting a convenient value.
	if regexp.MustCompile("(?i:\\bconst)\\s+" + regexp.QuoteMeta(name) + "\\s*=").MatchString(active) {
		return false
	}
	skipSpace := func(index int) int {
		for index < len(active) && strings.ContainsRune(" \t\r\n", rune(active[index])) {
			index++
		}
		return index
	}
	calls := regexp.MustCompile("(?i:\\bdefine)\\s*\\(").FindAllStringIndex(active, -1)
	literal := regexp.MustCompile("(?i)^(true|false)\\s*\\)\\s*;")
	definitions, confirmed := 0, false
	for _, call := range calls {
		index := skipSpace(call[1])
		if index >= len(active) || (active[index] != '\'' && active[index] != '"') {
			continue
		}
		quote := active[index]
		end := strings.IndexByte(active[index+1:], quote)
		if end < 0 {
			continue
		}
		end += index + 1
		if content[index+1:end] != name {
			continue
		}
		definitions++
		index = skipSpace(end + 1)
		if index >= len(active) || active[index] != ',' {
			continue
		}
		index = skipSpace(index + 1)
		match := literal.FindStringSubmatch(active[index:])
		if len(match) != 2 {
			continue
		}
		// Member calls and variable functions are not proven calls to PHP define.
		before := strings.TrimRight(active[:call[0]], " \t\r\n")
		if strings.HasSuffix(before, "$") || strings.HasSuffix(before, "->") || strings.HasSuffix(before, "::") {
			continue
		}
		if strings.HasSuffix(before, "\\") {
			prefix := strings.TrimSuffix(before, "\\")
			if len(prefix) > 0 && (prefix[len(prefix)-1] == '_' || prefix[len(prefix)-1] == '\\' || prefix[len(prefix)-1] >= 'a' && prefix[len(prefix)-1] <= 'z' || prefix[len(prefix)-1] >= 'A' && prefix[len(prefix)-1] <= 'Z' || prefix[len(prefix)-1] >= '0' && prefix[len(prefix)-1] <= '9') {
				continue
			}
		}
		confirmed = strings.EqualFold(match[1], fmt.Sprint(value))
	}
	return definitions == 1 && confirmed
}

// Mask comments and string contents, preserving byte offsets and line breaks.
// Quote delimiters remain available so the caller can read a literal argument
// from the original source. Heredoc/nowdoc bodies never count as executable code.
func siteSecurityPHPWithoutComments(content string) string {
	data := []byte(content)
	mask := func(start, end int) {
		for index := start; index < end && index < len(data); index++ {
			if data[index] != '\n' && data[index] != '\r' {
				data[index] = ' '
			}
		}
	}
	heredoc := regexp.MustCompile("^<<<[ \t]*(?:'([A-Za-z_][A-Za-z0-9_]*)'|\"([A-Za-z_][A-Za-z0-9_]*)\"|([A-Za-z_][A-Za-z0-9_]*))[ \t]*\r?\n")
	for i := 0; i < len(data); {
		if data[i] == '\'' || data[i] == '"' || data[i] == '`' {
			quote := data[i]
			i++
			for i < len(data) {
				if data[i] == '\\' {
					mask(i, i+2)
					i += 2
					continue
				}
				if data[i] == quote {
					i++
					break
				}
				mask(i, i+1)
				i++
			}
			continue
		}
		if i+2 < len(data) && string(data[i:i+3]) == "<<<" {
			match := heredoc.FindStringSubmatch(string(data[i:]))
			if len(match) != 4 {
				mask(i, len(data))
				break
			}
			label := match[1]
			if label == "" {
				label = match[2]
			}
			if label == "" {
				label = match[3]
			}
			body := i + len(match[0])
			end := regexp.MustCompile("(?m)^[ \t]*" + regexp.QuoteMeta(label) + "(?:[;,\\)\\]\r\n]|$)").FindStringIndex(string(data[body:]))
			if end == nil {
				mask(i, len(data))
				break
			}
			next := body + end[1]
			mask(i, next)
			i = next
			continue
		}
		if data[i] == '#' || (i+1 < len(data) && data[i] == '/' && data[i+1] == '/') {
			for i < len(data) && data[i] != '\n' {
				mask(i, i+1)
				i++
			}
			continue
		}
		if i+1 < len(data) && data[i] == '/' && data[i+1] == '*' {
			data[i], data[i+1] = ' ', ' '
			i += 2
			for i < len(data) {
				if i+1 < len(data) && data[i] == '*' && data[i+1] == '/' {
					data[i], data[i+1] = ' ', ' '
					i += 2
					break
				}
				mask(i, i+1)
				i++
			}
			continue
		}
		i++
	}
	return string(data)
}

func readSiteSecurityFile(root, target string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(target) {
		return nil, fmt.Errorf("unmanaged security file")
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("unmanaged security file")
	}
	current := filepath.Clean(root)
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("unsafe security directory")
		}
		current = filepath.Join(current, part)
	}
	info, err := os.Lstat(current)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("unsafe security file")
	}
	f, err := openSafeWPSecurityLog(current, func(directory string) bool {
		return directory == filepath.Dir(current)
	})
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("security file changed")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("security file too large")
	}
	return data, err
}

func validSiteSecurityHost(host string) bool {
	return len(host) > 0 && len(host) <= 253 && regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`).MatchString(host) && !strings.Contains(host, "..")
}

func observeSiteSecurityDenials(ctx context.Context, host string, wordpress, denyXMLRPC bool) map[string]bool {
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 350 * time.Millisecond}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 650 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return observeSiteSecurityDenialsWithClient(ctx, client, host, wordpress, denyXMLRPC)
}

func observeSiteSecurityDenialsWithClient(ctx context.Context, client *http.Client, host string, wordpress, denyXMLRPC bool) map[string]bool {
	result := map[string]bool{}
	if !validSiteSecurityHost(host) {
		return result
	}
	status := func(path string) int {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, "http://127.0.0.1:80"+path, nil)
		if err != nil {
			return 0
		}
		req.Host = host
		req.Header.Set("User-Agent", "OLS-WPanel-ReadOnly-Security-Check")
		response, err := client.Do(req)
		if err != nil {
			return 0
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	control := status("/.well-known/acme-challenge/ols-wpanel-readonly-security-probe")
	if control == 0 || control == 403 || control >= 500 {
		return result
	}
	// The default deny-all host intentionally permits ACME. A normal path must
	// also respond before accepting 403s as evidence for this site's rules.
	control = status("/ols-wpanel-readonly-security-control-not-a-file")
	if control == 0 || control == 403 || control >= 500 {
		return result
	}
	result["_reachable"] = true
	result["sensitive_files"] = status("/.git/ols-wpanel-readonly-security-probe") == 403
	if wordpress {
		result["uploads_php"] = status("/wp-content/uploads/ols-wpanel-readonly-security-probe.php") == 403
		if denyXMLRPC {
			result["xmlrpc"] = status("/xmlrpc.php") == 403
		}
	}
	return result
}
