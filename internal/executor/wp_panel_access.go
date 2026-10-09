package executor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

const wpPanelAccessPluginFile = "ols-wpanel-access.php"
const wpPanelAccessPluginMarker = "OLS-WPANEL-MANAGED:wordpress-access:1"

type WPPanelAccessError struct{ Code string }

func (e *WPPanelAccessError) Error() string { return "WordPress panel access: " + e.Code }
func WPPanelAccessErrorCode(err error) string {
	var e *WPPanelAccessError
	if errors.As(err, &e) {
		return e.Code
	}
	return "operation_failed"
}
func wpPanelAccessError(code string) error { return &WPPanelAccessError{code} }

type WPPanelAccessSettings struct {
	ManualLoginURL   string `json:"manual_login_url"`
	LoginSuffix      string `json:"login_suffix"`
	SSOEnabled       bool   `json:"sso_enabled"`
	Generation       string `json:"generation"`
	Domain           string `json:"domain"`
	InstallationPath string `json:"installation_path"`
	SiteIdentity     string `json:"site_identity"`
}

type WPPanelAccessAdministrator struct {
	ID          int    `json:"id"`
	Login       string `json:"login"`
	DisplayName string `json:"display_name"`
}

type WPPanelAccessStatus struct {
	Installed             bool                         `json:"installed"`
	LoginURL              string                       `json:"login_url"`
	DetectedLoginURL      string                       `json:"detected_login_url"`
	LoginSource           string                       `json:"login_source"`
	InstallURL            string                       `json:"install_url"`
	InstallationPath      string                       `json:"installation_path"`
	ManualLoginURL        string                       `json:"manual_login_url"`
	LoginSuffix           string                       `json:"login_suffix"`
	SSOEnabled            bool                         `json:"sso_enabled"`
	SSOAvailable          bool                         `json:"sso_available"`
	BridgeInstalled       bool                         `json:"bridge_installed"`
	ExternalLoginControl  bool                         `json:"external_login_control"`
	ConflictingPlugins    []string                     `json:"conflicting_plugins"`
	AuthenticationPlugins []string                     `json:"authentication_plugins"`
	Administrators        []WPPanelAccessAdministrator `json:"administrators"`
	PermalinksEnabled     bool                         `json:"permalinks_enabled"`
	ReasonCode            string                       `json:"reason_code"`
	RecoveryFile          string                       `json:"recovery_file"`
	CurlUnixAvailable     bool                         `json:"curl_unix_available"`
	SiteURL               string                       `json:"-"`
	AdministratorProofs   map[int]string               `json:"-"`
}

func WPPanelAccessSiteIdentity(site *models.Website) string {
	if site == nil {
		return ""
	}
	value := fmt.Sprintf("%d\n%s\n%s\n%s\n%s\n%s", site.ID, site.Domain, site.SystemUser, site.WebRoot, site.DBName, site.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z"))
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

var wpPanelAccessSuffixPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

func ValidateWPPanelAccessSuffix(suffix string) error {
	if suffix == "" {
		return nil
	}
	if !wpPanelAccessSuffixPattern.MatchString(suffix) {
		return wpPanelAccessError("invalid_suffix")
	}
	for _, reserved := range []string{"wp-admin", "wp-login", "wp-json", "wp-content", "wp-includes", "index", "admin", "login", "feed", "sitemap", "robots"} {
		if suffix == reserved {
			return wpPanelAccessError("invalid_suffix")
		}
	}
	return nil
}

// ValidateWPPanelAccessURL accepts only same-origin URLs below the actual WP
// installation. It never follows a submitted URL or treats it as a filesystem path.
func ValidateWPPanelAccessURL(site *models.Website, installationPath, raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if site == nil || !IsValidDomain(site.Domain) || len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\\\r\n\t") {
		return "", wpPanelAccessError("invalid_login_url")
	}
	scheme := "http"
	if site.SSLEnabled {
		scheme = "https"
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		raw = scheme + "://" + site.Domain + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Scheme != scheme || !strings.EqualFold(u.Hostname(), site.Domain) || (u.Port() != "" && u.Port() != map[string]string{"https": "443", "http": "80"}[scheme]) {
		return "", wpPanelAccessError("invalid_login_url")
	}
	decoded := u.Path
	if decoded == "" || strings.ContainsAny(decoded, "\\%\x00\r\n\t") || strings.Contains(strings.ToLower(u.EscapedPath()), "%2f") || strings.Contains(strings.ToLower(u.EscapedPath()), "%5c") || path.Clean(decoded) != strings.TrimSuffix(decoded, "/") && decoded != "/" {
		return "", wpPanelAccessError("invalid_login_url")
	}
	base := strings.TrimSuffix(installationPath, "/")
	if base != "" && decoded != base && !strings.HasPrefix(decoded, base+"/") {
		return "", wpPanelAccessError("invalid_login_url")
	}
	for key, values := range u.Query() {
		if strings.ContainsAny(key, "\x00\r\n") {
			return "", wpPanelAccessError("invalid_login_url")
		}
		if strings.EqualFold(key, "redirect_to") {
			for _, value := range values {
				if value != "" {
					if _, err := ValidateWPPanelAccessURL(site, installationPath, value); err != nil {
						return "", err
					}
				}
			}
		}
	}
	u.Host = strings.ToLower(u.Host)
	return u.String(), nil
}

func WPPanelAccessUID(site *models.Website) (int, error) {
	if site == nil || !wpInventoryUserPattern.MatchString(site.SystemUser) {
		return 0, wpPanelAccessError("site_unavailable")
	}
	uid, _, err := siteUserIDs(site.SystemUser)
	if err != nil || uid <= 0 {
		return 0, wpPanelAccessError("site_unavailable")
	}
	return uid, nil
}

func wpPanelAccessConfigPath(site *models.Website, create bool) (string, error) {
	cfg := config.AppConfig
	if cfg == nil || !filepath.IsAbs(cfg.Panel.DataDir) || site == nil || site.ID <= 0 {
		return "", wpPanelAccessError("settings_unavailable")
	}
	dir := filepath.Join(cfg.Panel.DataDir, "wp-panel-access")
	if create {
		if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) && !create {
		return filepath.Join(dir, strconv.Itoa(site.ID)+".json"), nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return "", wpPanelAccessError("settings_unavailable")
	}
	uid, _, err := fileOwnerIDs(info)
	if err != nil || uid != 0 {
		return "", wpPanelAccessError("settings_unavailable")
	}
	return filepath.Join(dir, strconv.Itoa(site.ID)+".json"), nil
}

func ReadWPPanelAccessSettings(site *models.Website) (WPPanelAccessSettings, error) {
	var result WPPanelAccessSettings
	file, err := wpPanelAccessConfigPath(site, false)
	if err != nil {
		return result, err
	}
	info, err := os.Lstat(file)
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	uid, _, ownerErr := fileOwnerIDs(info)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || ownerErr != nil || uid != 0 || info.Size() > 16<<10 {
		return result, wpPanelAccessError("settings_unavailable")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return result, err
	}
	if json.Unmarshal(data, &result) != nil {
		return result, wpPanelAccessError("settings_unavailable")
	}
	// An old website ID must never carry an authorization across reinstallation.
	if result.SiteIdentity != WPPanelAccessSiteIdentity(site) {
		return WPPanelAccessSettings{}, nil
	}
	if result.Domain != site.Domain || len(result.Generation) != 32 || ValidateWPPanelAccessSuffix(result.LoginSuffix) != nil {
		return WPPanelAccessSettings{}, wpPanelAccessError("settings_unavailable")
	}
	return result, nil
}

func WPPanelAccessPluginMatches(site *models.Website, settings WPPanelAccessSettings) bool {
	file, err := managedWordPressPath(site.WebRoot, "wp-content", "mu-plugins", wpPanelAccessPluginFile)
	if err != nil {
		return false
	}
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return false
	}
	data, err := os.ReadFile(file)
	return err == nil && string(data) == renderWPPanelAccessPlugin(site.ID, settings)
}

func wpPanelAccessReadSnapshot(file string, limit int64) ([]byte, bool, error) {
	info, err := os.Lstat(file)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, false, wpPanelAccessError("settings_unavailable")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, false, wpPanelAccessError("settings_unavailable")
	}
	return data, true, nil
}

func wpPanelAccessWriteConfig(file string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(file), ".wp-access-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), file)
}

// ApplyWPPanelAccessSettings writes only one named MU plugin and one private
// settings file. Its rollback restores both; callers keep their per-site lock
// through runtime verification and call rollback if validation fails.
func ApplyWPPanelAccessSettings(site *models.Website, settings WPPanelAccessSettings) (func() error, error) {
	if site == nil || site.SiteType != "wordpress" || site.FileLockEnabled || site.Status != models.StatusActive {
		return nil, wpPanelAccessError("site_unavailable")
	}
	if err := ValidateWPPanelAccessSuffix(settings.LoginSuffix); err != nil {
		return nil, err
	}
	if _, err := ValidateWPPanelAccessURL(site, settings.InstallationPath, settings.ManualLoginURL); err != nil {
		return nil, err
	}
	configPath, err := wpPanelAccessConfigPath(site, true)
	if err != nil {
		return nil, err
	}
	muDir, err := managedWordPressPath(site.WebRoot, "wp-content", "mu-plugins")
	if err != nil {
		return nil, err
	}
	pluginPath, err := managedWordPressPath(site.WebRoot, "wp-content", "mu-plugins", wpPanelAccessPluginFile)
	if err != nil {
		return nil, err
	}
	oldConfig, configExists, err := wpPanelAccessReadSnapshot(configPath, 16<<10)
	if err != nil {
		return nil, err
	}
	oldPlugin, pluginExists, err := wpPanelAccessReadSnapshot(pluginPath, 64<<10)
	if err != nil {
		return nil, err
	}
	if pluginExists && !strings.Contains(string(oldPlugin), wpPanelAccessPluginMarker) {
		return nil, wpPanelAccessError("unmanaged_bridge")
	}
	if settings.LoginSuffix != "" {
		collision, err := managedWordPressPath(site.WebRoot, settings.LoginSuffix)
		if err != nil {
			return nil, err
		}
		if _, err := os.Lstat(collision); err == nil || !os.IsNotExist(err) {
			return nil, wpPanelAccessError("suffix_conflict")
		}
	}
	if err := os.MkdirAll(muDir, 0755); err != nil {
		return nil, err
	}
	if err := ChownSitePath(muDir, site.WebRoot, site.SystemUser); err != nil {
		return nil, err
	}
	rollback := func() error {
		var failures []error
		if pluginExists {
			if err := writeManagedPHPFile(site.WebRoot, pluginPath, oldPlugin, 0644); err != nil {
				failures = append(failures, err)
			}
		} else if err := os.Remove(pluginPath); err != nil && !os.IsNotExist(err) {
			failures = append(failures, err)
		}
		if configExists {
			if err := wpPanelAccessWriteConfig(configPath, oldConfig); err != nil {
				failures = append(failures, err)
			}
		} else if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
			failures = append(failures, err)
		}
		return errors.Join(failures...)
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	settings.Generation = hex.EncodeToString(random)
	settings.Domain = site.Domain
	settings.SiteIdentity = WPPanelAccessSiteIdentity(site)
	if settings.SSOEnabled || settings.LoginSuffix != "" {
		if err := writeManagedPHPFile(site.WebRoot, pluginPath, []byte(renderWPPanelAccessPlugin(site.ID, settings)), 0644); err != nil {
			return rollback, err
		}
		if err := ChownSitePath(pluginPath, site.WebRoot, site.SystemUser); err != nil {
			return rollback, err
		}
	} else if pluginExists {
		if err := os.Remove(pluginPath); err != nil {
			return rollback, err
		}
	}
	data, err := json.Marshal(settings)
	if err != nil {
		return rollback, err
	}
	if err := wpPanelAccessWriteConfig(configPath, data); err != nil {
		return rollback, err
	}
	DefaultWPPanelAccessTokens.Revoke(site.ID, "")
	return rollback, nil
}
