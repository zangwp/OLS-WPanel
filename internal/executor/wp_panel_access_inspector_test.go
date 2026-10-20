package executor

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func TestWPPanelAccessInspectionAvoidsRedundantBootstrapAndKeepsInstallationGuard(t *testing.T) {
	oldConfig, oldPHP := config.AppConfig, wpPanelAccessInspectPHP
	t.Cleanup(func() { config.AppConfig = oldConfig; wpPanelAccessInspectPHP = oldPHP })
	cfg := &config.Config{}
	cfg.Panel.DataDir = t.TempDir()
	config.AppConfig = cfg
	site := &models.Website{ID: 8, Domain: "example.com", SiteType: "wordpress", Status: models.StatusActive, SSLEnabled: true, WebRoot: t.TempDir()}
	installed := true
	var phases, candidates []string
	wpPanelAccessInspectPHP = func(ctx context.Context, s *models.Website, settings WPPanelAccessSettings, phase, candidate string, probe *wpPanelAccessProbe) error {
		phases = append(phases, phase)
		candidates = append(candidates, candidate)
		*probe = wpPanelAccessProbe{Installed: installed, SiteURL: "https://example.com", LoginURL: "https://example.com/wp-login.php"}
		if candidate == "about" {
			return wpPanelAccessError("suffix_conflict")
		}
		return nil
	}
	before, err := InspectWPPanelAccessForSettings(context.Background(), site, "staff-signin")
	if err != nil || !before.Installed || !reflect.DeepEqual(phases, []string{"installation", "status"}) || !reflect.DeepEqual(candidates, []string{"", "staff-signin"}) {
		t.Fatalf("before state=%+v phases=%v candidates=%v err=%v", before, phases, candidates, err)
	}
	phases, candidates = nil, nil
	if _, err := InspectWPPanelAccessAfterSettings(context.Background(), site); err != nil || !reflect.DeepEqual(phases, []string{"status"}) {
		t.Fatalf("after phases=%v err=%v", phases, err)
	}
	phases = nil
	if _, err := InspectWPPanelAccessForSettings(context.Background(), site, "about"); WPPanelAccessErrorCode(err) != "suffix_conflict" || !reflect.DeepEqual(phases, []string{"installation", "status"}) {
		t.Fatalf("occupied route phases=%v err=%v", phases, err)
	}
	installed = false
	phases = nil
	result, err := InspectWPPanelAccess(context.Background(), site)
	if err != nil || result.Installed || result.ReasonCode != "not_installed" || !reflect.DeepEqual(phases, []string{"installation"}) {
		t.Fatalf("uninstalled state=%+v phases=%v err=%v", result, phases, err)
	}
	if _, err := InspectWPPanelAccessAfterSettings(context.Background(), site); WPPanelAccessErrorCode(err) != "not_installed" {
		t.Fatalf("after accepted installation disappearing during save: %v", err)
	}
}

func TestWPPanelAccessInspectionSeparatesUnavailablePanelRouteFromExternalControl(t *testing.T) {
	for _, test := range []struct {
		name, path, loginURL      string
		conflicts, authentication []string
		clearSuffix, disableSSO   bool
		matchingBridge            bool
		wantSource, wantReason    string
		wantExternal, wantSSO     bool
		wantError                 string
	}{
		{name: "stale suffix without bridge", loginURL: "https://example.com/wp-login.php", conflicts: []string{"filtered_login_url"}, wantSource: "native", wantReason: "login_route_mismatch"},
		{name: "stale suffix with matching bridge", loginURL: "https://example.com/wp-login.php", conflicts: []string{"filtered_login_url"}, matchingBridge: true, wantSource: "native", wantReason: "login_route_mismatch"},
		{name: "native without comparison marker", loginURL: "https://example.com/wp-login.php", matchingBridge: true, wantSource: "native", wantReason: "login_route_mismatch"},
		{name: "subdirectory native route", path: "/wp", loginURL: "https://example.com/wp/wp-login.php", conflicts: []string{"filtered_login_url"}, matchingBridge: true, wantSource: "native", wantReason: "login_route_mismatch"},
		{name: "native explicit default port", loginURL: "https://example.com:443/wp-login.php", conflicts: []string{"filtered_login_url"}, wantSource: "native", wantReason: "login_route_mismatch"},
		{name: "healthy panel route", loginURL: "https://example.com/zang", matchingBridge: true, wantSource: "panel", wantSSO: true},
		{name: "known hiding plugin retains control", loginURL: "https://example.com/wp-login.php", conflicts: []string{"wps-hide-login", "filtered_login_url"}, matchingBridge: true, wantSource: "plugin", wantReason: "external_login_control", wantExternal: true},
		{name: "login URL hook retains control", loginURL: "https://example.com/wp-login.php", conflicts: []string{"login_url_filter", "filtered_login_url"}, matchingBridge: true, wantSource: "plugin", wantReason: "external_login_control", wantExternal: true},
		{name: "external custom route retains control", loginURL: "https://example.com/hidden-entry", conflicts: []string{"filtered_login_url"}, matchingBridge: true, wantSource: "plugin", wantReason: "external_login_control", wantExternal: true},
		{name: "native query retains control", loginURL: "https://example.com/wp-login.php?reauth=1", conflicts: []string{"filtered_login_url"}, matchingBridge: true, wantSource: "plugin", wantReason: "external_login_control", wantExternal: true},
		{name: "native empty query is not exact", loginURL: "https://example.com/wp-login.php?", conflicts: []string{"filtered_login_url"}, matchingBridge: true, wantSource: "plugin", wantReason: "external_login_control", wantExternal: true},
		{name: "encoded native path is not exact", loginURL: "https://example.com/wp-%6cogin.php", conflicts: []string{"filtered_login_url"}, matchingBridge: true, wantSource: "plugin", wantReason: "external_login_control", wantExternal: true},
		{name: "native trailing slash is not exact", loginURL: "https://example.com/wp-login.php/", conflicts: []string{"filtered_login_url"}, matchingBridge: true, wantSource: "plugin", wantReason: "external_login_control", wantExternal: true},
		{name: "cleared suffix and disabled SSO recover native status", loginURL: "https://example.com/wp-login.php", clearSuffix: true, disableSSO: true, wantSource: "native", wantReason: "sso_disabled"},
		{name: "cleared suffix with healthy SSO bridge", loginURL: "https://example.com/wp-login.php", clearSuffix: true, matchingBridge: true, wantSource: "native", wantSSO: true},
		{name: "authentication plugin remains blocked", loginURL: "https://example.com/zang", authentication: []string{"two-factor"}, matchingBridge: true, wantSource: "panel", wantReason: "authentication_plugin"},
		{name: "route mismatch retains authentication evidence", loginURL: "https://example.com/wp-login.php", conflicts: []string{"filtered_login_url"}, authentication: []string{"two-factor"}, matchingBridge: true, wantSource: "native", wantReason: "login_route_mismatch"},
		{name: "off-site native path remains invalid", loginURL: "https://evil.test/wp-login.php", conflicts: []string{"filtered_login_url"}, wantError: "invalid_login_url"},
		{name: "insecure native URL remains invalid", loginURL: "http://example.com/wp-login.php", conflicts: []string{"filtered_login_url"}, wantError: "invalid_login_url"},
		{name: "native outside installation remains invalid", path: "/wp", loginURL: "https://example.com/wp-login.php", conflicts: []string{"filtered_login_url"}, wantError: "invalid_login_url"},
	} {
		t.Run(test.name, func(t *testing.T) {
			oldConfig, oldPHP, oldReadSettings := config.AppConfig, wpPanelAccessInspectPHP, wpPanelAccessReadSettings
			oldBrokerReady := wpPanelAccessBrokerReady.Load()
			t.Cleanup(func() {
				config.AppConfig, wpPanelAccessInspectPHP, wpPanelAccessReadSettings = oldConfig, oldPHP, oldReadSettings
				wpPanelAccessBrokerReady.Store(oldBrokerReady)
			})
			config.AppConfig = &config.Config{}
			wpPanelAccessBrokerReady.Store(true)
			site := &models.Website{ID: 8, Domain: "example.com", SiteType: "wordpress", Status: models.StatusActive, SSLEnabled: true, WebRoot: t.TempDir()}
			settings := WPPanelAccessSettings{Domain: site.Domain, InstallationPath: test.path, LoginSuffix: "zang", SSOEnabled: !test.disableSSO, Generation: strings.Repeat("a", 32)}
			if test.clearSuffix {
				settings.LoginSuffix = ""
			}
			// Keep root-only settings ownership and Linux PHP execution outside this
			// inspection test. The probe classification and MU file match are real.
			wpPanelAccessReadSettings = func(*models.Website) (WPPanelAccessSettings, error) { return settings, nil }
			probe := wpPanelAccessProbe{Installed: true, SiteURL: "https://example.com" + test.path, LoginURL: test.loginURL, ConflictingPlugins: test.conflicts, AuthenticationPlugins: test.authentication, PermalinksEnabled: true, CurlUnixAvailable: true}
			probe.Administrators = append(probe.Administrators, struct {
				ID          int    `json:"id"`
				Login       string `json:"login"`
				DisplayName string `json:"display_name"`
				Proof       string `json:"proof"`
			}{ID: 7, Login: "site-admin", DisplayName: "Admin", Proof: strings.Repeat("e", 64)})
			wpPanelAccessInspectPHP = func(_ context.Context, _ *models.Website, _ WPPanelAccessSettings, _, _ string, target *wpPanelAccessProbe) error {
				*target = probe
				return nil
			}
			if test.matchingBridge {
				dir := filepath.Join(site.WebRoot, "wp-content", "mu-plugins")
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, wpPanelAccessPluginFile), []byte(renderWPPanelAccessPlugin(site.ID, settings)), 0644); err != nil {
					t.Fatal(err)
				}
			}
			result, err := InspectWPPanelAccess(context.Background(), site)
			if test.wantError != "" {
				if WPPanelAccessErrorCode(err) != test.wantError {
					t.Fatalf("error=%v want=%s", err, test.wantError)
				}
				return
			}
			if err != nil || result.LoginSource != test.wantSource || result.ReasonCode != test.wantReason || result.ExternalLoginControl != test.wantExternal || result.SSOAvailable != test.wantSSO || result.BridgeInstalled != test.matchingBridge {
				t.Fatalf("status=%+v err=%v", result, err)
			}
			if result.LoginURL != test.loginURL || result.LoginSuffix != settings.LoginSuffix || result.SSOEnabled != settings.SSOEnabled || !reflect.DeepEqual(result.AuthenticationPlugins, append([]string{}, test.authentication...)) {
				t.Fatalf("inspection changed saved settings, actual URL or authentication evidence: %+v", result)
			}
			if test.wantExternal && !reflect.DeepEqual(result.ConflictingPlugins, test.conflicts) || test.wantReason == "login_route_mismatch" && len(result.ConflictingPlugins) != 0 {
				t.Fatalf("unexpected login control evidence: %v", result.ConflictingPlugins)
			}
		})
	}
}
