package executor

import (
	"context"
	"reflect"
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
