package executor

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"strings"
)

//go:embed wp_panel_access_plugin.php
var wpPanelAccessPluginSource string

//go:embed wp_panel_access_guards.php
var wpPanelAccessGuardsSource string

func renderWPPanelAccessPlugin(siteID int, settings WPPanelAccessSettings) string {
	data, _ := json.Marshal(struct {
		SiteID           int    `json:"site_id"`
		Domain           string `json:"domain"`
		InstallationPath string `json:"installation_path"`
		LoginSuffix      string `json:"login_suffix"`
		SSOEnabled       bool   `json:"sso_enabled"`
		Generation       string `json:"generation"`
		Socket           string `json:"socket"`
	}{siteID, settings.Domain, settings.InstallationPath, settings.LoginSuffix, settings.SSOEnabled, settings.Generation, WPPanelAccessSocketPath})
	// Only JSON data is substituted. Site fields are never interpolated as PHP.
	header := "<?php\n// " + wpPanelAccessPluginMarker + "\nif (!defined('ABSPATH')) exit;\n$ols_wpanel_access_config = json_decode(base64_decode('" + base64.StdEncoding.EncodeToString(data) + "'), true);\n"
	return header + strings.TrimPrefix(wpPanelAccessGuardsSource, "<?php") + "\n" + strings.TrimPrefix(wpPanelAccessPluginSource, "<?php")
}
