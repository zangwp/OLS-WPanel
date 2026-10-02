package executor

import (
	"regexp"
	"strings"
)

var nativePolicyBlock = regexp.MustCompile(`(?s)/\* OLS-WPANEL-POLICY-BEGIN \*/.*?/\* OLS-WPANEL-POLICY-END \*/\r?\n?`)

// WordPress builds these preinitialized hooks when loading its core plugin API.
// This block has no HTTP calls, settings page, background jobs or extra plugin.
func renderWPNativePolicy(content string, noUpdates, noApplicationPasswords bool) string {
	content = nativePolicyBlock.ReplaceAllString(content, "")
	if !noUpdates && !noApplicationPasswords {
		return content
	}
	var body strings.Builder
	body.WriteString("/* OLS-WPANEL-POLICY-BEGIN */\n")
	body.WriteString("if (!(PHP_SAPI === 'cli' && defined('OLS_WPANEL_INVENTORY_RUNNER'))) {\n")
	if noApplicationPasswords {
		body.WriteString("$GLOBALS['wp_filter']['wp_is_application_passwords_available'][PHP_INT_MAX][] = array('function' => '__return_false', 'accepted_args' => 1);\n")
	}
	if noUpdates {
		body.WriteString(`if (!function_exists('ols_wpanel_policy_no_updates')) {
 function ols_wpanel_policy_no_updates() { return null; }
 function ols_wpanel_policy_disable_checks() {
  remove_action('init', 'wp_schedule_update_checks');
  foreach (array('wp_version_check', 'wp_update_plugins', 'wp_update_themes') as $hook) remove_action($hook, $hook);
  foreach (array('_maybe_update_core', '_maybe_update_plugins', '_maybe_update_themes') as $callback) remove_action('admin_init', $callback);
  remove_action('load-plugins.php', 'wp_update_plugins');
  remove_action('load-update.php', 'wp_update_plugins');
  remove_action('load-themes.php', 'wp_update_themes');
  remove_action('load-update-core.php', 'wp_update_plugins');
  remove_action('load-update-core.php', 'wp_update_themes');
  remove_action('admin_notices', 'update_nag', 3);
  remove_action('network_admin_notices', 'update_nag', 3);
 }
}
$GLOBALS['wp_filter']['plugins_loaded'][PHP_INT_MAX][] = array('function' => 'ols_wpanel_policy_disable_checks', 'accepted_args' => 0);
foreach (array('update_core', 'update_plugins', 'update_themes') as $name) {
 $GLOBALS['wp_filter']['pre_site_transient_' . $name][PHP_INT_MAX][] = array('function' => 'ols_wpanel_policy_no_updates', 'accepted_args' => 1);
}
`)
	}
	body.WriteString("}\n/* OLS-WPANEL-POLICY-END */\n")
	return insertBeforeMarker(content, body.String())
}
