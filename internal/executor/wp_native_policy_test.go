package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeWordPressPolicyTransitions(t *testing.T) {
	original := "<?php\n// custom settings\n/* That's all, stop editing! Happy publishing. */\n"
	enabled := renderWPNativePolicy(original, true, true)
	if got := renderWPNativePolicy(enabled, true, true); got != enabled {
		t.Fatal("policy is not idempotent")
	}
	if got := renderWPNativePolicy(enabled, false, false); got != original {
		t.Fatal("disabling policy changed unrelated configuration")
	}
	applicationOnly := renderWPNativePolicy(enabled, false, true)
	if !strings.Contains(applicationOnly, "wp_is_application_passwords_available") || strings.Contains(applicationOnly, "pre_site_transient_") {
		t.Fatal("policy controls are not independent")
	}
}

func TestNativeWordPressPolicyRegistersWithoutPlugin(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("PHP CLI unavailable")
	}
	root := t.TempDir()
	path := filepath.Join(root, "config.php")
	if err := os.WriteFile(path, []byte(renderWPNativePolicy("<?php\n", true, true)), 0600); err != nil {
		t.Fatal(err)
	}
	// Exercise the actual generated configuration before WordPress initializes hooks.
	harness := `require $argv[1];
 if (($GLOBALS['wp_filter']['wp_is_application_passwords_available'][PHP_INT_MAX][0]['function'] ?? '') !== '__return_false') exit(1);
 foreach (['update_core','update_plugins','update_themes'] as $name) {
  $fn=$GLOBALS['wp_filter']['pre_site_transient_'.$name][PHP_INT_MAX][0]['function'] ?? '';
  if (!is_callable($fn) || $fn() !== null) exit(2);
 }
 $removed=[];
 function remove_action($hook,$callback,$priority=10){$GLOBALS['removed'][]=$hook.':'.$callback;}
 ols_wpanel_policy_disable_checks();
 if (!in_array('init:wp_schedule_update_checks',$removed,true) || !in_array('admin_init:_maybe_update_plugins',$removed,true)) exit(3);
 echo 'policy ok';`
	output, err := exec.Command(php, "-r", harness, path).CombinedOutput()
	if err != nil || string(output) != "policy ok" {
		t.Fatal(string(output), err)
	}
}

func TestSiteSecurityCoreProbeDistinguishesUpdateDiscoveryFromFileProtection(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("PHP CLI unavailable")
	}
	for _, tc := range []struct {
		name, missingHook, suppressedTransient string
		disableUpdates, want                   bool
	}{
		{name: "locked with discovery hooks", want: true},
		{name: "explicitly disabled", disableUpdates: true},
		{name: "missing scheduler", missingHook: "init"},
		{name: "missing core check", missingHook: "wp_version_check"},
		{name: "missing plugin check", missingHook: "wp_update_plugins"},
		{name: "missing theme check", missingHook: "wp_update_themes"},
		{name: "core transient suppressed", suppressedTransient: "update_core"},
		{name: "plugin transient suppressed", suppressedTransient: "update_plugins"},
		{name: "theme transient suppressed", suppressedTransient: "update_themes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			policy := renderWPNativePolicy("<?php\ndefine('DISALLOW_FILE_MODS', true);\ndefine('DISALLOW_FILE_EDIT', true);\ndefine('WP_DEBUG_DISPLAY', false);\n", tc.disableUpdates, true)
			// Execute the actual probe and generated policy. Only the WordPress
			// hook/bootstrap API is a fixture; it exposes independently missing
			// hooks and suppressed transients without running update downloads.
			bootstrap := `<?php
require __DIR__.'/wp-config.php';
$actions=['init'=>['wp_schedule_update_checks'], 'wp_version_check'=>['wp_version_check'], 'wp_update_plugins'=>['wp_update_plugins'], 'wp_update_themes'=>['wp_update_themes']];
function has_action($hook,$callback) { return in_array($callback,$GLOBALS['actions'][$hook]??[],true) ? 10 : false; }
function remove_action($hook,$callback,$priority=10) { $GLOBALS['actions'][$hook]=array_values(array_diff($GLOBALS['actions'][$hook]??[],[$callback])); }
function apply_filters($hook,$value) {
 foreach ($GLOBALS['wp_filter'][$hook]??[] as $entries) foreach ($entries as $entry) $value=($entry['function'])($value);
 return $value;
}
function map_meta_cap($cap,$user) { return ['do_not_allow']; }
function get_site_transient($key) { return false; }
function __return_false() { return false; }
foreach ($GLOBALS['wp_filter']['plugins_loaded']??[] as $entries) foreach ($entries as $entry) ($entry['function'])();
`
			missing, _ := json.Marshal(tc.missingHook)
			suppressed, _ := json.Marshal("pre_site_transient_" + tc.suppressedTransient)
			if tc.missingHook != "" {
				bootstrap += "unset($actions[" + string(missing) + "]);\n"
			}
			if tc.suppressedTransient != "" {
				bootstrap += "$GLOBALS['wp_filter'][" + string(suppressed) + "][PHP_INT_MAX][]=['function'=>static function(){return null;},'accepted_args'=>1];\n"
			}
			for name, content := range map[string]string{"wp-config.php": policy, "wp-load.php": bootstrap} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			input, err := json.Marshal(map[string]string{"root": filepath.ToSlash(root), "domain": "site.example.com", "token": strings.Repeat("a", 32)})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			// Adapt only the output descriptor for this standalone PHP fixture,
			// including Windows PHP where php://fd/3 is unsupported.
			command := exec.CommandContext(ctx, php, "-n", "-d", "display_errors=0", "-r", strings.Replace(siteSecurityCorePHP, "php://fd/3", "php://stdout", 1))
			command.Stdin = bytes.NewReader(input)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("core probe failed: %v\n%s", err, output)
			}
			var envelope struct {
				OK     bool            `json:"ok"`
				Checks map[string]bool `json:"checks"`
			}
			if err := json.Unmarshal(output, &envelope); err != nil || !envelope.OK {
				t.Fatalf("invalid core probe response: %v\n%s", err, output)
			}
			if got, present := envelope.Checks["wp_updates"]; !present || got != tc.want {
				t.Fatalf("update-discovery observation=%v present=%v want=%v", got, present, tc.want)
			}
			if content, err := os.ReadFile(filepath.Join(root, "wp-config.php")); err != nil || string(content) != policy {
				t.Fatalf("core probe changed file protection policy: %v", err)
			}
		})
	}
}
