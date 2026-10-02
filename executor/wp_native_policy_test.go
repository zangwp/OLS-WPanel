package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
