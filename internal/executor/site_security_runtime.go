package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// This is an isolated core-policy observation, not evidence that a web request
// with third-party plugins has enforced the policy. No inventory bypass marker
// is defined: the panel's actual wp-config policy must execute during bootstrap.
const siteSecurityCorePHP = `
$input = json_decode(stream_get_contents(STDIN), true, 8, JSON_THROW_ON_ERROR);
if (PHP_SAPI !== 'cli' || !is_array($input) || !preg_match('/^[0-9a-f]{32}$/', $input['token'] ?? '')) exit(2);
$protocol = fopen('php://fd/3', 'wb');
if (!is_resource($protocol)) exit(2);
$root = realpath($input['root'] ?? '');
if (!is_string($root) || !is_file($root . '/wp-load.php') || is_link($root . '/wp-load.php')) exit(2);
ob_start(static function($output) { return ''; }, 1);
define('WP_USE_THEMES', false);
define('DISABLE_WP_CRON', true);
define('WP_INSTALLING', true);
define('WP_HTTP_BLOCK_EXTERNAL', true);
// A unique, nonexistent content directory prevents loading plugins, MU plugins,
// themes and database/cache drop-ins. No directory or website file is created.
$empty = $root . '/.ols-wpanel-security-isolation-' . $input['token'];
if (file_exists($empty)) exit(2);
define('WP_CONTENT_DIR', $empty);
define('WP_PLUGIN_DIR', $empty . '/plugins');
define('WPMU_PLUGIN_DIR', $empty . '/mu-plugins');
$GLOBALS['wp_filter']['enable_loading_advanced_cache_dropin'][PHP_INT_MAX][] = ['function'=>static function() { return false; }, 'accepted_args'=>1];
$GLOBALS['wp_filter']['enable_loading_object_cache_dropin'][PHP_INT_MAX][] = ['function'=>static function() { return false; }, 'accepted_args'=>1];
$GLOBALS['wp_filter']['pre_http_request'][PHP_INT_MAX][] = ['function'=>static function() { return new WP_Error('ols_wpanel_security_readonly'); }, 'accepted_args'=>3];
$GLOBALS['wp_filter']['query'][PHP_INT_MAX][] = ['function'=>static function($sql) {
 if (!is_string($sql) || !preg_match('/^\s*(SELECT|SHOW|DESCRIBE)\b/i', $sql) || preg_match('/\bINTO\s+(OUTFILE|DUMPFILE)\b/i', $sql)) return 'SELECT 0';
 return $sql;
}, 'accepted_args'=>1];
$_SERVER['HTTP_HOST'] = $input['domain'];
$_SERVER['SERVER_NAME'] = $input['domain'];
$_SERVER['REQUEST_METHOD'] = 'HEAD';
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['HTTPS'] = 'on';
try {
 require $root . '/wp-load.php';
 if (!function_exists('apply_filters') || !function_exists('map_meta_cap') || !function_exists('has_action') || !function_exists('get_site_transient')) exit(3);
 // Test the restriction with a true seed so lack of HTTPS support cannot
 // accidentally appear to prove the application-password filter is installed.
 $appDisabled = apply_filters('wp_is_application_passwords_available', true) === false;
 $editorDisabled = defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT === true
  && in_array('do_not_allow', map_meta_cap('edit_themes', 0), true)
  && in_array('do_not_allow', map_meta_cap('edit_plugins', 0), true);
 // DISALLOW_FILE_MODS restricts installation; update-discovery hooks can remain active.
 $updates = has_action('init', 'wp_schedule_update_checks') !== false
  && has_action('wp_version_check', 'wp_version_check') !== false
  && has_action('wp_update_plugins', 'wp_update_plugins') !== false
  && has_action('wp_update_themes', 'wp_update_themes') !== false;
 foreach (['update_core', 'update_plugins', 'update_themes'] as $name) {
  if (apply_filters('pre_site_transient_' . $name, false) !== false) $updates = false;
 }
 $checks = ['application_passwords'=>$appDisabled, 'file_editing'=>$editorDisabled,
  'debug_display'=>defined('WP_DEBUG_DISPLAY') && WP_DEBUG_DISPLAY === false,
  'wp_updates'=>$updates];
 $data = ['token'=>$input['token'], 'ok'=>true, 'uid'=>function_exists('posix_geteuid') ? posix_geteuid() : -1,
  'gid'=>function_exists('posix_getegid') ? posix_getegid() : -1, 'root'=>$root,
  'open_basedir'=>(string)ini_get('open_basedir'), 'checks'=>$checks];
 fwrite($protocol, json_encode($data, JSON_THROW_ON_ERROR));
 fflush($protocol);
} catch (Throwable $error) { exit(3); }
`

type siteSecurityCoreEnvelope struct {
	Token       string          `json:"token"`
	OK          bool            `json:"ok"`
	UID         int             `json:"uid"`
	GID         int             `json:"gid"`
	Root        string          `json:"root"`
	OpenBaseDir string          `json:"open_basedir"`
	Checks      map[string]bool `json:"checks"`
}

func runSiteSecurityCorePolicy(ctx context.Context, site *models.Website) (map[string]bool, error) {
	if err := wpInventoryPlatformSupported(); err != nil || wpInventoryEffectiveUID() != 0 {
		return nil, errors.New("core runtime platform unavailable")
	}
	runner, err := NewWPInventoryRunner()
	if err != nil {
		return nil, err
	}
	input, err := runner.validateInputs(config.AppConfig, site)
	if err != nil {
		return nil, err
	}
	execCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := acquireInventorySlot(execCtx); err != nil {
		return nil, err
	}
	defer releaseInventorySlot()
	token, err := randomInventoryToken()
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]string{"root": input.siteRoot, "domain": input.domain, "token": token})
	if err != nil {
		return nil, err
	}
	openBaseDir := input.siteRoot + ":/tmp:/usr/share/php"
	disabled := sitePHPDisabledFunctions() + ",curl_exec,curl_multi_exec,fsockopen,pfsockopen,stream_socket_client"
	args := []string{"-u", input.user.Name, "--", input.phpPath, "-d", "open_basedir=" + openBaseDir, "-d", "disable_functions=" + disabled, "-d", "allow_url_include=0", "-d", "allow_url_fopen=0", "-d", "display_errors=0", "-d", "memory_limit=256M", "-d", "max_execution_time=8", "-r", siteSecurityCorePHP}
	cmd := exec.CommandContext(execCtx, input.runuser, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=" + input.user.HomeDir, "USER=" + input.user.Name, "LOGNAME=" + input.user.Name, "TMPDIR=/tmp"}
	cmd.Dir = input.siteRoot
	cmd.Stdin = bytes.NewReader(payload)
	stdout, stderr, protocol := newCountingSink(64<<10, false), newCountingSink(64<<10, false), newCountingSink(64<<10, true)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer readPipe.Close()
	cmd.ExtraFiles = []*os.File{writePipe}
	wpInventoryConfigureCommand(cmd)
	if err := cmd.Start(); err != nil {
		writePipe.Close()
		return nil, errors.New("core runtime start failed")
	}
	_ = writePipe.Close()
	done := make(chan error, 1)
	go func() { _, err := io.Copy(protocol, readPipe); done <- err }()
	waitErr := cmd.Wait()
	copyErr := <-done
	if execCtx.Err() != nil {
		return nil, errors.New("core runtime timed out")
	}
	_, stdoutExceeded, _ := stdout.snapshot()
	_, stderrExceeded, _ := stderr.snapshot()
	_, protocolExceeded, raw := protocol.snapshot()
	if waitErr != nil || copyErr != nil || stdoutExceeded || stderrExceeded || protocolExceeded {
		return nil, errors.New("core runtime output unavailable")
	}
	var envelope siteSecurityCoreEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || !envelope.OK || envelope.Token != token || envelope.UID != input.user.UID || envelope.GID != input.user.GID || filepath.Clean(envelope.Root) != input.siteRoot || envelope.OpenBaseDir != openBaseDir {
		return nil, errors.New("core runtime identity mismatch")
	}
	if len(envelope.Checks) != 4 {
		return nil, errors.New("core runtime checks incomplete")
	}
	for _, key := range []string{"application_passwords", "file_editing", "debug_display", "wp_updates"} {
		if _, ok := envelope.Checks[key]; !ok {
			return nil, errors.New("core runtime checks incomplete")
		}
	}
	return envelope.Checks, nil
}
