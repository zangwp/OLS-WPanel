package executor

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWPPanelAccessGeneratedPHPParses(t *testing.T) {
	php := wpPanelAccessTestPHP(t)
	for name, source := range map[string]string{"plugin.php": renderWPPanelAccessPlugin(8, WPPanelAccessSettings{Domain: "example.com", InstallationPath: "/wp", LoginSuffix: "staff-signin", SSOEnabled: true, Generation: strings.Repeat("a", 32)}), "inspector.php": "<?php\n" + strings.TrimPrefix(wpPanelAccessGuardsSource, "<?php") + strings.TrimPrefix(wpPanelAccessInspectorSource, "<?php")} {
		file := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(file, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(php, "-l", file).CombinedOutput(); err != nil {
			t.Fatalf("generated %s: %v: %s", name, err, output)
		}
	}
}

func TestWPPanelAccessAuthenticationCacheObserversRemainNarrow(t *testing.T) {
	php := wpPanelAccessTestPHP(t)
	for _, mode := range []string{"cache", "foreign_source"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "guards.php"), []byte(wpPanelAccessGuardsSource), 0600); err != nil {
				t.Fatal(err)
			}
			fixture := `<?php
define('WP_PLUGIN_DIR', __DIR__ . '/plugins');
$options = ['active_plugins' => ['litespeed-cache/litespeed-cache.php']];
$wp_filter = [];
function get_option($key, $default=null) { return $GLOBALS['options'][$key] ?? $default; }
function observe($hook, $callback) { $GLOBALS['wp_filter'][$hook] = (object)['callbacks'=>[10=>[['function'=>$callback]]]]; }
function check($condition, $message) { if (!$condition) throw new RuntimeException($message); }
require __DIR__ . '/guards.php';
$definitions = [
 'tag.cls.php' => 'class Tag { public function check_login_cacheable() { throw new \\RuntimeException("callback must not run"); } public function authenticate() {} }',
 'purge.cls.php' => 'class Purge { public static function purge_on_logout() { throw new \\RuntimeException("callback must not run"); } }',
 'vary.cls.php' => 'class Vary { public function add_logged_in() { throw new \\RuntimeException("callback must not run"); } }',
];
$source_dir = WP_PLUGIN_DIR . ($argv[1] === 'cache' ? '/litespeed-cache/src' : '/another-plugin');
mkdir(WP_PLUGIN_DIR . '/litespeed-cache/src', 0700, true);
if (!is_dir($source_dir)) mkdir($source_dir, 0700, true);
foreach ($definitions as $filename => $definition) {
 // Even a same-named class must not be trusted from another plugin's file.
 file_put_contents(WP_PLUGIN_DIR . '/litespeed-cache/src/' . $filename, '<?php');
 file_put_contents($source_dir . '/' . $filename, '<?php namespace LiteSpeed; ' . $definition);
 require $source_dir . '/' . $filename;
}
$cache = [
 'login_init' => [new LiteSpeed\Tag(), 'check_login_cacheable'],
 'wp_login' => 'LiteSpeed\Purge::purge_on_logout',
 'set_logged_in_cookie' => [new LiteSpeed\Vary(), 'add_logged_in'],
];
foreach ($cache as $hook => $callback) observe($hook, $callback);
$expected = $argv[1] === 'cache' ? [] : ['login_init_filter', 'wp_login_filter', 'set_logged_in_cookie_filter'];
check(ols_wpanel_access_authentication_conflicts() === $expected, 'cache callback classification');
if ($argv[1] === 'foreign_source') exit(0);
$before = serialize($wp_filter);
check(ols_wpanel_access_authentication_conflicts() === [], 'repeat inspection');
check(serialize($wp_filter) === $before, 'inspection removed or replaced hooks');
// Every monitored hook still rejects an unknown MFA callback alongside cache.
foreach (['authenticate', 'wp_authenticate_user', 'determine_current_user', 'wp_authenticate', 'login_init', 'wp_login', 'send_auth_cookies', 'set_auth_cookie', 'set_logged_in_cookie'] as $hook) {
 $wp_filter = unserialize($before);
 if (!isset($wp_filter[$hook])) $wp_filter[$hook] = (object)['callbacks'=>[]];
 $wp_filter[$hook]->callbacks[20][] = ['function'=>function() {}];
 check(ols_wpanel_access_authentication_conflicts() === [$hook . '_filter'], 'unknown auth hook bypassed: ' . $hook);
}
$wp_filter = unserialize($before);
$options['active_plugins'][] = 'two-factor/two-factor.php';
check(ols_wpanel_access_authentication_conflicts() === ['two-factor'], 'known MFA plugin bypassed');
$options['active_plugins'] = [];
check(ols_wpanel_access_authentication_conflicts() === ['login_init_filter', 'wp_login_filter', 'set_logged_in_cookie_filter'], 'inactive cache plugin trusted');
$options['active_plugins'] = ['litespeed-cache/litespeed-cache.php'];
check(!ols_wpanel_access_cache_observer('authenticate', $cache['set_logged_in_cookie']), 'cache method trusted on auth hook');
check(!ols_wpanel_access_cache_observer('login_init', [new LiteSpeed\Tag(), 'authenticate']), 'unknown cache method trusted');
check(!ols_wpanel_access_cache_observer('login_init', ['LiteSpeed\Tag', 'check_login_cacheable']), 'invalid static method trusted');
eval('namespace LiteSpeed; class ChildTag extends Tag {}');
check(!ols_wpanel_access_cache_observer('login_init', [new LiteSpeed\ChildTag(), 'check_login_cacheable']), 'subclass trusted');
foreach ([null, [], ['unknown'], ['class'=>'LiteSpeed\Tag','method'=>'check_login_cacheable'], function() {}] as $bad) {
 check(!ols_wpanel_access_cache_observer('login_init', $bad), 'unknown callback representation trusted');
}
echo "cache observers and authentication guards verified\n";
`
			file := filepath.Join(dir, "test.php")
			if err := os.WriteFile(file, []byte(fixture), 0600); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command(php, "-n", file, mode).CombinedOutput(); err != nil {
				t.Fatalf("authentication observer checks: %v: %s", err, output)
			}
		})
	}
}

// The real generated plugin runs through PHP's HTTP server. Only WordPress core
// APIs are fixture stubs; the plugin route, URL filters and refusal paths remain
// exactly the embedded production source, including the non-CLI request guard.
func TestWPPanelAccessPluginRoutesAndPreservesOtherLoginPlugins(t *testing.T) {
	php := wpPanelAccessTestPHP(t)
	dir := t.TempDir()
	settings := WPPanelAccessSettings{Domain: "example.com", InstallationPath: "/wp", LoginSuffix: "staff-signin", SSOEnabled: true, Generation: strings.Repeat("a", 32)}
	if err := os.WriteFile(filepath.Join(dir, "access.php"), []byte(renderWPPanelAccessPlugin(8, settings)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wp-login.php"), []byte("<?php echo 'NATIVE_LOGIN:' . ($GLOBALS['pagenow'] ?? '');"), 0600); err != nil {
		t.Fatal(err)
	}
	fixture := `<?php
define('ABSPATH', __DIR__ . '/');
$wp_filter = [];
function get_option($key, $default=null) { if ($key==='siteurl'||$key==='home') return 'https://example.com/wp'; if($key==='rewrite_rules')return ['^api-entry/?$'=>'index.php?plugin_endpoint=1','^([^/]+)/?$'=>'index.php?pagename=$matches[1]']; if ($key==='active_plugins') return isset($_GET['hidden']) ? ['wps-hide-login/wps-hide-login.php'] : []; return $default; }
function is_blog_installed(){return !isset($_GET['uninstalled']);} function is_multisite(){return false;} function wp_installing(){return false;}
function wp_parse_url($url,$component=-1){return parse_url($url,$component);} function is_ssl(){return !empty($_SERVER['HTTP_X_FIXTURE_TLS']);}
function add_query_arg($key,$value,$url){return $url . (strpos($url,'?')===false ? '?' : '&') . rawurlencode($key) . '=' . rawurlencode($value);}
function add_filter($hook,$fn,$priority=10,$args=1){global $wp_filter;if(!isset($wp_filter[$hook]))$wp_filter[$hook]=(object)['callbacks'=>[]];$wp_filter[$hook]->callbacks[$priority][]=['function'=>$fn,'args'=>$args];}
function add_action($hook,$fn,$priority=10){add_filter($hook,$fn,$priority);}
function apply_filters($hook,$value,...$args){global $wp_filter;if(!isset($wp_filter[$hook]))return $value;$callbacks=$wp_filter[$hook]->callbacks;ksort($callbacks);foreach($callbacks as $group)foreach($group as $callback){$value=call_user_func_array($callback['function'],array_slice(array_merge([$value],$args),0,$callback['args']));}return $value;}
function wp_login_url($redirect='',$force=false){$url=apply_filters('site_url','https://example.com/wp/wp-login.php','wp-login.php','login',null);return apply_filters('login_url',$url,$redirect,$force);}
function nocache_headers(){header('Cache-Control: no-store');}function status_header($code){http_response_code($code);}
function esc_html__($s){return $s;}function wp_die($s,$title='',$args=[]){http_response_code($args['response']??500);echo 'DENIED';exit;}
function fixture_hidden($url,$path){return strpos($path,'wp-login.php')===0?'https://example.com/wp/hidden-entry':$url;}
function get_userdata($id){if(isset($_GET['deleted']))return false;return(object)['ID'=>$id,'roles'=>isset($_GET['nonadmin'])?['subscriber']:['administrator'],'user_login'=>'site-admin','user_registered'=>'2024-01-01','user_pass'=>isset($_GET['changed'])?'new-password-hash':'old-password-hash'];}
function admin_url(){return isset($_GET['offsite'])?'https://evil.test/wp/wp-admin/':'https://example.com/wp/wp-admin/';}
function wp_clear_auth_cookie(){} function wp_set_current_user($id){} function wp_set_auth_cookie($id,$remember,$secure){setcookie('wordpress_fixture','authorized-'.$id,['path'=>'/wp/','secure'=>$secure,'httponly'=>true,'samesite'=>'Lax']);}
function wp_safe_redirect($url,$status){header('Location: '.$url,true,$status);}function do_action($hook,...$args){}
// The Unix transport is a fixture; all plugin-side role/proof/host checks and
// WordPress cookie/redirect calls below remain the production PHP source.
foreach(['CURLOPT_UNIX_SOCKET_PATH','CURLOPT_PROXY','CURLOPT_POST','CURLOPT_POSTFIELDS','CURLOPT_HTTPHEADER','CURLOPT_RETURNTRANSFER','CURLOPT_FOLLOWLOCATION','CURLOPT_CONNECTTIMEOUT','CURLOPT_TIMEOUT','CURLOPT_WRITEFUNCTION','CURLINFO_HTTP_CODE'] as $index=>$name)if(!defined($name))define($name,$index+100);
function curl_init($url){return $url;}function curl_setopt_array($ch,$options){$GLOBALS['fixture_curl']=$options;}
function curl_exec($ch){$options=$GLOBALS['fixture_curl'];$request=json_decode($options[CURLOPT_POSTFIELDS],true);$old=(object)['ID'=>7,'user_login'=>'site-admin','user_registered'=>'2024-01-01','user_pass'=>'old-password-hash'];$data=['administrator_id'=>7,'administrator_login'=>'site-admin','administrator_proof'=>ols_wpanel_access_administrator_proof($old),'domain'=>'example.com','installation_path'=>'/wp','generation'=>$request['generation']];$options[CURLOPT_WRITEFUNCTION]($ch,json_encode(['success'=>true,'data'=>$data]));return true;}
function curl_getinfo($ch,$flag){return 200;}function curl_close($ch){}
define('OBJECT','OBJECT');function url_to_postid($url){return strpos($url,'/about')!==false?42:0;}function get_post_types($args,$output){return ['post','page'];}function get_page_by_path($slug,$type,$post_types){return $slug==='contact'?(object)['ID'=>43]:null;}
require __DIR__ . '/access.php';
// Actual WordPress default-filters.php registers these core login_init hooks.
// They set response security headers and are not third-party MFA guards.
add_action('login_init','send_frame_options_header');
add_action('login_init','wp_admin_headers');
if(isset($_GET['hidden']))add_filter('site_url','fixture_hidden',10,2);
if(isset($_GET['mfa']))add_filter('authenticate','fixture_mfa');
if(isset($_GET['mfa_action']))add_action('wp_authenticate','fixture_mfa_action');
ols_wpanel_access_dispatch();
header('Content-Type: application/json');echo json_encode(['login_url'=>wp_login_url(),'conflicts'=>ols_wpanel_access_login_conflicts(ols_wpanel_access_expected_login(),wp_login_url()),'suffix_conflict'=>isset($_GET['candidate'])?ols_wpanel_access_suffix_conflict($_GET['candidate']):false]);
`
	router := filepath.Join(dir, "router.php")
	if err := os.WriteFile(router, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, php, "-n", "-S", address, router)
	serverLog, err := os.Create(filepath.Join(dir, "php-server.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer serverLog.Close()
	cmd.Stdout, cmd.Stderr = io.Discard, serverLog
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { cancel(); <-done })
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := "http://" + address
	ready := false
	var lastConnectionError error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(base + "/")
		lastConnectionError = err
		if err == nil {
			response.Body.Close()
			ready = true
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !ready {
		output, _ := os.ReadFile(serverLog.Name())
		t.Fatalf("PHP fixture server did not start: %v; %s", lastConnectionError, output)
	}
	for _, test := range []struct {
		path, method, body string
		tls                bool
		status             int
		contains           string
	}{
		{"/wp/index.php", "GET", "", false, 200, `"login_url":"https:\/\/example.com\/wp\/staff-signin"`},
		{"/wp/staff-signin", "GET", "", false, 200, "NATIVE_LOGIN:wp-login.php"},
		{"/wp/wp-login.php", "GET", "", false, 404, ""},
		{"/wp/index.php?hidden=1", "GET", "", false, 200, `"login_url":"https:\/\/example.com\/wp\/hidden-entry"`},
		{"/wp/staff-signin?hidden=1", "GET", "", false, 200, "hidden-entry"},
		{"/wp/wp-login.php?uninstalled=1", "GET", "", false, 200, "wp-login.php"},
		{"/wp/index.php", "POST", "ols_wpanel_access_token=" + strings.Repeat("a", 43) + "&ols_wpanel_access_generation=" + settings.Generation, false, 403, "DENIED"},
		{"/wp/index.php?hidden=1", "POST", "ols_wpanel_access_token=" + strings.Repeat("a", 43) + "&ols_wpanel_access_generation=" + settings.Generation, true, 403, "DENIED"},
		{"/wp/index.php", "POST", "ols_wpanel_access_token=" + strings.Repeat("a", 43) + "&ols_wpanel_access_generation=" + strings.Repeat("b", 32), true, 403, "DENIED"},
		{"/wp/index.php?ols_wpanel_access_token=" + strings.Repeat("a", 43), "GET", "", true, 200, "staff-signin"},
		{"/wp/index.php", "POST", "ols_wpanel_access_token=" + strings.Repeat("a", 43) + "&ols_wpanel_access_generation=" + settings.Generation, true, 303, ""},
		{"/wp/index.php?deleted=1", "POST", "ols_wpanel_access_token=" + strings.Repeat("a", 43) + "&ols_wpanel_access_generation=" + settings.Generation, true, 403, "DENIED"},
		{"/wp/index.php?nonadmin=1", "POST", "ols_wpanel_access_token=" + strings.Repeat("a", 43) + "&ols_wpanel_access_generation=" + settings.Generation, true, 403, "DENIED"},
		{"/wp/index.php?changed=1", "POST", "ols_wpanel_access_token=" + strings.Repeat("a", 43) + "&ols_wpanel_access_generation=" + settings.Generation, true, 403, "DENIED"},
		{"/wp/index.php?offsite=1", "POST", "ols_wpanel_access_token=" + strings.Repeat("a", 43) + "&ols_wpanel_access_generation=" + settings.Generation, true, 403, "DENIED"},
		{"/wp/index.php?mfa=1", "POST", "ols_wpanel_access_token=" + strings.Repeat("a", 43) + "&ols_wpanel_access_generation=" + settings.Generation, true, 403, "DENIED"},
		{"/wp/index.php?mfa_action=1", "POST", "ols_wpanel_access_token=" + strings.Repeat("a", 43) + "&ols_wpanel_access_generation=" + settings.Generation, true, 403, "DENIED"},
		{"/wp/index.php?uninstalled=1", "POST", "ols_wpanel_access_token=" + strings.Repeat("a", 43) + "&ols_wpanel_access_generation=" + settings.Generation, true, 200, "wp-login.php"},
		{"/wp/index.php?candidate=about", "GET", "", false, 200, `"suffix_conflict":true`},
		{"/wp/index.php?candidate=contact", "GET", "", false, 200, `"suffix_conflict":true`},
		{"/wp/index.php?candidate=api-entry", "GET", "", false, 200, `"suffix_conflict":true`},
		{"/wp/index.php?candidate=unused-staff-signin", "GET", "", false, 200, `"suffix_conflict":false`},
	} {
		r, err := http.NewRequest(test.method, base+test.path, strings.NewReader(test.body))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = "example.com"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if test.tls {
			r.Header.Set("X-Fixture-TLS", "1")
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != test.status || !strings.Contains(string(body), test.contains) {
			t.Fatalf("%s %s => %d %s", test.method, test.path, response.StatusCode, body)
		}
		cookies := response.Cookies()
		if test.status == 303 {
			if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || response.Header.Get("Location") != "https://example.com/wp/wp-admin/" {
				t.Fatal("authorized login did not create a secure WordPress cookie and fixed same-site redirect")
			}
		} else if len(cookies) != 0 {
			t.Fatal("refused or uninstalled request created a WordPress cookie")
		}
	}
}

func wpPanelAccessTestPHP(t *testing.T) string {
	t.Helper()
	php, err := exec.LookPath("php")
	if err != nil {
		if os.Getenv("OLS_WPANEL_REQUIRE_PHP_TESTS") == "1" {
			t.Fatal("required PHP regression runtime unavailable")
		}
		t.Skip("php unavailable")
	}
	return php
}
