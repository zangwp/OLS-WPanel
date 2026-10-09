<?php
$ols_token = getenv('OLS_WPANEL_RUNNER_TOKEN'); $ols_sent = false;
$ols_send = function($ok, $data = [], $code = '') use (&$ols_sent, $ols_token) {
    if ($ols_sent) return; $ols_sent = true;
    file_put_contents('php://fd/3', json_encode(['token' => $ols_token, 'ok' => $ok, 'data' => $data, 'error_code' => $code], JSON_UNESCAPED_SLASHES));
};
register_shutdown_function(function() use (&$ols_sent, $ols_send) { if (!$ols_sent) $ols_send(false, [], 'runtime_unavailable'); });
$ols_raw = stream_get_contents(STDIN, 65537); $ols_input = json_decode($ols_raw, true);
if (PHP_SAPI !== 'cli' || !preg_match('/^[0-9a-f]{32}$/D', (string)$ols_token) || strlen($ols_raw) > 65536 || !is_array($ols_input)) { $ols_send(false, [], 'invalid_input'); exit(2); }
$ols_root = $ols_input['root'] ?? '';
if (!is_string($ols_root) || !is_dir($ols_root) || realpath($ols_root) !== rtrim($ols_root, '/')) { $ols_send(false, [], 'invalid_root'); exit(2); }
$_SERVER['HTTP_HOST'] = $ols_input['domain']; $_SERVER['SERVER_NAME'] = $ols_input['domain'];
$_SERVER['REQUEST_URI'] = '/'; $_SERVER['REQUEST_METHOD'] = 'GET'; $_SERVER['SCRIPT_FILENAME'] = $ols_root . '/index.php';
if (!empty($ols_input['https'])) { $_SERVER['HTTPS'] = 'on'; $_SERVER['SERVER_PORT'] = 443; } else { $_SERVER['SERVER_PORT'] = 80; }
if ($ols_input['phase'] === 'installation') { define('SHORTINIT', true); define('WP_INSTALLING', true); }
define('WP_USE_THEMES', false); if (!defined('WP_HTTP_BLOCK_EXTERNAL')) define('WP_HTTP_BLOCK_EXTERNAL', true);
if (!defined('DISABLE_WP_CRON')) define('DISABLE_WP_CRON', true);
chdir($ols_root); ob_start(); require $ols_root . '/wp-load.php'; ob_end_clean();
global $wpdb;
if (is_multisite()) { $ols_send(false, [], 'multisite_unsupported'); exit(1); }
if (DB_NAME !== $ols_input['db_name'] || $wpdb->prefix !== $ols_input['table_prefix']) { $ols_send(false, [], 'database_mismatch'); exit(1); }
if ($ols_input['phase'] === 'installation') { $ols_send(true, ['installed' => is_blog_installed()]); exit; }
if (!is_blog_installed()) { $ols_send(false, [], 'not_installed'); exit(1); }
if (!empty($ols_input['candidate_suffix'])) {
    $suffix = $ols_input['candidate_suffix'];
    if (!is_string($suffix) || !preg_match('/^[a-z][a-z0-9_-]{2,63}$/D', $suffix)) { $ols_send(false, [], 'invalid_suffix'); exit(1); }
    if (ols_wpanel_access_suffix_conflict($suffix)) { $ols_send(false, [], 'suffix_conflict'); exit(1); }
}
$ols_users = [];
foreach (get_users(['role' => 'administrator', 'orderby' => 'ID', 'order' => 'ASC', 'number' => 101]) as $user) {
    $ols_users[] = ['id' => (int)$user->ID, 'login' => $user->user_login, 'display_name' => $user->display_name, 'proof' => ols_wpanel_access_administrator_proof($user)];
}
if (count($ols_users) > 100) { $ols_send(false, [], 'too_many_administrators'); exit(1); }
$ols_siteurl = (string)get_option('siteurl'); $ols_login = wp_login_url();
$ols_expected = rtrim($ols_siteurl, '/') . '/' . ($ols_input['login_suffix'] ?: 'wp-login.php');
$ols_send(true, ['installed' => true, 'site_url' => $ols_siteurl, 'login_url' => $ols_login, 'conflicting_plugins' => ols_wpanel_access_login_conflicts($ols_expected, $ols_login), 'authentication_plugins' => ols_wpanel_access_authentication_conflicts(), 'administrators' => $ols_users, 'permalinks_enabled' => (string)get_option('permalink_structure') !== '', 'curl_unix_available' => function_exists('curl_init') && defined('CURLOPT_UNIX_SOCKET_PATH')]);
