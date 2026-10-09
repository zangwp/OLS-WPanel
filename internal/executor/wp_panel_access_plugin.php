<?php
// OLS-WPANEL-MANAGED:wordpress-access:1
// The generator inserts only non-secret site settings and the shared guards.
if (!defined('ABSPATH')) exit;

function ols_wpanel_access_native_login() {
    $base = (string)get_option('siteurl');
    return rtrim($base, '/') . '/wp-login.php';
}
function ols_wpanel_access_expected_login() {
    global $ols_wpanel_access_config;
    $base = (string)get_option('siteurl');
    return rtrim($base, '/') . '/' . ($ols_wpanel_access_config['login_suffix'] ?: 'wp-login.php');
}
function ols_wpanel_access_login_url($url, $redirect = '', $force = false) {
    global $ols_wpanel_access_config;
    if (!$ols_wpanel_access_config['login_suffix'] || !is_blog_installed() || is_multisite() || ols_wpanel_access_login_conflicts(ols_wpanel_access_expected_login(), $url)) return $url;
    $result = ols_wpanel_access_expected_login();
    if ($redirect !== '') $result = add_query_arg('redirect_to', $redirect, $result);
    if ($force) $result = add_query_arg('reauth', '1', $result);
    return $result;
}
function ols_wpanel_access_site_url($url, $relative, $scheme, $blog_id) {
    global $ols_wpanel_access_config;
    if (!$ols_wpanel_access_config['login_suffix'] || !is_blog_installed() || is_multisite() || ols_wpanel_access_login_plugins()) return $url;
    if (!preg_match('~^wp-login\.php(?:\?|$)~', ltrim($relative, '/'))) return $url;
    $query = wp_parse_url($url, PHP_URL_QUERY);
    return ols_wpanel_access_expected_login() . ($query !== null && $query !== false ? '?' . $query : '');
}
function ols_wpanel_access_fail() {
    nocache_headers();
    header('Referrer-Policy: no-referrer');
    wp_die(esc_html__('This login authorization is unavailable or has expired. Return to the panel and try again.'), '', ['response' => 403]);
}
function ols_wpanel_access_dispatch() {
    global $ols_wpanel_access_config;
    if (PHP_SAPI === 'cli' || !is_blog_installed() || is_multisite() || wp_installing()) return;
    $request_path = wp_parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
    $base_path = rtrim($ols_wpanel_access_config['installation_path'], '/');
    if (isset($_POST['ols_wpanel_access_token'])) {
        // Tokens are accepted only in a direct HTTPS POST to the core index,
        // never from a URL, a third-party login plugin route or a redirect.
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !is_ssl() || !$ols_wpanel_access_config['sso_enabled'] || $request_path !== $base_path . '/index.php') ols_wpanel_access_fail();
        $host = strtolower($_SERVER['HTTP_HOST'] ?? '');
        $expected_host = strtolower($ols_wpanel_access_config['domain']);
        if ($host !== $expected_host && $host !== $expected_host . ':443') ols_wpanel_access_fail();
        if (ols_wpanel_access_login_conflicts(ols_wpanel_access_expected_login(), wp_login_url()) || ols_wpanel_access_authentication_conflicts()) ols_wpanel_access_fail();
        $token = $_POST['ols_wpanel_access_token'];
        $generation = $_POST['ols_wpanel_access_generation'] ?? '';
        if (!is_string($token) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $token) || !is_string($generation) || !hash_equals($ols_wpanel_access_config['generation'], $generation)) ols_wpanel_access_fail();
        if (!function_exists('curl_init') || !defined('CURLOPT_UNIX_SOCKET_PATH')) ols_wpanel_access_fail();
        nocache_headers(); header('Referrer-Policy: no-referrer');
        // No IP/TLS fallback exists: redemption travels over this root-owned
        // Unix socket and the panel checks SO_PEERCRED against this site's UID.
        $curl = curl_init('http://localhost/redeem');
        $reply = '';
        curl_setopt_array($curl, [CURLOPT_UNIX_SOCKET_PATH => $ols_wpanel_access_config['socket'], CURLOPT_PROXY => '', CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode(['token' => $token, 'site_id' => $ols_wpanel_access_config['site_id'], 'generation' => $generation]), CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_RETURNTRANSFER => false, CURLOPT_FOLLOWLOCATION => false, CURLOPT_CONNECTTIMEOUT => 2, CURLOPT_TIMEOUT => 8, CURLOPT_WRITEFUNCTION => function($ch, $chunk) use (&$reply) { if (strlen($reply) + strlen($chunk) > 8192) return 0; $reply .= $chunk; return strlen($chunk); }]);
        $ok = curl_exec($curl); $status = curl_getinfo($curl, CURLINFO_HTTP_CODE); curl_close($curl);
        unset($_POST['ols_wpanel_access_token']); $token = null;
        $body = json_decode($reply, true); $reply = null;
        if (!$ok || $status !== 200 || !is_array($body) || empty($body['success']) || !isset($body['data'])) ols_wpanel_access_fail();
        $grant = $body['data'];
        if (!hash_equals($ols_wpanel_access_config['generation'], (string)($grant['generation'] ?? '')) || ($grant['domain'] ?? '') !== $ols_wpanel_access_config['domain'] || ($grant['installation_path'] ?? '') !== $ols_wpanel_access_config['installation_path']) ols_wpanel_access_fail();
        $user = get_userdata((int)($grant['administrator_id'] ?? 0));
        if (!$user || !in_array('administrator', (array)$user->roles, true) || $user->user_login !== ($grant['administrator_login'] ?? '') || !hash_equals(ols_wpanel_access_administrator_proof($user), (string)($grant['administrator_proof'] ?? ''))) ols_wpanel_access_fail();
        $redirect = admin_url(); $parts = wp_parse_url($redirect);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || strtolower($parts['host'] ?? '') !== strtolower($ols_wpanel_access_config['domain']) || isset($parts['user']) || isset($parts['pass']) || (isset($parts['port']) && $parts['port'] !== 443) || strpos($parts['path'] ?? '', $base_path . '/wp-admin/') !== 0) ols_wpanel_access_fail();
        // Fresh, non-remembered secure cookies are created by WordPress itself.
        wp_clear_auth_cookie(); wp_set_current_user($user->ID); wp_set_auth_cookie($user->ID, false, true);
        do_action('wp_login', $user->user_login, $user);
        wp_safe_redirect($redirect, 303, 'OLS WPanel'); exit;
    }
    if (!$ols_wpanel_access_config['login_suffix']) return;
    // A subsequently enabled hiding plugin keeps control. Do not redirect or
    // rewrite a route that another login plugin owns.
    if (ols_wpanel_access_login_conflicts(ols_wpanel_access_expected_login(), wp_login_url())) return;
    $custom = $base_path . '/' . $ols_wpanel_access_config['login_suffix'];
    if ($request_path === $custom || $request_path === $custom . '/') {
        nocache_headers(); header('X-OLS-WPanel-Login-Route: ' . $ols_wpanel_access_config['generation']); $GLOBALS['pagenow'] = 'wp-login.php';
        require ABSPATH . 'wp-login.php'; exit;
    }
    if ($request_path === $base_path . '/wp-login.php') {
        nocache_headers(); status_header(404); exit;
    }
}
add_filter('login_url', 'ols_wpanel_access_login_url', 1, 3);
add_filter('site_url', 'ols_wpanel_access_site_url', 1, 4);
add_action('wp_loaded', 'ols_wpanel_access_dispatch', 0);
