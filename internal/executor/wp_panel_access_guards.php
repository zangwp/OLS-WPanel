<?php
// Shared by the read-only CLI inspector and the panel-managed MU plugin.
if (!function_exists('ols_wpanel_access_login_conflicts')) {
function ols_wpanel_access_login_plugins() {
    $items = [];
    foreach ((array)get_option('active_plugins', []) as $plugin) {
        if (preg_match('~(^|/)(wps-hide-login|hide-my-wp|hide-login-page|rename-wp-login|all-in-one-wp-security-and-firewall|better-wp-security|solid-security)(/|\.)~i', $plugin)) {
            $items[] = basename(dirname($plugin));
        }
    }
    global $wp_filter;
    if (isset($wp_filter['login_url']) && is_object($wp_filter['login_url'])) {
        foreach ($wp_filter['login_url']->callbacks as $callbacks) {
            foreach ($callbacks as $callback) {
                $fn = $callback['function'];
                if (is_string($fn) && strpos($fn, 'ols_wpanel_access_') === 0) continue;
                $items[] = 'login_url_filter';
            }
        }
    }
    return array_values(array_unique($items));
}
function ols_wpanel_access_login_conflicts($expected, $actual) {
    $items = ols_wpanel_access_login_plugins();
    $expected_path = wp_parse_url($expected, PHP_URL_PATH);
    $actual_path = wp_parse_url($actual, PHP_URL_PATH);
    if ($expected_path !== $actual_path || wp_parse_url($actual, PHP_URL_QUERY)) $items[] = 'filtered_login_url';
    return array_values(array_unique($items));
}

function ols_wpanel_access_authentication_conflicts() {
    $items = [];
    foreach ((array)get_option('active_plugins', []) as $plugin) {
        if (preg_match('~(^|/)(wordfence|wordfence-login-security|two-factor|two-factor-authentication|wp-2fa|mini-orange-2-factor-authentication|miniorange-2-factor-authentication|two-factor-authentication-2|google-authenticator|loginizer|duo-wordpress|limit-login-attempts-reloaded)(/|\.)~i', $plugin)) {
            $items[] = basename(dirname($plugin));
        }
    }
    $core = ['wp_authenticate_username_password', 'wp_authenticate_email_password', 'wp_authenticate_application_password', 'wp_authenticate_spam_check', 'wp_validate_auth_cookie', 'wp_validate_logged_in_cookie', 'wp_validate_application_password', 'send_frame_options_header', 'wp_admin_headers'];
    global $wp_filter;
    foreach (['authenticate', 'wp_authenticate_user', 'determine_current_user', 'wp_authenticate', 'login_init', 'wp_login', 'send_auth_cookies', 'set_auth_cookie', 'set_logged_in_cookie'] as $hook) {
        if (!isset($wp_filter[$hook]) || !is_object($wp_filter[$hook])) continue;
        foreach ($wp_filter[$hook]->callbacks as $callbacks) {
            foreach ($callbacks as $callback) {
                $fn = $callback['function'];
                if (is_string($fn) && in_array($fn, $core, true)) continue;
                $items[] = $hook . '_filter';
            }
        }
    }
    return array_values(array_unique($items));
}

function ols_wpanel_access_administrator_proof($user) {
    return hash('sha256', $user->ID . "\n" . $user->user_login . "\n" . $user->user_registered . "\n" . $user->user_pass);
}

function ols_wpanel_access_suffix_conflict($suffix) {
    $site = rtrim((string)get_option('siteurl'), '/');
    if (url_to_postid($site . '/' . $suffix)) return true;
    $types = get_post_types(['public' => true], 'names');
    if (get_page_by_path($suffix, OBJECT, $types)) return true;
    $site_path = rtrim((string)wp_parse_url($site, PHP_URL_PATH), '/');
    $home_path = rtrim((string)wp_parse_url((string)get_option('home'), PHP_URL_PATH), '/');
    $candidate = ltrim($site_path . '/' . $suffix, '/');
    if ($home_path !== '' && strpos('/' . $candidate, $home_path . '/') === 0) $candidate = ltrim(substr('/' . $candidate, strlen($home_path)), '/');
    foreach ((array)get_option('rewrite_rules', []) as $pattern => $target) {
        if (!is_string($pattern) || !is_string($target)) return true;
        $matches = [];
        if (@preg_match('#^' . str_replace('#', '\\#', $pattern) . '#', $candidate, $matches) !== 1) continue;
        // Broad core page/post permalink rules are not occupied unless they
        // resolve an actual post above. Other matching routes stay protected.
        if (strpos($target, 'index.php?') !== 0) return true;
        parse_str(substr($target, strlen('index.php?')), $vars);
        if (!$vars || !isset($vars['name']) && !isset($vars['pagename'])) return true;
        foreach (array_keys($vars) as $key) if (!in_array($key, ['name', 'pagename', 'page', 'post_type', 'attachment', 'attachment_id'], true)) return true;
    }
    return false;
}
}
