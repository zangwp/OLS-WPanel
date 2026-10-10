<?php
// Only WordPress API boundaries are mocked; the shipped helper performs the
// real filesystem fingerprinting/deletions and writes its real result record.
$configuration = json_decode(file_get_contents('php://stdin'), true);
define('ABSPATH', $configuration['root'] . '/');
define('WP_CONTENT_DIR', $configuration['root'] . '/wp-content');
$GLOBALS['actions'] = array();
$GLOBALS['options'] = array('active_plugins' => $configuration['active_plugins']);
function add_action($name, $callback, $priority = 10) { $GLOBALS['actions'][$name][] = $callback; }
function add_option($name, $value, $deprecated = '', $autoload = false) {
    if (array_key_exists($name, $GLOBALS['options'])) { return false; }
    $GLOBALS['options'][$name] = $value;
    return true;
}
function update_option($name, $value, $autoload = false) { $GLOBALS['options'][$name] = $value; return true; }
function get_option($name, $default = false) { return $GLOBALS['options'][$name] ?? $default; }
function get_stylesheet() { return $GLOBALS['configuration']['stylesheet']; }
function get_template() { return $GLOBALS['configuration']['template']; }
function is_multisite() { return $GLOBALS['configuration']['multisite']; }
function wp_clean_themes_cache($check = true) { $GLOBALS['cache_cleared'] = true; }
require $configuration['helper'];
if ($configuration['mode'] !== 'existing') {
    foreach ($GLOBALS['actions']['wp_install'] ?? array() as $callback) { $callback(); }
}
if ($configuration['mode'] === 'repeat') {
    // Content installed by the user after the first cleanup must survive.
    file_put_contents(WP_CONTENT_DIR . '/plugins/hello.php', 'user-installed-again');
    foreach ($GLOBALS['actions']['wp_install'] ?? array() as $callback) { $callback(); }
}
echo json_encode(array('record' => $GLOBALS['options']['_ols_wpanel_default_cleanup'] ?? null,
    'registered' => array_keys($GLOBALS['actions']), 'helper_exists' => file_exists($configuration['helper'])));
