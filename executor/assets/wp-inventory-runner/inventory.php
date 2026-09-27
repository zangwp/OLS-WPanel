<?php

declare(strict_types=1);

const OLS_WPANEL_INVENTORY_PROTOCOL = 'ols-wpanel-inventory';
const OLS_WPANEL_INVENTORY_RUNNER_VERSION = '1';
const OLS_WPANEL_INVENTORY_SCHEMA_VERSION = 1;
const OLS_WPANEL_INVENTORY_PLUGIN_LIMIT = 2000;
const OLS_WPANEL_INVENTORY_THEME_LIMIT = 1000;
const OLS_WPANEL_INVENTORY_UPDATE_LIMIT = 3000;
const OLS_WPANEL_INVENTORY_NAME_LIMIT = 512;
const OLS_WPANEL_INVENTORY_VERSION_LIMIT = 128;

$yubWPanelInventoryState = array(
    'emitted' => false,
    'bootstrap_output_bytes' => 0,
    'protocol' => null,
);
$yubWPanelInventoryEmergencyReserve = str_repeat('R', 256 * 1024);

function ols_wpanel_inventory_diagnostics(): array
{
    global $yubWPanelInventoryState;

    $allowUrlInclude = filter_var(ini_get('allow_url_include'), FILTER_VALIDATE_BOOLEAN) ? '1' : '0';

    return array(
        'sapi' => PHP_SAPI,
        'effective_uid' => function_exists('posix_geteuid') ? (int) posix_geteuid() : -1,
        'effective_gid' => function_exists('posix_getegid') ? (int) posix_getegid() : -1,
        'open_basedir' => (string) ini_get('open_basedir'),
        'disable_functions' => (string) ini_get('disable_functions'),
        'allow_url_include' => $allowUrlInclude,
        'memory_limit' => (string) ini_get('memory_limit'),
        'bootstrap_output_bytes' => (int) $yubWPanelInventoryState['bootstrap_output_bytes'],
    );
}

function ols_wpanel_inventory_emit(array $envelope): void
{
    global $yubWPanelInventoryState;

    if ($yubWPanelInventoryState['emitted']) {
        return;
    }
    $yubWPanelInventoryState['emitted'] = true;
    $envelope['protocol'] = OLS_WPANEL_INVENTORY_PROTOCOL;
    $envelope['runner_version'] = OLS_WPANEL_INVENTORY_RUNNER_VERSION;
    $envelope['inventory_schema_version'] = OLS_WPANEL_INVENTORY_SCHEMA_VERSION;
    $envelope['diagnostics'] = ols_wpanel_inventory_diagnostics();
    $encoded = json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (!is_string($encoded)) {
        $encoded = '{"protocol":"ols-wpanel-inventory","runner_version":"1","inventory_schema_version":1,"ok":false,"error":{"code":"json_encode_failed"},"diagnostics":{"sapi":"cli","effective_uid":-1,"effective_gid":-1,"open_basedir":"","disable_functions":"","allow_url_include":"0","memory_limit":"256M","bootstrap_output_bytes":0}}';
    }
    $token = (string) getenv('OLS_WPANEL_RUNNER_TOKEN');
    $frame = 'OLS_WPANEL_INVENTORY_BEGIN ' . $token . "\n" . $encoded . "\n" . 'OLS_WPANEL_INVENTORY_END ' . $token . "\n";
    $protocol = $yubWPanelInventoryState['protocol'];
    if (is_resource($protocol)) {
        @fwrite($protocol, $frame);
        @fflush($protocol);
    }
}

function ols_wpanel_inventory_fail(string $code): void
{
    ols_wpanel_inventory_emit(array('ok' => false, 'error' => array('code' => $code)));
}

function ols_wpanel_inventory_string(mixed $value, int $limit): string
{
    $value = is_scalar($value) ? (string) $value : '';
    if (strlen($value) > $limit || !preg_match('//u', $value)) {
        throw new LengthException('inventory value exceeds limit');
    }
    return $value;
}

function ols_wpanel_inventory_component_id(mixed $value): string
{
    $value = ols_wpanel_inventory_string($value, OLS_WPANEL_INVENTORY_NAME_LIMIT);
    if ($value === '' || str_contains($value, '\\') || str_starts_with($value, '/') || preg_match('~(^|/)\.\.(/|$)~', $value)) {
        throw new UnexpectedValueException('invalid component id');
    }
    return $value;
}

function ols_wpanel_inventory_object_value(mixed $object, string $key, mixed $default = ''): mixed
{
    if (is_object($object) && property_exists($object, $key)) {
        return $object->{$key};
    }
    if (is_array($object) && array_key_exists($key, $object)) {
        return $object[$key];
    }
    return $default;
}

function ols_wpanel_inventory_component_updates(string $transientName): array
{
    $transient = get_site_transient($transientName);
    $present = $transient !== false;
    $items = array();
    $responses = $present ? ols_wpanel_inventory_object_value($transient, 'response', array()) : array();
    if (is_array($responses)) {
        foreach ($responses as $id => $response) {
            $items[] = array(
                'id' => ols_wpanel_inventory_component_id($id),
                'version' => ols_wpanel_inventory_string(ols_wpanel_inventory_object_value($response, 'new_version'), OLS_WPANEL_INVENTORY_VERSION_LIMIT),
            );
        }
    }
    usort($items, static fn(array $a, array $b): int => strcmp($a['id'], $b['id']));

    return array(
        'transient_present' => $present,
        'last_checked' => $present ? (int) ols_wpanel_inventory_object_value($transient, 'last_checked', 0) : 0,
        'items' => $items,
    );
}

function ols_wpanel_inventory_core_updates(): array
{
    $transient = get_site_transient('update_core');
    $present = $transient !== false;
    $items = array();
    $updates = $present ? ols_wpanel_inventory_object_value($transient, 'updates', array()) : array();
    if (is_array($updates)) {
        foreach ($updates as $update) {
            $items[] = array(
                'version' => ols_wpanel_inventory_string(ols_wpanel_inventory_object_value($update, 'current'), OLS_WPANEL_INVENTORY_VERSION_LIMIT),
                'response' => ols_wpanel_inventory_string(ols_wpanel_inventory_object_value($update, 'response'), OLS_WPANEL_INVENTORY_VERSION_LIMIT),
                'locale' => ols_wpanel_inventory_string(ols_wpanel_inventory_object_value($update, 'locale'), OLS_WPANEL_INVENTORY_VERSION_LIMIT),
            );
        }
    }
    usort($items, static function (array $a, array $b): int {
        return strcmp($a['version'] . "\0" . $a['locale'] . "\0" . $a['response'], $b['version'] . "\0" . $b['locale'] . "\0" . $b['response']);
    });

    return array(
        'transient_present' => $present,
        'last_checked' => $present ? (int) ols_wpanel_inventory_object_value($transient, 'last_checked', 0) : 0,
        'version_checked' => $present ? ols_wpanel_inventory_string(ols_wpanel_inventory_object_value($transient, 'version_checked'), OLS_WPANEL_INVENTORY_VERSION_LIMIT) : '',
        'items' => $items,
    );
}

function ols_wpanel_inventory_maybe_force_update_check(): void
{
    if (getenv('OLS_WPANEL_FORCE_UPDATE_CHECK') !== '1') {
        return;
    }
    if (!function_exists('wp_update_plugins')) {
        $adminUpdate = ABSPATH . 'wp-admin/includes/update.php';
        if (is_file($adminUpdate)) {
            require_once $adminUpdate;
        }
    }
    // The panel setting is authoritative. Older optimizer versions may still
    // have a stale cached option from before the setting was toggled, and may
    // already have installed pre-transient filters during WordPress bootstrap.
    // A forced scan is only requested by the worker when update checks are
    // enabled for this site, so synchronize that option and remove the
    // uniquely named filters owned by current OLS WPanel Optimizer versions.
    update_option('olsw_optimizer_no_updates', '0');
    if (class_exists('OLS_WPanel_Optimizer')) {
        $optimizerCallback = array('OLS_WPanel_Optimizer', 'suppress_update_transient');
        foreach (array('update_core', 'update_plugins', 'update_themes') as $name) {
            remove_filter('pre_site_transient_' . $name, $optimizerCallback);
        }
        // Versions before 1.1.9 used the shared __return_null callback. Only
        // retain that compatibility path when the loaded optimizer is old.
        if (!method_exists('OLS_WPanel_Optimizer', 'suppress_update_transient')) {
            foreach (array('update_core', 'update_plugins', 'update_themes') as $name) {
                remove_filter('pre_site_transient_' . $name, '__return_null');
            }
        }
    }
    foreach (array('update_core', 'update_plugins', 'update_themes') as $name) {
        delete_site_transient($name);
    }
    try {
        if (function_exists('wp_version_check')) {
            wp_version_check();
        }
        if (function_exists('wp_update_plugins')) {
            wp_update_plugins();
        }
        if (function_exists('wp_update_themes')) {
            wp_update_themes();
        }
    } catch (Throwable $error) {
        // A failed live update check should not fail the entire read-only
        // inventory scan. The deleted transients will be repopulated by
        // WordPress on the next regular update check or admin page load.
    }
}

function ols_wpanel_inventory_collect(): array
{
    global $wp_version;

    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    ols_wpanel_inventory_maybe_force_update_check();
    $pluginRows = array();
    $activePlugins = array_fill_keys((array) get_option('active_plugins', array()), true);
    $networkPlugins = is_multisite() ? (array) get_site_option('active_sitewide_plugins', array()) : array();
    foreach (get_plugins() as $file => $plugin) {
        $file = ols_wpanel_inventory_component_id($file);
        $pluginRows[] = array(
            'file' => $file,
            'name' => ols_wpanel_inventory_string($plugin['Name'] ?? '', OLS_WPANEL_INVENTORY_NAME_LIMIT),
            'version' => ols_wpanel_inventory_string($plugin['Version'] ?? '', OLS_WPANEL_INVENTORY_VERSION_LIMIT),
            'active' => isset($activePlugins[$file]) || isset($networkPlugins[$file]),
            'network_active' => isset($networkPlugins[$file]),
        );
    }
    if (count($pluginRows) > OLS_WPANEL_INVENTORY_PLUGIN_LIMIT) {
        throw new OverflowException('plugin limit');
    }
    usort($pluginRows, static fn(array $a, array $b): int => strcmp($a['file'], $b['file']));

    $themeRows = array();
    foreach (wp_get_themes() as $stylesheet => $theme) {
        $themeRows[] = array(
            'stylesheet' => ols_wpanel_inventory_component_id($stylesheet),
            'name' => ols_wpanel_inventory_string($theme->get('Name'), OLS_WPANEL_INVENTORY_NAME_LIMIT),
            'version' => ols_wpanel_inventory_string($theme->get('Version'), OLS_WPANEL_INVENTORY_VERSION_LIMIT),
        );
    }
    if (count($themeRows) > OLS_WPANEL_INVENTORY_THEME_LIMIT) {
        throw new OverflowException('theme limit');
    }
    usort($themeRows, static fn(array $a, array $b): int => strcmp($a['stylesheet'], $b['stylesheet']));

    $current = wp_get_theme();
    $currentTheme = $current->exists() ? array(
        'stylesheet' => ols_wpanel_inventory_component_id($current->get_stylesheet()),
        'name' => ols_wpanel_inventory_string($current->get('Name'), OLS_WPANEL_INVENTORY_NAME_LIMIT),
        'version' => ols_wpanel_inventory_string($current->get('Version'), OLS_WPANEL_INVENTORY_VERSION_LIMIT),
    ) : null;

    $coreUpdates = ols_wpanel_inventory_core_updates();
    $pluginUpdates = ols_wpanel_inventory_component_updates('update_plugins');
    $themeUpdates = ols_wpanel_inventory_component_updates('update_themes');
    if (count($coreUpdates['items']) + count($pluginUpdates['items']) + count($themeUpdates['items']) > OLS_WPANEL_INVENTORY_UPDATE_LIMIT) {
        throw new OverflowException('update limit');
    }

    return array(
        'wordpress' => array(
            'version' => ols_wpanel_inventory_string($wp_version ?? '', OLS_WPANEL_INVENTORY_VERSION_LIMIT),
            'locale' => ols_wpanel_inventory_string(get_locale(), OLS_WPANEL_INVENTORY_VERSION_LIMIT),
            'multisite' => is_multisite(),
        ),
        'plugins' => $pluginRows,
        'themes' => $themeRows,
        'current_theme' => $currentTheme,
        'updates' => array('core' => $coreUpdates, 'plugins' => $pluginUpdates, 'themes' => $themeUpdates),
    );
}

function ols_wpanel_inventory_anomaly_sample(array $query): array
{
    if (is_multisite()) return array('error'=>'multisite_unsupported');
    if (!in_array('ols-wpanel-optimizer/ols-wpanel-optimizer.php', (array)get_option('active_plugins', array()), true)
        || !is_callable(array('OLS_WPanel_Optimizer', 'collect_anomaly_sample'))) {
        return array('error'=>'plugin_required');
    }
    return OLS_WPanel_Optimizer::collect_anomaly_sample($query['since'], $query['until'], $query['known_ids']);
}

$token = (string) getenv('OLS_WPANEL_RUNNER_TOKEN');
$yubWPanelInventoryState['protocol'] = @fopen('php://fd/3', 'wb');
if (PHP_SAPI !== 'cli' || !preg_match('/^[0-9a-f]{32}$/', $token) || !is_resource($yubWPanelInventoryState['protocol'])) {
    ols_wpanel_inventory_fail('invalid_sapi');
    exit(2);
}

ob_start(static function (string $buffer) use (&$yubWPanelInventoryState): string {
    $yubWPanelInventoryState['bootstrap_output_bytes'] += strlen($buffer);
    return '';
}, 1);

register_shutdown_function(static function () use (&$yubWPanelInventoryState, &$yubWPanelInventoryEmergencyReserve): void {
    $yubWPanelInventoryEmergencyReserve = null;
    if ($yubWPanelInventoryState['emitted']) {
        return;
    }
    $last = error_get_last();
    if (is_array($last)) {
        $message = (string) ($last['message'] ?? '');
        ols_wpanel_inventory_fail(str_contains($message, 'Allowed memory size') ? 'memory_limit_exhausted' : 'fatal_error');
        return;
    }
    ols_wpanel_inventory_fail('bootstrap_terminated');
});

$siteRoot = $argv[1] ?? '';
$realSiteRoot = is_string($siteRoot) ? realpath($siteRoot) : false;
if ($realSiteRoot === false || !is_dir($realSiteRoot)) {
    ols_wpanel_inventory_fail('invalid_site_root');
    exit(2);
}
$wpLoad = $realSiteRoot . DIRECTORY_SEPARATOR . 'wp-load.php';
$realWpLoad = realpath($wpLoad);
if ($realWpLoad === false || dirname($realWpLoad) !== $realSiteRoot || !is_file($realWpLoad)) {
    ols_wpanel_inventory_fail('invalid_wp_load');
    exit(2);
}

define('OLS_WPANEL_INVENTORY_RUNNER', true);
define('WP_USE_THEMES', false);
define('DISABLE_WP_CRON', true);

try {
    require $realWpLoad;
    $inventory = ols_wpanel_inventory_collect();
    $anomalyQuery = getenv('OLS_WPANEL_ANOMALY_QUERY');
    if (is_string($anomalyQuery) && $anomalyQuery !== '') {
        $query = json_decode($anomalyQuery, true, 8, JSON_THROW_ON_ERROR);
        $inventory['anomaly'] = ols_wpanel_inventory_anomaly_sample($query);
    }
    ols_wpanel_inventory_emit(array('ok' => true, 'data' => $inventory));
} catch (OverflowException | LengthException | UnexpectedValueException $error) {
    ols_wpanel_inventory_fail('inventory_limit_exceeded');
    exit(3);
} catch (Throwable $error) {
    ols_wpanel_inventory_fail('bootstrap_throwable');
    exit(3);
}
