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

$olsWPanelInventoryState = array(
    'emitted' => false,
    'bootstrap_output_bytes' => 0,
    'protocol' => null,
);
$olsWPanelInventoryEmergencyReserve = str_repeat('R', 256 * 1024);

function ols_wpanel_inventory_diagnostics(): array
{
    global $olsWPanelInventoryState;

    $allowUrlInclude = filter_var(ini_get('allow_url_include'), FILTER_VALIDATE_BOOLEAN) ? '1' : '0';

    return array(
        'sapi' => PHP_SAPI,
        'effective_uid' => function_exists('posix_geteuid') ? (int) posix_geteuid() : -1,
        'effective_gid' => function_exists('posix_getegid') ? (int) posix_getegid() : -1,
        'open_basedir' => (string) ini_get('open_basedir'),
        'disable_functions' => (string) ini_get('disable_functions'),
        'allow_url_include' => $allowUrlInclude,
        'memory_limit' => (string) ini_get('memory_limit'),
        'bootstrap_output_bytes' => (int) $olsWPanelInventoryState['bootstrap_output_bytes'],
    );
}

function ols_wpanel_inventory_emit(array $envelope): void
{
    global $olsWPanelInventoryState;

    if ($olsWPanelInventoryState['emitted']) {
        return;
    }
    $olsWPanelInventoryState['emitted'] = true;
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
    $protocol = $olsWPanelInventoryState['protocol'];
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
        'cache' => ols_wpanel_inventory_cache_status(),
        'plugins' => $pluginRows,
        'themes' => $themeRows,
        'current_theme' => $currentTheme,
        'updates' => array('core' => $coreUpdates, 'plugins' => $pluginUpdates, 'themes' => $themeUpdates),
    );
}

function ols_wpanel_inventory_collect_anomaly($since, $until, $known_ids) {
        if (PHP_SAPI !== 'cli' || !defined('OLS_WPANEL_INVENTORY_RUNNER') || !OLS_WPANEL_INVENTORY_RUNNER) {
            throw new RuntimeException('runner_required');
        }
        if (is_multisite()) return ['error'=>'multisite_unsupported'];
        if (!is_int($since) || !is_int($until) || $since < 0 || $until < $since || count($known_ids) > 100) {
            return ['error'=>'sample_invalid'];
        }
        global $wpdb;
		$database_objects = [];
		$object_queries = [
			['trigger', "SELECT TRIGGER_NAME object_name,EVENT_OBJECT_TABLE target_name,CONCAT(ACTION_TIMING,' ',EVENT_MANIPULATION) object_action,'' object_status,ACTION_STATEMENT definition_body,CONCAT_WS('|',ACTION_STATEMENT,DEFINER,SQL_MODE,CHARACTER_SET_CLIENT,COLLATION_CONNECTION,DATABASE_COLLATION) object_definition FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=%s"],
			['event', "SELECT EVENT_NAME object_name,'' target_name,EVENT_TYPE object_action,STATUS object_status,EVENT_DEFINITION definition_body,CONCAT_WS('|',EVENT_DEFINITION,DEFINER,SQL_MODE,TIME_ZONE,EVENT_TYPE,INTERVAL_VALUE,INTERVAL_FIELD,EXECUTE_AT,STARTS,ENDS,ON_COMPLETION) object_definition FROM information_schema.EVENTS WHERE EVENT_SCHEMA=%s"],
			['procedure', "SELECT ROUTINE_NAME object_name,'' target_name,SECURITY_TYPE object_action,'' object_status,ROUTINE_DEFINITION definition_body,CONCAT_WS('|',ROUTINE_DEFINITION,DEFINER,SQL_MODE,DTD_IDENTIFIER,SQL_DATA_ACCESS,IS_DETERMINISTIC,SECURITY_TYPE) object_definition FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=%s AND ROUTINE_TYPE='PROCEDURE'"],
			['function', "SELECT ROUTINE_NAME object_name,'' target_name,SECURITY_TYPE object_action,'' object_status,ROUTINE_DEFINITION definition_body,CONCAT_WS('|',ROUTINE_DEFINITION,DEFINER,SQL_MODE,DTD_IDENTIFIER,SQL_DATA_ACCESS,IS_DETERMINISTIC,SECURITY_TYPE) object_definition FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=%s AND ROUTINE_TYPE='FUNCTION'"],
		];
		foreach ($object_queries as [$kind, $sql]) {
			$rows = $wpdb->get_results($wpdb->prepare($sql, DB_NAME), ARRAY_A);
			if ($wpdb->last_error !== '' || !is_array($rows)) return ['error'=>'sample_failed'];
			foreach ($rows as $row) {
				$name = (string)($row['object_name'] ?? '');
				$definition_body = $row['definition_body'] ?? null;
				$definition = (string)($row['object_definition'] ?? '');
				if ($name === '' || !is_string($definition_body) || $definition_body === '' || $definition === '') return ['error'=>'sample_malformed'];
				$database_objects[] = [
					'kind'=>$kind,
					'name'=>$name,
					'target'=>(string)($row['target_name'] ?? ''),
					'action'=>(string)($row['object_action'] ?? ''),
					'status'=>(string)($row['object_status'] ?? ''),
					'fingerprint'=>hash_hmac('sha256', $definition, wp_salt('auth')),
				];
				if (count($database_objects) > 100) return ['error'=>'sample_too_large'];
			}
		}
		usort($database_objects, static function($a, $b) {
			return [$a['kind'], $a['name']] <=> [$b['kind'], $b['name']];
		});
        $users = get_users(['role'=>'administrator', 'number'=>101, 'orderby'=>'ID', 'order'=>'ASC']);
        if ($wpdb->last_error !== '') return ['error'=>'sample_failed'];
        if (count($users) > 100) return ['error'=>'sample_too_large'];
        $admins = [];
        $application_passwords = [];
        $current = [];
        foreach ($users as $user) {
            $roles = array_values($user->roles);
            sort($roles, SORT_STRING);
            $admins[] = ['id'=>(int)$user->ID, 'login'=>$user->user_login, 'roles'=>$roles,
                'email_hash'=>hash_hmac('sha256', strtolower(trim($user->user_email)), wp_salt('auth')),
                'display_hash'=>hash_hmac('sha256', (string)$user->display_name, wp_salt('auth')),
                'credential_hash'=>hash_hmac('sha256', (string)$user->user_pass, wp_salt('auth'))];
            if (!class_exists('WP_Application_Passwords')) return ['error'=>'sample_failed'];
            // Core may repair legacy entries missing a UUID while reading them.
            $passwords = WP_Application_Passwords::get_user_application_passwords((int)$user->ID);
            if (!is_array($passwords)) return ['error'=>'sample_failed'];
            if (count($passwords) > 100) return ['error'=>'sample_too_large'];
            foreach ($passwords as $password) {
                if (!is_array($password) || !isset($password['uuid'], $password['name'], $password['created']) || (string)$password['uuid'] === '' || (string)$password['name'] === '' || (int)$password['created'] < 1) return ['error'=>'sample_malformed'];
                $application_passwords[] = [
                    'admin_id'=>(int)$user->ID,
                    'fingerprint'=>hash_hmac('sha256', (string)$password['uuid'], wp_salt('auth')),
                    'name'=>(string)$password['name'],
                    'has_app_id'=>isset($password['app_id']) && (string)$password['app_id'] !== '',
                    'created'=>(int)($password['created'] ?? 0),
                    'last_used'=>(int)($password['last_used'] ?? 0),
                    'last_ip'=>(string)($password['last_ip'] ?? ''),
                ];
                if (count($application_passwords) > 1000) return ['error'=>'sample_too_large'];
            }
            $current[(int)$user->ID] = true;
        }
        usort($application_passwords, static function($a, $b) {
            return [$a['admin_id'], $a['fingerprint']] <=> [$b['admin_id'], $b['fingerprint']];
        });
        // Only former administrators are looked up: no full subscriber inventory.
        $removed = [];
        foreach ($known_ids as $id) {
            if (!is_int($id) || $id < 1) return ['error'=>'sample_invalid'];
            if (isset($current[$id])) continue;
            $user = get_userdata($id);
            if ($wpdb->last_error !== '') return ['error'=>'sample_failed'];
            $removed[] = ['id'=>$id, 'deleted'=>$user === false];
        }
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type IN ('post','page') AND post_status = 'publish' AND post_date_gmt > %s AND post_date_gmt <= %s",
            gmdate('Y-m-d H:i:s', max($since, $until - DAY_IN_SECONDS)), gmdate('Y-m-d H:i:s', $until)
        ));
        if ($wpdb->last_error !== '' || $count === null) return ['error'=>'sample_failed'];
        $content = [];
        $last_id = 0;
        do {
            $rows = $wpdb->get_results($wpdb->prepare(
                "SELECT ID,post_type,post_status,post_title,post_content,post_excerpt,post_name FROM {$wpdb->posts} WHERE post_type IN ('post','page') AND post_status='publish' AND ID > %d ORDER BY ID ASC LIMIT 251",
                $last_id
            ), ARRAY_A);
            if ($wpdb->last_error !== '' || !is_array($rows)) return ['error'=>'sample_failed'];
            foreach ($rows as $row) {
                $encoded = wp_json_encode([
                    (int)$row['ID'], (string)$row['post_type'], (string)$row['post_status'],
                    (string)$row['post_title'], (string)$row['post_content'],
                    (string)$row['post_excerpt'], (string)$row['post_name'],
                ]);
                if ($encoded === false) return ['error'=>'sample_failed'];
                $content[] = [
                    'id'=>(int)$row['ID'],
                    'type'=>(string)$row['post_type'],
                    'fingerprint'=>hash_hmac('sha256', $encoded, wp_salt('auth')),
                ];
                $last_id = (int)$row['ID'];
                if (count($content) > 5000) return ['error'=>'sample_too_large'];
            }
        } while (count($rows) === 251);
        return [
            'version'=>4,
            'admins'=>$admins,
            'application_passwords'=>$application_passwords,
			'database_objects'=>$database_objects,
            'removed'=>$removed,
            'post_count'=>(int)$count,
            'content'=>$content,
            'options'=>[
                'siteurl'=>(string)get_option('siteurl', ''),
                'home'=>(string)get_option('home', ''),
                'users_can_register'=>(bool)get_option('users_can_register', false),
                'default_role'=>(string)get_option('default_role', 'subscriber'),
                'front_page_id'=>(int)get_option('page_on_front', 0),
            ],
        ];
    }

function ols_wpanel_inventory_anomaly_sample(array $query): array
{
    return ols_wpanel_inventory_collect_anomaly($query['since'], $query['until'], $query['known_ids']);
}

function ols_wpanel_inventory_cache_status(): array {
    $conf = (array)get_option('litespeed-cache-conf', array());
    $value = static function($key, $default) use ($conf) {
        $constant = 'LITESPEED_CONF__' . strtoupper(str_replace('-', '__', $key));
        return defined($constant) ? constant($constant) : ($conf[$key] ?? $default);
    };
    return array('page_enabled'=>(bool)$value('cache', true),
        'object_enabled'=>(bool)$value('object', false) && (bool)$value('object-kind', false),
        'host'=>substr((string)$value('object-host', 'localhost'),0,255),
        'port'=>(int)$value('object-port',11211),'database'=>(int)$value('object-db_id',0));
}

function ols_wpanel_inventory_migrate_cache(array $patch): void {
    if (is_multisite()) throw new RuntimeException('multisite_unsupported');
    $allowed = array('object','object-kind','object-host','object-port','object-db_id','object-persistent');
    foreach ($patch as $key=>$value) {
        if (!in_array($key,$allowed,true) || (!is_bool($value) && !is_int($value) && !is_string($value))) throw new RuntimeException('invalid_cache_setting');
    }
    $conf=(array)get_option('litespeed-cache-conf',array());
    foreach ($patch as $key=>$value) $conf[$key]=$value;
    update_option('litespeed-cache-conf',$conf);
    $saved=(array)get_option('litespeed-cache-conf',array());
    foreach ($patch as $key=>$value) if (!array_key_exists($key,$saved) || $saved[$key] != $value) throw new RuntimeException('cache_settings_write_failed');
}

function ols_wpanel_inventory_retire_optimizer(): void
{
    if (is_multisite()) throw new RuntimeException('multisite_unsupported');
    $plugin = 'ols-wpanel-optimizer/ols-wpanel-optimizer.php';
    $active = (array)get_option('active_plugins', array());
    if (in_array($plugin, $active, true)) {
        // Do not execute the legacy uninstall hook: it also removes cache settings.
        update_option('active_plugins', array_values(array_diff($active, array($plugin))));
        if (in_array($plugin, (array)get_option('active_plugins', array()), true)) {
            throw new RuntimeException('optimizer_deactivation_failed');
        }
    }
    wp_clear_scheduled_hook('olsw_optimizer_preload_batch');
}

$token = (string) getenv('OLS_WPANEL_RUNNER_TOKEN');
$olsWPanelInventoryState['protocol'] = @fopen('php://fd/3', 'wb');
if (PHP_SAPI !== 'cli' || !preg_match('/^[0-9a-f]{32}$/', $token) || !is_resource($olsWPanelInventoryState['protocol'])) {
    ols_wpanel_inventory_fail('invalid_sapi');
    exit(2);
}

ob_start(static function (string $buffer) use (&$olsWPanelInventoryState): string {
    $olsWPanelInventoryState['bootstrap_output_bytes'] += strlen($buffer);
    return '';
}, 1);

register_shutdown_function(static function () use (&$olsWPanelInventoryState, &$olsWPanelInventoryEmergencyReserve): void {
    $olsWPanelInventoryEmergencyReserve = null;
    if ($olsWPanelInventoryState['emitted']) {
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
    $cachePatch=getenv('OLS_WPANEL_CACHE_SETTINGS');
    if (is_string($cachePatch) && $cachePatch !== '') ols_wpanel_inventory_migrate_cache(json_decode($cachePatch,true,8,JSON_THROW_ON_ERROR));
    if (getenv('OLS_WPANEL_RETIRE_OPTIMIZER') === '1') ols_wpanel_inventory_retire_optimizer();
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
