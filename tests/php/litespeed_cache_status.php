<?php
declare(strict_types=1);

// Exercise the shipped runner functions, without loading WordPress or touching a VPS.
$source = file_get_contents(__DIR__ . '/../../internal/executor/assets/wp-inventory-runner/inventory.php');
$start = strpos($source, 'function ols_wpanel_inventory_cache_value(');
$end = strpos($source, 'function ols_wpanel_inventory_retire_optimizer(', $start);
if ($start === false || $end === false) throw new RuntimeException('missing cache runner functions');
eval(substr($source, $start, $end - $start));

$options = [];
$filterValues = [];
$filterPriority = false;
$actionPriority = false;
$actionBehavior = 'save';
$filterCalls = 0;
$actionCalls = [];
$multisite = false;
$cases = 0;

function get_option($key, $default = false) {
    return array_key_exists($key, $GLOBALS['options']) ? $GLOBALS['options'][$key] : $default;
}
function has_filter($hook) {
    check($hook === 'litespeed_conf', 'official read hook');
    return $GLOBALS['filterPriority'];
}
function apply_filters($hook, $key) {
    check($hook === 'litespeed_conf', 'official read filter');
    $GLOBALS['filterCalls']++;
    return array_key_exists($key, $GLOBALS['filterValues']) ? $GLOBALS['filterValues'][$key] : $key;
}
function has_action($hook) {
    check($hook === 'litespeed_save_conf', 'official write hook');
    return $GLOBALS['actionPriority'];
}
function do_action($hook, $patch) {
    check($hook === 'litespeed_save_conf', 'official write action');
    $GLOBALS['actionCalls'][] = $patch;
    if ($GLOBALS['actionBehavior'] === 'reject') return;
    foreach ($patch as $key => $value) $GLOBALS['options']['litespeed.conf.' . $key] = $value;
    if ($GLOBALS['actionBehavior'] === 'persist_wrong') $GLOBALS['options']['litespeed.conf.object'] = false;
    if ($GLOBALS['actionBehavior'] === 'persist_invalid') $GLOBALS['options']['litespeed.conf.object'] = 'yes';
    if ($GLOBALS['actionBehavior'] === 'persist_canonical_strings') {
        foreach ($patch as $key => $value) {
            if (is_bool($value)) $GLOBALS['options']['litespeed.conf.' . $key] = $value ? '1' : '';
            elseif (is_int($value)) $GLOBALS['options']['litespeed.conf.' . $key] = (string)$value;
        }
    }
    if (!defined('LSCWP_DIR')) return;
    $runtime = [];
    foreach (['object-kind' => false, 'object-host' => 'localhost', 'object-port' => 11211, 'object-db_id' => 0, 'object-persistent' => true] as $key => $default) {
        $runtime[$key] = ols_wpanel_inventory_cache_value($key, $default);
    }
    $dropin = WP_CONTENT_DIR . '/object-cache.php';
    $data = LSCWP_CONTENT_DIR . '/.litespeed_conf.dat';
    if ($GLOBALS['actionBehavior'] === 'dropin_mismatch') file_put_contents($dropin, '<?php /* another plugin */');
    else copy(LSCWP_DIR . '/lib/object-cache.php', $dropin);
    if ($GLOBALS['actionBehavior'] === 'data_missing') return;
    if ($GLOBALS['actionBehavior'] === 'data_wrong') $runtime['object-port'] = 11211;
    if ($GLOBALS['actionBehavior'] === 'data_zero_missing') unset($runtime['object-db_id']);
    file_put_contents($data, json_encode($runtime, JSON_THROW_ON_ERROR));
}
function is_multisite() { return $GLOBALS['multisite']; }
function check($condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}
function expectFailure(string $message, callable $operation): void {
    try { $operation(); }
    catch (RuntimeException $error) {
        check($error->getMessage() === $message, 'expected ' . $message . ', got ' . $error->getMessage());
        return;
    }
    throw new RuntimeException('expected rejection: ' . $message);
}
function resetFixture(): void {
    $GLOBALS['options'] = [];
    $GLOBALS['filterValues'] = [];
    $GLOBALS['filterPriority'] = false;
    $GLOBALS['actionPriority'] = false;
    $GLOBALS['actionBehavior'] = 'save';
    $GLOBALS['filterCalls'] = 0;
    $GLOBALS['actionCalls'] = [];
    $GLOBALS['multisite'] = false;
    if (defined('WP_CONTENT_DIR')) {
        foreach ([WP_CONTENT_DIR . '/object-cache.php', LSCWP_CONTENT_DIR . '/.litespeed_conf.dat'] as $path) {
            if (is_file($path)) unlink($path);
        }
    }
}
function caseCheck(string $name, callable $operation): void {
    resetFixture();
    try { $operation(); }
    catch (Throwable $error) { throw new RuntimeException($name . ': ' . $error->getMessage(), 0, $error); }
    $GLOBALS['cases']++;
}
function redisSettings(): array {
    return ['cache' => true, 'object' => true, 'object-kind' => true, 'object-host' => 'localhost', 'object-port' => 6379, 'object-db_id' => 0];
}
function modernOptions(array $settings): array {
    $result = [];
    foreach ($settings as $key => $value) $result['litespeed.conf.' . $key] = $value;
    return $result;
}
function expectRedisStatus(bool $page): void {
    check(ols_wpanel_inventory_cache_status() === ['page_enabled' => $page, 'object_enabled' => true, 'host' => 'localhost', 'port' => 6379, 'database' => 0], 'current Redis configuration');
}

$mode = $argv[1] ?? '';
if ($mode === '') {
    $total = 0;
    foreach (['read', 'master_absent', 'master_false', 'master_true', 'migration', 'runtime_unavailable'] as $childMode) {
        // Keep the caller's relative path so Windows PHP does not re-encode a
        // Unicode absolute workspace path when creating the child process.
        $process = proc_open([PHP_BINARY, '-n', $argv[0], $childMode], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) throw new RuntimeException('cannot create isolated PHP fixture');
        $output = stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($process);
        if ($code !== 0 || !preg_match('/^' . preg_quote($childMode, '/') . ': (\d+) cases passed\s*$/D', $output, $matches)) {
            throw new RuntimeException($childMode . " failed\n" . $output . $errors);
        }
        $total += (int)$matches[1];
    }
    echo 'LiteSpeed cache status and migration: ' . $total . " cases passed\n";
    exit;
}

if ($mode === 'read') {
    caseCheck('modern per-key Redis settings', function (): void {
        $GLOBALS['options'] = modernOptions(redisSettings()) + ['litespeed-cache-conf' => ['cache' => false, 'object' => false, 'object-port' => 11211, 'object-db_id' => 8]];
        expectRedisStatus(true);
    });
    caseCheck('Redis independent of page cache', function (): void {
        $settings = redisSettings(); $settings['cache'] = false;
        $GLOBALS['options'] = modernOptions($settings);
        expectRedisStatus(false);
    });
    caseCheck('Memcached is not Redis', function (): void {
        $GLOBALS['options'] = modernOptions(['cache' => true, 'object' => true, 'object-kind' => false]);
        $status = ols_wpanel_inventory_cache_status();
        check(!$status['object_enabled'] && $status['port'] === 11211, 'Memcached default is not Redis');
    });
    caseCheck('official defaults', function (): void {
        check(ols_wpanel_inventory_cache_status() === ['page_enabled' => true, 'object_enabled' => false, 'host' => 'localhost', 'port' => 11211, 'database' => 0], 'plugin defaults');
    });
    caseCheck('official filter at priority zero', function (): void {
        $GLOBALS['filterPriority'] = 0;
        $GLOBALS['filterValues'] = redisSettings();
        $GLOBALS['options'] = modernOptions(['cache' => false, 'object' => false]);
        expectRedisStatus(true);
        check($GLOBALS['filterCalls'] > 0, 'priority zero callback is registered');
    });
    caseCheck('filter preserves false and zero', function (): void {
        $GLOBALS['filterPriority'] = 10;
        $settings = redisSettings(); $settings['cache'] = false;
        $GLOBALS['filterValues'] = $settings;
        $GLOBALS['options'] = modernOptions(['cache' => true, 'object-db_id' => 7]);
        expectRedisStatus(false);
    });
    caseCheck('missing filter never returns a slug', function (): void {
        $GLOBALS['options'] = modernOptions(['cache' => false, 'object' => false]);
        $status = ols_wpanel_inventory_cache_status();
        check(!$status['page_enabled'] && !$status['object_enabled'] && $GLOBALS['filterCalls'] === 0, 'absent hook is not applied');
    });
    caseCheck('legacy grouped configuration fallback', function (): void {
        $GLOBALS['options'] = ['litespeed-cache-conf' => redisSettings()];
        expectRedisStatus(true);
    });
    caseCheck('modern false and zero override legacy', function (): void {
        $GLOBALS['options'] = modernOptions(['cache' => false, 'object' => false, 'object-kind' => false, 'object-db_id' => 0]);
        $GLOBALS['options']['litespeed-cache-conf'] = ['cache' => true, 'object' => true, 'object-kind' => true, 'object-db_id' => 9];
        $status = ols_wpanel_inventory_cache_status();
        check(!$status['page_enabled'] && !$status['object_enabled'] && $status['database'] === 0, 'modern values retain their types');
    });
    caseCheck('persisted boolean and integer strings', function (): void {
        $GLOBALS['options'] = modernOptions(['cache' => '0', 'object' => '1', 'object-kind' => 'true', 'object-host' => 'localhost', 'object-port' => '6379', 'object-db_id' => '0']);
        expectRedisStatus(false);
    });
    caseCheck('invalid boolean fails collection', function (): void {
        $GLOBALS['options'] = modernOptions(['cache' => 'yes']);
        expectFailure('invalid_cache_setting', static fn() => ols_wpanel_inventory_cache_status());
    });
    caseCheck('host length bounded', function (): void {
        $GLOBALS['options'] = modernOptions(['object-host' => str_repeat('a', 400)]);
        check(strlen(ols_wpanel_inventory_cache_status()['host']) === 255, 'bounded host');
    });
} elseif ($mode === 'master_absent' || $mode === 'master_false' || $mode === 'master_true') {
    if ($mode !== 'master_absent') define('LITESPEED_CONF', $mode === 'master_true');
    define('LITESPEED_CONF__CACHE', false);
    define('LITESPEED_CONF__OBJECT', true);
    define('LITESPEED_CONF__OBJECT__KIND', true);
    define('LITESPEED_CONF__OBJECT__HOST', 'localhost');
    define('LITESPEED_CONF__OBJECT__PORT', 6379);
    define('LITESPEED_CONF__OBJECT__DB_ID', 0);
    if ($mode === 'master_true') {
        caseCheck('enabled master activates setting constants', function (): void {
            $GLOBALS['options'] = modernOptions(['cache' => true, 'object' => false, 'object-port' => 11211, 'object-db_id' => 9]);
            expectRedisStatus(false);
        });
        caseCheck('official filter precedes fallback constants', function (): void {
            $GLOBALS['filterPriority'] = 0;
            $GLOBALS['filterValues'] = ['cache' => true, 'object' => false, 'object-kind' => false, 'object-host' => 'forced.example', 'object-port' => 11211, 'object-db_id' => 2];
            $status = ols_wpanel_inventory_cache_status();
            check($status['page_enabled'] && !$status['object_enabled'] && $status['host'] === 'forced.example' && $status['database'] === 2, 'effective official settings take precedence');
        });
    } else {
        caseCheck('inactive master ignores setting constants', function (): void {
            $GLOBALS['options'] = modernOptions(['cache' => true, 'object' => false, 'object-kind' => false, 'object-host' => 'database.example', 'object-port' => 11211, 'object-db_id' => 3]);
            $status = ols_wpanel_inventory_cache_status();
            check($status['page_enabled'] && !$status['object_enabled'] && $status['host'] === 'database.example' && $status['port'] === 11211 && $status['database'] === 3, 'inactive constants do not mask stored configuration');
        });
        caseCheck('inactive override migration rejected', function (): void {
            $GLOBALS['actionPriority'] = 0;
            expectFailure('cache_overrides_inactive', static fn() => ols_wpanel_inventory_migrate_cache(['object' => true]));
            check($GLOBALS['actionCalls'] === [] && $GLOBALS['options'] === [], 'inactive constants never become persisted settings');
        });
    }
} elseif ($mode === 'migration' || $mode === 'runtime_unavailable') {
    define('LITESPEED_CONF', true);
    $fixtureRoot = null;
    if ($mode === 'migration') {
        $fixtureRoot = sys_get_temp_dir() . '/ols-cache-fixture-' . bin2hex(random_bytes(8));
        foreach ([$fixtureRoot, $fixtureRoot . '/plugin', $fixtureRoot . '/plugin/lib', $fixtureRoot . '/content', $fixtureRoot . '/runtime'] as $path) {
            if (!mkdir($path)) throw new RuntimeException('cannot create cache fixture directory');
        }
        define('LSCWP_DIR', $fixtureRoot . '/plugin');
        define('WP_CONTENT_DIR', $fixtureRoot . '/content');
        define('LSCWP_CONTENT_DIR', $fixtureRoot . '/runtime');
        file_put_contents(LSCWP_DIR . '/lib/object-cache.php', '<?php /* LiteSpeed fixture drop-in */');
    }
    $patch = ['object' => true, 'object-kind' => true, 'object-host' => 'localhost', 'object-port' => 6379, 'object-db_id' => 0, 'object-persistent' => true];
    try {
        if ($mode === 'runtime_unavailable') {
            caseCheck('runtime constants unavailable', function () use ($patch): void {
                $GLOBALS['actionPriority'] = 0;
                expectFailure('cache_runtime_files_unavailable', static fn() => ols_wpanel_inventory_migrate_cache($patch));
            });
        } else {
            caseCheck('missing official action rejected', function () use ($patch): void {
                expectFailure('cache_settings_api_unavailable', static fn() => ols_wpanel_inventory_migrate_cache($patch));
                check($GLOBALS['actionCalls'] === [] && $GLOBALS['options'] === [], 'no direct option write fallback');
            });
            caseCheck('unsupported setting rejected before API', function (): void {
                $GLOBALS['actionPriority'] = 0;
                expectFailure('invalid_cache_setting', static fn() => ols_wpanel_inventory_migrate_cache(['cache' => true]));
                check($GLOBALS['actionCalls'] === [], 'unrelated settings are not written');
            });
            caseCheck('invalid boolean rejected before API', function (): void {
                $GLOBALS['actionPriority'] = 0;
                expectFailure('invalid_cache_setting', static fn() => ols_wpanel_inventory_migrate_cache(['object' => 'yes']));
                check($GLOBALS['actionCalls'] === [], 'no invalid boolean writes');
            });
            caseCheck('invalid scalar rejected before API', function (): void {
                $GLOBALS['actionPriority'] = 0;
                expectFailure('invalid_cache_setting', static fn() => ols_wpanel_inventory_migrate_cache(['object-host' => ['localhost']]));
            });
            caseCheck('out-of-range port rejected before API', function (): void {
                $GLOBALS['actionPriority'] = 0;
                expectFailure('invalid_cache_setting', static fn() => ols_wpanel_inventory_migrate_cache(['object-port' => 65536]));
            });
            caseCheck('official partial patch and runtime refresh', function () use ($patch): void {
                $GLOBALS['actionPriority'] = 0;
                $GLOBALS['options'] = ['litespeed.conf.cache' => false, 'litespeed.conf.css_min' => true, 'litespeed-cache-conf' => ['cache' => true, 'object' => false]];
                ols_wpanel_inventory_migrate_cache($patch);
                check($GLOBALS['actionCalls'] === [$patch], 'official action receives partial patch at priority zero');
                check($GLOBALS['options']['litespeed.conf.cache'] === false && $GLOBALS['options']['litespeed.conf.css_min'] === true && $GLOBALS['options']['litespeed-cache-conf'] === ['cache' => true, 'object' => false], 'unrelated and legacy options preserved');
                expectRedisStatus(false);
            });
            caseCheck('canonical persisted strings accepted', function () use ($patch): void {
                $GLOBALS['actionPriority'] = 0;
                $GLOBALS['actionBehavior'] = 'persist_canonical_strings';
                $stringPatch = $patch; $stringPatch['object'] = '1'; $stringPatch['object-port'] = '6379'; $stringPatch['object-db_id'] = '0';
                ols_wpanel_inventory_migrate_cache($stringPatch);
                check($GLOBALS['actionCalls'] === [$patch], 'typed API patch');
                expectRedisStatus(true);
            });
            caseCheck('failed persisted write rejected', function () use ($patch): void {
                $GLOBALS['actionPriority'] = 0; $GLOBALS['actionBehavior'] = 'reject';
                expectFailure('cache_settings_write_failed', static fn() => ols_wpanel_inventory_migrate_cache($patch));
            });
            caseCheck('wrong persisted boolean rejected', function () use ($patch): void {
                $GLOBALS['actionPriority'] = 0; $GLOBALS['actionBehavior'] = 'persist_wrong';
                expectFailure('cache_settings_write_failed', static fn() => ols_wpanel_inventory_migrate_cache($patch));
            });
            caseCheck('invalid persisted boolean rejected', function () use ($patch): void {
                $GLOBALS['actionPriority'] = 0; $GLOBALS['actionBehavior'] = 'persist_invalid';
                expectFailure('invalid_cache_setting', static fn() => ols_wpanel_inventory_migrate_cache($patch));
            });
            caseCheck('missing runtime data rejected', function () use ($patch): void {
                $GLOBALS['actionPriority'] = 0; $GLOBALS['actionBehavior'] = 'data_missing';
                expectFailure('cache_runtime_files_write_failed', static fn() => ols_wpanel_inventory_migrate_cache($patch));
            });
            caseCheck('other object-cache drop-in rejected', function () use ($patch): void {
                $GLOBALS['actionPriority'] = 0; $GLOBALS['actionBehavior'] = 'dropin_mismatch';
                expectFailure('cache_runtime_files_write_failed', static fn() => ols_wpanel_inventory_migrate_cache($patch));
            });
            caseCheck('stale runtime port rejected', function () use ($patch): void {
                $GLOBALS['actionPriority'] = 0; $GLOBALS['actionBehavior'] = 'data_wrong';
                expectFailure('cache_runtime_files_write_failed', static fn() => ols_wpanel_inventory_migrate_cache($patch));
            });
            caseCheck('missing zero-valued database rejected', function () use ($patch): void {
                $GLOBALS['actionPriority'] = 0; $GLOBALS['actionBehavior'] = 'data_zero_missing';
                expectFailure('cache_runtime_files_write_failed', static fn() => ols_wpanel_inventory_migrate_cache($patch));
            });
            caseCheck('disabled object cache needs no runtime files', function (): void {
                $GLOBALS['actionPriority'] = 0; $GLOBALS['actionBehavior'] = 'data_missing';
                ols_wpanel_inventory_migrate_cache(['object' => false]);
                check($GLOBALS['options']['litespeed.conf.object'] === false, 'disabled object setting persisted');
            });
            caseCheck('debug disable all needs no runtime files', function () use ($patch): void {
                $GLOBALS['actionPriority'] = 0; $GLOBALS['actionBehavior'] = 'data_missing';
                $GLOBALS['options']['litespeed.conf.debug-disable-all'] = true;
                ols_wpanel_inventory_migrate_cache($patch);
            });
            caseCheck('multisite migration rejected', function () use ($patch): void {
                $GLOBALS['multisite'] = true; $GLOBALS['actionPriority'] = 0;
                expectFailure('multisite_unsupported', static fn() => ols_wpanel_inventory_migrate_cache($patch));
                check($GLOBALS['actionCalls'] === [], 'multisite write blocked');
            });
            caseCheck('empty patch is a no-op', function (): void {
                ols_wpanel_inventory_migrate_cache([]);
                check($GLOBALS['actionCalls'] === [], 'empty patch does not invoke API');
            });
        }
    } finally {
        if ($fixtureRoot !== null) {
            resetFixture();
            unlink(LSCWP_DIR . '/lib/object-cache.php');
            foreach ([$fixtureRoot . '/plugin/lib', $fixtureRoot . '/plugin', $fixtureRoot . '/content', $fixtureRoot . '/runtime', $fixtureRoot] as $path) rmdir($path);
        }
    }
} else {
    throw new RuntimeException('unknown fixture mode');
}
echo $mode . ': ' . $cases . " cases passed\n";
