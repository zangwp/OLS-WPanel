<?php
/**
 * Plugin Name: OLS WPanel Optimizer
 * Plugin URI:  https://github.com/zangwp/OLS-WPanel
 * Description: Companion plugin for OLS WPanel: manages LiteSpeed Cache, preload, Redis-aware optimization, debug mode, post revisions and memory limits.
 * Version:     1.1.28
 * Author:      OLS WPanel Project
 * Author URI:  https://github.com/zangwp
 * License:     GPL-2.0+
 * Text Domain: ols-wpanel-optimizer
 * Domain Path: /languages
 */

// AI/开发者注意：这是由 OLS WPanel 自动部署和更新的托管组件。请勿直接修改
// 此插件目录；面板可在 AI 开发访问或临时维护期间用内嵌版本完整覆盖这些文件。
// AI/developer notice: OLS WPanel owns this plugin directory and may replace it
// from its embedded copy at any time. Do not make site-specific edits here.

if (!defined('ABSPATH')) exit;

register_uninstall_hook(__FILE__, 'olsw_optimizer_uninstall');
function olsw_optimizer_uninstall() {
    delete_option('olsw_optimizer_litespeed_cache_enabled');
    delete_option('olsw_optimizer_litespeed_cache_ttl');
    delete_option('olsw_optimizer_no_updates');
    delete_option('olsw_optimizer_no_file_edit');
    delete_option('olsw_optimizer_verified');
    delete_option('olsw_optimizer_log');
    delete_option('olsw_optimizer_xmlrpc_enabled');
    delete_option('olsw_optimizer_disable_application_passwords');
    delete_option('olsw_optimizer_wp_debug');
    delete_option('olsw_optimizer_post_revisions');
    delete_option('olsw_optimizer_memory_limit');
    delete_option('olsw_optimizer_file_lock_enabled');
    delete_option('olsw_optimizer_anomaly_monitor_status');
    delete_option('olsw_optimizer_password_reset_mode');
    delete_transient('olsw_optimizer_file_lock_state');
    delete_option('olsw_optimizer_preload_enabled');
    delete_option('olsw_optimizer_preload_limit');
    delete_option('olsw_optimizer_preload_queue');
    delete_option('olsw_optimizer_preload_status');
    wp_clear_scheduled_hook('olsw_optimizer_preload_batch');
    delete_option('olsw_optimizer_image_mode');
    delete_option('olsw_optimizer_image_jpeg_quality');
    delete_option('olsw_optimizer_image_webp_quality');
    delete_option('olsw_optimizer_image_skipped_count');
}


// 拆分成 trait 文件后 __FILE__ 在 trait 内部指向的是 includes/ 下的文件，不是本文件；
// plugin_action_links_{basename} 这个钩子名必须精确匹配主文件的 basename，用一个
// 在主文件里求值的常量传给 trait，不能在 trait 内部重新取 __FILE__。
define('OLSW_OPTIMIZER_PLUGIN_FILE', __FILE__);

require_once __DIR__ . '/includes/trait-config.php';
require_once __DIR__ . '/includes/trait-cache.php';
require_once __DIR__ . '/includes/trait-settings.php';
require_once __DIR__ . '/includes/trait-image-optimizer.php';
require_once __DIR__ . '/includes/trait-maintenance.php';
require_once __DIR__ . '/includes/trait-anomaly-monitor.php';

class OLS_WPanel_Optimizer {

    use OLSW_Optimizer_Config_Trait;
    use OLSW_Optimizer_Cache_Trait;
    use OLSW_Optimizer_Settings_Trait;
    use OLSW_Optimizer_Image_Trait;
    use OLSW_Optimizer_Maintenance_Trait;
    use OLSW_Optimizer_Anomaly_Monitor_Trait;

    const VERSION = '1.1.28';

    const OPTION_LSCACHE_ENABLED = 'olsw_optimizer_litespeed_cache_enabled';
    const OPTION_LSCACHE_TTL     = 'olsw_optimizer_litespeed_cache_ttl';
    const OPTION_NO_UPDATES     = 'olsw_optimizer_no_updates';
    const OPTION_NO_FILE_EDIT   = 'olsw_optimizer_no_file_edit';
    const OPTION_VERIFIED       = 'olsw_optimizer_verified';
    const OPTION_LOG            = 'olsw_optimizer_log';
    const OPTION_XMLRPC_ENABLED = 'olsw_optimizer_xmlrpc_enabled';
    const OPTION_DISABLE_APPLICATION_PASSWORDS = 'olsw_optimizer_disable_application_passwords';
    const OPTION_WP_DEBUG       = 'olsw_optimizer_wp_debug';
    const OPTION_POST_REVISIONS = 'olsw_optimizer_post_revisions';
    const OPTION_MEMORY_LIMIT   = 'olsw_optimizer_memory_limit';
    const OPTION_FILE_LOCK_ENABLED = 'olsw_optimizer_file_lock_enabled';
    const OPTION_ANOMALY_MONITOR_STATUS = 'olsw_optimizer_anomaly_monitor_status';
    const OPTION_PASSWORD_RESET_MODE = 'olsw_optimizer_password_reset_mode';
    const FILE_LOCK_STATE_TRANSIENT = 'olsw_optimizer_file_lock_state';
    const FILE_LOCK_STATE_TTL       = 300;
    const OPTION_PRELOAD_ENABLED = 'olsw_optimizer_preload_enabled';
    const OPTION_PRELOAD_LIMIT   = 'olsw_optimizer_preload_limit';
    const OPTION_PRELOAD_QUEUE   = 'olsw_optimizer_preload_queue';
    const OPTION_PRELOAD_STATUS  = 'olsw_optimizer_preload_status';
    const PRELOAD_HOOK           = 'olsw_optimizer_preload_batch';
    const PRELOAD_BATCH_SIZE     = 5;
    const PRELOAD_TICK_THROTTLE  = 50;
}

add_action('plugins_loaded', ['OLS_WPanel_Optimizer', 'bootstrap'], 1);
add_action('init', ['OLS_WPanel_Optimizer', 'init']);
add_action('init', ['OLS_WPanel_Optimizer', 'maintenance_hooks']);

// 自托管分发，语言包只随插件自带；init 阶段 locale 已就绪（含用户个人语言设置）。
add_action('init', function () {
    load_plugin_textdomain('ols-wpanel-optimizer', false, dirname(plugin_basename(OLSW_OPTIMIZER_PLUGIN_FILE)) . '/languages');
}, 1);

add_action('wp_ajax_olsw_optimizer_verify', function() {
    check_ajax_referer('olsw_optimizer_settings');
    if (!current_user_can('manage_options')) {
        wp_send_json(['success' => false, 'data' => ['message' => __('Insufficient permissions', 'ols-wpanel-optimizer')]]);
        return;
    }
    $domain = wp_parse_url(home_url(), PHP_URL_HOST);
    $resp = OLS_WPanel_Optimizer::api_request_public('GET', '/api/sites/find?domain=' . urlencode($domain));
    if (!$resp || is_wp_error($resp)) {
        $err = is_wp_error($resp) ? $resp->get_error_message() : __('No response; please check the panel address', 'ols-wpanel-optimizer');
        wp_send_json(['success' => false, 'data' => ['message' => $err]]);
        return;
    }
    $data = json_decode($resp, true);
    if (!empty($data['success'])) {
        update_option(OLS_WPanel_Optimizer::OPTION_VERIFIED, '1');
        wp_send_json(['success' => true, 'data' => ['message' => __('Connection successful', 'ols-wpanel-optimizer')]]);
    } else {
        wp_send_json(['success' => false, 'data' => ['message' => $data['message'] ?? __('API returned an error', 'ols-wpanel-optimizer')]]);
    }
});
