<?php
/** Restricted maintenance UI. No password is stored in WordPress. */
if (!defined('ABSPATH')) exit;

trait OLSW_Optimizer_Maintenance_Trait {
    public static function maintenance_hooks() {
        add_action('admin_bar_menu', [__CLASS__, 'maintenance_bar'], 110);
        add_action('admin_enqueue_scripts', [__CLASS__, 'maintenance_assets']);
        add_action('admin_footer', [__CLASS__, 'maintenance_dialog']);
        add_action('wp_ajax_olsw_maintenance', [__CLASS__, 'maintenance_ajax']);
    }

    public static function maintenance_bar($bar) {
        if (!is_admin() || !current_user_can('manage_options') || is_multisite()) return;
        $bar->add_node(['id' => 'olsw-maintenance', 'title' => 'OLS WPanel: …', 'href' => '#olsw-maintenance-dialog']);
    }

    public static function maintenance_assets() {
        if (!current_user_can('manage_options') || is_multisite()) return;
        $base = plugin_dir_url(OLSW_OPTIMIZER_PLUGIN_FILE);
        wp_enqueue_style('olsw-maintenance', $base . 'assets/maintenance.css', [], self::VERSION);
        wp_enqueue_script('olsw-maintenance', $base . 'assets/maintenance.js', [], self::VERSION, true);
        wp_localize_script('olsw-maintenance', 'WPPMaintenance', [
            'url' => admin_url('admin-ajax.php'), 'nonce' => wp_create_nonce('olsw_maintenance'),
            'text' => [
                'locked'=>__('Locked', 'ols-wpanel-optimizer'), 'unlocked'=>__('Unlocked', 'ols-wpanel-optimizer'), 'unlocked_permanent'=>__('File lock disabled', 'ols-wpanel-optimizer'),
                'unlocking'=>__('Unlocking', 'ols-wpanel-optimizer'), 'relocking'=>__('Relocking', 'ols-wpanel-optimizer'), 'relock_failed'=>__('Relock failed — contact administrator', 'ols-wpanel-optimizer'),
                'unknown'=>__('State unknown', 'ols-wpanel-optimizer'), 'unlock'=>__('Temporary unlock', 'ols-wpanel-optimizer'), 'relock'=>__('Relock now', 'ols-wpanel-optimizer'), 'close'=>__('Close', 'ols-wpanel-optimizer'),
                'password'=>__('Maintenance password', 'ols-wpanel-optimizer'), 'extend'=>__('Add', 'ols-wpanel-optimizer'), 'minute'=>__('minutes', 'ols-wpanel-optimizer'), 'busy'=>__('Processing…', 'ols-wpanel-optimizer'),
                'warning'=>__('Extend before expiry if the update is unfinished. Relocking at expiry or panel restart may interrupt updates.', 'ols-wpanel-optimizer'),
                'restart'=>__('Panel restart ended the maintenance window early. Enter the password again to start a new window.', 'ols-wpanel-optimizer'),
                'disabled'=>__('Ask the panel owner to enable maintenance.', 'ols-wpanel-optimizer'), 'password_required'=>__('Enter the maintenance password; verification is required again across each 30-minute boundary.', 'ols-wpanel-optimizer'),
                'password_not_required'=>__('Relocking now and extensions that stay within the current 30-minute verification period do not require the password again.', 'ols-wpanel-optimizer'),
                'password_boundary'=>__('Only an extension that crosses the current 30-minute verification boundary requires the password again. Relocking never requires it.', 'ols-wpanel-optimizer'),
                'verification_failed'=>__('Verification failed. Please check the maintenance password.', 'ols-wpanel-optimizer'), 'operation_unavailable'=>__('Operation unavailable. Refresh or contact the administrator.', 'ols-wpanel-optimizer'),
                'verification_frozen'=>__('Too many failed attempts. Password verification has been suspended for 10 minutes. Please try again later.', 'ols-wpanel-optimizer'),
                'lock_mode_required'=>__('Ask the panel owner to apply Standard or Strict file lock before enabling maintenance.', 'ols-wpanel-optimizer'),
                'state_unknown'=>__('State unknown. Refresh or contact the administrator.', 'ols-wpanel-optimizer'), 'invalid_request'=>__('Invalid request', 'ols-wpanel-optimizer'),
            ],
        ]);
    }

    public static function maintenance_dialog() {
        if (!current_user_can('manage_options') || is_multisite()) return;
        $title = __('File protection / maintenance', 'ols-wpanel-optimizer');
        $intro = __('File protection is managed by OLS WPanel. Temporarily unlock it with the maintenance password when installing, updating, or changing plugins and themes.', 'ols-wpanel-optimizer');
        echo '<dialog id="olsw-maintenance-dialog" aria-labelledby="olsw-maintenance-title">'
            . '<header class="olsw-maintenance-head"><img src="' . esc_url(plugin_dir_url(OLSW_OPTIMIZER_PLUGIN_FILE) . 'assets/ols-wpanel-logo.png') . '" alt=""><div><span>OLS WPANEL · MANAGED WORDPRESS</span><h2 id="olsw-maintenance-title">' . esc_html($title) . '</h2></div></header>'
            . '<div class="olsw-maintenance-body"><p class="olsw-maintenance-intro">' . esc_html($intro) . '</p><p id="olsw-maintenance-state" role="status"></p><p id="olsw-maintenance-warning"></p>'
            . '<form id="olsw-maintenance-form"><label id="olsw-maintenance-password-label" for="olsw-maintenance-password"></label><input id="olsw-maintenance-password" type="password" autocomplete="new-password" spellcheck="false" maxlength="72"><p id="olsw-maintenance-password-hint"></p><div id="olsw-maintenance-actions"></div></form><p id="olsw-maintenance-message" role="alert"></p></div>'
            . '<footer class="olsw-maintenance-foot"><button type="button" id="olsw-maintenance-close"></button></footer></dialog>';
    }

    public static function maintenance_ajax() {
        if (!current_user_can('manage_options') || is_multisite()) wp_send_json_error(['message'=>'verification_failed'], 403);
        check_ajax_referer('olsw_maintenance', 'nonce');
        $op = isset($_POST['operation']) && is_string($_POST['operation']) ? sanitize_key(wp_unslash($_POST['operation'])) : '';
        if (!in_array($op, ['status','unlock','extend','relock'], true)) wp_send_json_error(['message'=>'invalid_request'], 400);
        $url = rtrim((string) self::get_panel_url(), '/');
        // This password-bearing path is loopback-only and never follows a redirect.
        if (!preg_match('~^https://(?:127\.0\.0\.1|\[::1\]):[0-9]+/[A-Za-z0-9_-]+$~D', $url)) wp_send_json_error(['message'=>'state_unknown'], 503);
        $body = [];
        if ($op !== 'status') {
            foreach (['window_id','request_id','password'] as $key) {
                if (isset($_POST[$key]) && !is_string($_POST[$key])) wp_send_json_error(['message'=>'invalid_request'], 400);
                $body[$key] = isset($_POST[$key]) ? wp_unslash($_POST[$key]) : '';
            }
            if (strlen($body['password']) > 72 || strlen($body['window_id']) > 36 || strlen($body['request_id']) > 36) wp_send_json_error(['message'=>'invalid_request'], 400);
            foreach (['minutes', 'revision'] as $key) {
                if (isset($_POST[$key]) && !is_scalar($_POST[$key])) wp_send_json_error(['message'=>'invalid_request'], 400);
            }
            $body['minutes'] = isset($_POST['minutes']) ? absint($_POST['minutes']) : 0;
            $body['revision'] = isset($_POST['revision']) ? absint($_POST['revision']) : 0;
            $body['actor'] = (string) get_current_user_id(); // Site-asserted, not panel-verified.
        }
        $args = ['method'=>$op === 'status' ? 'GET' : 'POST', 'timeout'=>20, 'redirection'=>0, 'sslverify'=>false,
            'headers'=>['X-OLS-WPanel-Key'=>self::get_api_key(), 'Content-Type'=>'application/json']];
        if ($op !== 'status') $args['body'] = wp_json_encode($body);
        $response = wp_remote_request($url . '/api/sites/maintenance' . ($op === 'status' ? '' : '/' . $op), $args);
        unset($body, $args);
        if (is_wp_error($response)) wp_send_json_error(['message'=>'state_unknown'], 503);
        $data = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($data) || empty($data['success'])) {
            $allowed = ['password_required','verification_failed','verification_frozen','operation_unavailable','state_unknown','invalid_request','lock_mode_required'];
            $code = isset($data['message']) && in_array($data['message'], $allowed, true) ? $data['message'] : 'state_unknown';
            wp_send_json_error(['message'=>$code], 409);
        }
        if (isset($data['data']['state'])) {
            // Refresh the pre-existing optimization guard after a maintenance action.
            self::update_file_lock_state_option(['file_lock_enabled'=>$data['data']['state'] !== 'unlocked' && $data['data']['state'] !== 'unlocked_permanent']);
            delete_transient(self::FILE_LOCK_STATE_TRANSIENT);
        }
        wp_send_json_success($data['data']);
    }
}
