package router

import (
	"database/sql"
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"path/filepath"

	"github.com/zangwp/OLS-WPanel/internal/accountsecurity"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/handlers"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/middleware"

	"github.com/gin-gonic/gin"
)

var panelVersion string

var i18nKeys = []string{
	"auth.login",
	"auth.workspace_login",
	"auth.workspace_prompt",
	"followup.invalid_config",
	"followup.invalid_threshold",
	"followup.load_failed",
	"followup.loading_config",
	"followup.loading_logs",
	"followup.retry_load",
	"followup.retry_save",
	"followup.save_before_test",
	"followup.saved_reload_failed",
	"followup.smtp_save_first",
	"followup.status_unknown",

	"settings.mfa_backup_help",

	"account_security.event_notifications_changed",

	"account_security.actions",
	"account_security.activity_help",
	"account_security.add_authenticator",
	"account_security.audit",
	"account_security.audit_help",
	"account_security.authenticator_code",
	"account_security.change_password",
	"account_security.code_or_recovery",
	"account_security.codes_remaining",
	"account_security.codes_saved_confirm",
	"account_security.codes_stored",
	"account_security.configure_channels",
	"account_security.configured",
	"account_security.confirm_revoke",
	"account_security.confirm_revoke_others",
	"account_security.copied",
	"account_security.copy_codes",
	"account_security.copy_failed",
	"account_security.create_setup",
	"account_security.credentials_required",
	"account_security.current_password",
	"account_security.current_session",
	"account_security.device",
	"account_security.disable",
	"account_security.disable_warning",
	"account_security.disabled_done",
	"account_security.download_codes",
	"account_security.enable_notifications",
	"account_security.enabled",
	"account_security.enabled_done",
	"account_security.event",
	"account_security.event_credentials_changed",
	"account_security.event_login_blocked",
	"account_security.event_login_failure",
	"account_security.event_login_success",
	"account_security.event_logout",
	"account_security.event_mfa_disabled",
	"account_security.event_mfa_enabled",
	"account_security.event_recovery_regenerated",
	"account_security.event_recovery_used",
	"account_security.event_session_revoked",
	"account_security.event_sessions_revoked",
	"account_security.event_time",
	"account_security.finish",
	"account_security.last_active",
	"account_security.login_time",
	"account_security.mfa_already_enabled",
	"account_security.mfa_help",
	"account_security.mfa_invalid_code",
	"account_security.mfa_invalid_password",
	"account_security.mfa_not_enabled",
	"account_security.mfa_rate_limited",
	"account_security.mfa_setup_expired",
	"account_security.mfa_title",
	"account_security.mfa_unavailable",
	"account_security.missing_recovery_codes",
	"account_security.next",
	"account_security.no_audit",
	"account_security.no_channels",
	"account_security.no_sessions",
	"account_security.not_configured",
	"account_security.not_enabled",
	"account_security.notification_disabled",
	"account_security.notification_failed",
	"account_security.notification_none",
	"account_security.notification_pending",
	"account_security.notification_sent",
	"account_security.notification_status",
	"account_security.notification_suppressed",
	"account_security.notification_unconfigured",
	"account_security.notifications",
	"account_security.notifications_help",
	"account_security.notifications_saved",
	"account_security.open_authenticator",
	"account_security.other_sessions_revoked",
	"account_security.pagination",
	"account_security.previous",
	"account_security.recovery_once",
	"account_security.regenerate",
	"account_security.regenerate_warning",
	"account_security.regenerated_done",
	"account_security.revoke",
	"account_security.revoke_others",
	"account_security.save_recovery_codes",
	"account_security.sessions",
	"account_security.sessions_help",
	"account_security.sessions_revoked",
	"account_security.setup",
	"account_security.setup_expires",
	"account_security.setup_help",
	"account_security.setup_key",
	"account_security.setup_key_help",
	"account_security.six_digits",
	"account_security.subtitle",
	"account_security.unknown_device",
	"account_security.unusual_activity",
	"account_security.username",
	"account_security.verify_enable",
	"account_security.working",
	"auth.account_security_unavailable",
	"auth.invalid_security_request",
	"auth.session_not_found",
	"security_center.access",
	"security_center.access_help",
	"security_center.account",
	"security_center.account_help",
	"security_center.activity",
	"security_center.activity_help",
	"security_center.alert_settings",
	"security_center.firewall_events",
	"security_center.incomplete_settings",
	"security_center.loading_settings",
	"security_center.no_cdn_groups",
	"security_center.protection",
	"security_center.protection_help",
	"security_center.refresh_queued",
	"security_center.reload_settings",
	"security_center.request_failed",
	"security_center.retry",
	"security_center.saved_runtime_refreshed",
	"security_center.saved_status_unavailable",
	"security_center.sections",
	"security_center.settings_load_failed",
	"security_center.subtitle",
	"security_center.title",

	"auth.back_credentials",
	"auth.code_required",
	"auth.mfa_code",
	"auth.mfa_code_help",
	"auth.mfa_prompt",
	"auth.mfa_title",
	"auth.recovery_code",
	"auth.recovery_help",
	"auth.use_authenticator",
	"auth.use_recovery",
	"auth.verify_login",
	"common.retry",
	"settings.account_load_failed",
	"settings.current_web_password",
	"settings.mfa_code_optional",
	"settings.security_center_link",

	"ssh_port.title",
	"ssh_port.help",
	"ssh_port.current",
	"ssh_port.new",
	"ssh_port.scope",
	"ssh_port.cloud",
	"ssh_port.apply",
	"ssh_port.confirm_begin",
	"ssh_port.transition",
	"ssh_port.verify_help",
	"ssh_port.command",
	"ssh_port.deadline",
	"ssh_port.confirm",
	"ssh_port.saved",

	"firewall.access_everyone",
	"firewall.access_local",
	"firewall.access_public",
	"firewall.access_loopback",
	"firewall.scope_any",
	"firewall.access_title",
	"firewall.access_active",
	"firewall.access_draft",
	"firewall.access_help",
	"firewall.access_listening",
	"firewall.access_not_listening",
	"firewall.access_closed",
	"firewall.access_sources_hint",
	"firewall.access_add",
	"firewall.access_unsaved",
	"firewall.access_pending",
	"firewall.access_invalid_port",
	"firewall.access_duplicate_port",
	"firewall.access_discard",
	"firewall.access_preserve",
	"firewall.access_preview",
	"firewall.access_unavailable",
	"firewall.access_conflicts",
	"firewall.access_existing",
	"firewall.access_apply",
	"firewall.access_apply_confirm",
	"firewall.access_verify",
	"firewall.access_deadline",
	"firewall.access_verified",
	"firewall.access_confirm",
	"firewall.access_saved",
	"firewall.access_legacy",

	"website.job_success",
	"website.job_failed",
	"website.job_started",
	"website.job_no_record",

	"website.cert_auto",
	"website.cert_manual",
	"website.renewal_enabled",
	"website.renewal_help",
	"website.renewal_manual_help",
	"website.scheduled_wp",
	"website.scheduled_wp_help",
	"website.scheduled_wp_enabled",
	"website.scheduled_wp_suspended",
	"website.scheduled_wp_example",
	"website.scheduled_wp_last",
	"website.scheduled_wp_enable",
	"cron.overview_help",
	"cron.site_settings",

	"software.suggested_value",
	"software.recommend_refreshed",
	"settings.sync",
	"settings.ntp_starting",
	"settings.ntp_waiting",
	"website.litespeed_plugin_missing",
	"website.litespeed_plugin_inactive",
	"website.optimizer_retire_confirm", "website.optimizer_retire_done",
	"website.litespeed_plugin_active",
	"anomaly.disabled", "anomaly.pending", "anomaly.last_success", "anomaly.post_count", "anomaly.application_password_count", "anomaly.application_password_pending", "anomaly.database_object_count", "anomaly.database_object_pending",
	"anomaly.plugin_required", "anomaly.multisite_unsupported", "anomaly.site_busy", "anomaly.site_unavailable",
	"anomaly.sample_malformed", "anomaly.sample_too_large",
	"anomaly.busy", "anomaly.invalid", "anomaly.failed",
	"alert.type_wp_admin_change", "alert.type_wp_post_volume", "alert.type_wp_content_change", "alert.type_wp_content_volume", "alert.type_wp_setting_change", "alert.type_wp_application_password", "alert.type_wp_database_object", "alert.type_wp_code_integrity",
	"maintenance.locked", "maintenance.unlocked", "maintenance.unlocked_permanent", "maintenance.unlocking",
	"maintenance.relocking", "maintenance.relock_failed", "maintenance.unknown", "maintenance.state_unknown",
	"maintenance.operation_unavailable", "maintenance.verification_failed", "maintenance.password_required",
	"maintenance.lock_mode_required",
	"maintenance.copied", "maintenance.invalid_configuration",
	"auth.connect_failed",
	"auth.login_failed",
	"auth.missing_credentials",
	"auth.session_expired",
	"settings.saving",
	"security.save_settings",
	"software.action_success",
	"software.config_updated",
	"software.confirm_clear_log",
	"software.confirm_restart_service",
	"software.confirm_stop_service",
	"software.current_value",
	"software.development_tool_install_confirm",
	"software.development_tool_installed",
	"software.install",
	"software.installing",
	"software.log_cleared",
	"software.log_cleared_placeholder",
	"software.log_load_failed",
	"software.log_load_failed_with_error",
	"software.log_loading",
	"software.log_title",
	"software.nodejs_development_help",
	"software.php_runtime_install_confirm",
	"software.php_runtime_installed",
	"software.php_runtime_site_count",
	"software.recommended",
	"software.recovery_count",
	"software.update_available_candidate",
	"software.wp_cli_development_help",
	"website.created",
	"website.created_ssl_warning",
	"website.db_password_php_placeholder",
	"website.db_password_wp_placeholder",
	"website.alias_preview_same_site",
	"website.alias_redirect_301",
	"website.alias_redirect_302",
	"website.alias_serve_same_site",
	"website.alias_not_configured",
	"website.check_dns",
	"website.dns_check_attention",
	"website.dns_check_passed",
	"website.dns_checking",
	"website.dns_fix_before_ssl",
	"website.https_forced",
	"website.https_requires_ssl",
	"website.manual_ssl_domains_help",
	"website.reissue_ssl_domains_help",
	"website.ssl_precheck_failed",
	"website.ssl_precheck_warning",
	"backups.backup_auto",
	"backups.backup_manual",
	"backups.authorize_delete_tasks",
	"backups.authorize_rebuild_tasks",
	"backups.batch_saved",
	"backups.batch_saved_with_skips",
	"backups.confirm_rebuild_tasks",
	"backups.duplicate_mode_tasks",
	"backups.actions",
	"backups.clean_record",
	"backups.collapse_all",
	"backups.confirm_clean_record",
	"backups.confirm_delete_local",
	"backups.delete",
	"backups.deleted",
	"backups.download",
	"backups.expand_all",
	"backups.mode_full",
	"backups.mode_incremental",
	"backups.no_backups",
	"backups.summary_db_count",
	"backups.summary_file_count",
	"backups.transport_failed",
	"backups.transport_local",
	"backups.transport_missing",
	"backups.transport_synced",
	"backups.reconcile_remote_status",
	"backups.reconcile_success",
	"backups.reconciling",
	"backups.remote_disabled",
	"backups.remote_disabled_help",
	"backups.remote_enabled",
	"backups.remote_enabled_help",
	"backups.saving",
	"backups.remote_chain_healthy",
	"backups.remote_chain_cleanup_pending",
	"backups.remote_chain_repair_pending",
	"backups.remote_chain_rebuild",
	"backups.remote_chain_unknown",
	"backups.transport_synced_remote_only",
	"common.cancel",
	"common.confirm",
	"common.none",
	"common.operation_success",
	"common.save",
	"common.network_error",
	"common.operation_failed",
	"common.request_cancelled",
	"common.request_failed",
	"common.request_timeout",
	"common.saving",
	"common.loading",
	"common.service_busy",
	"common.service_exception",
	"cron.day_separator",
	"cron.full_backup",
	"cron.incremental_backup",
	"cron.schedule_daily",
	"cron.schedule_monthly",
	"cron.schedule_quarterly",
	"cron.schedule_weekly",
	"cron.weekday_friday",
	"cron.weekday_monday",
	"cron.weekday_saturday",
	"cron.weekday_sunday",
	"cron.weekday_thursday",
	"cron.weekday_tuesday",
	"cron.weekday_wednesday",
	"database.adminer_active_for",
	"database.adminer_database_password",
	"database.adminer_database_password_help",
	"database.adminer_disable",
	"database.adminer_disabled",
	"database.adminer_duration",
	"database.adminer_enable",
	"database.adminer_enable_failed",
	"database.adminer_enabled",
	"database.adminer_expires_at",
	"database.adminer_help",
	"database.adminer_indefinite",
	"database.adminer_minutes",
	"database.adminer_open",
	"database.adminer_starting",
	"database.adminer_stopping",
	"database.adminer_title",
	"database.adminer_warning",
	"dashboard.chart_load",
	"dashboard.chart_memory",
	"dashboard.close",
	"dashboard.swap_usage",
	"dashboard.system_updates",
	"dashboard.tooltip_time",
	"dashboard.update_available",
	"files.root_directory",
	"settings.account_saved_please_relogin",
	"settings.basic_auth_saved",
	"settings.basic_auth_username_required",
	"settings.current_password_required_for_account",
	"settings.save_basic_auth",
	"settings.save_web_account",
	"settings.section_updates",
	"settings.server_settings",
	"settings.web_username_required",
	"settings.operation_panel_manual_update",
	"settings.operation_panel_auto_update",
	"settings.operation_swap_apply_recommended",
	"settings.operation_swap_remove_managed",
	"settings.operation_swap_apply_custom",
	"settings.operation_nftables_enable_boot",
	"settings.operation_dns_apply_preset",
	"settings.operation_dns_restore_automatic",
	"settings.operation_firewall_port_open",
	"settings.operation_firewall_port_close",
	"settings.operation_firewall_protection_enable",
	"settings.operation_firewall_protection_confirm",
	"settings.operation_create_site",
	"settings.operation_wp_package_auto_check",
	"settings.operation_litespeed_cache_recommended",
	"settings.operation_redis_object_cache_clear",
	"settings.operation_wp_optimizations",
	"settings.operation_wp_update_checks",
	"settings.operation_wp_file_editor",
	"settings.operation_wp_password_reset",
	"settings.ai_settings_saved",
	"settings.api_key_placeholder",
	"settings.auto_update_saved",
	"settings.available_count",
	"settings.hide_update_list",
	"settings.no_matching_updates",
	"settings.show_update_list",
	"settings.update_filter_all",
	"settings.update_filter_regular",
	"settings.update_filter_security",
	"settings.backing_up",
	"settings.backup_finished",
	"settings.backup_now",
	"settings.basic_auth_password_min_length",
	"settings.check_updates",
	"settings.checking",
	"settings.command_copied",
	"settings.command_copied_short",
	"settings.connection_mode_advanced_help",
	"settings.connection_mode_auto_help",
	"settings.confirm_delete_backup",
	"settings.confirm_delete_local_wp_package",
	"settings.confirm_restore_db_backup",
	"settings.confirm_system_update",
	"settings.confirm_update_version",
	"settings.connection_failed",
	"settings.connection_failed_with_reason",
	"settings.connection_ok",
	"settings.connection_ok_with_latency",
	"settings.current_password_required",
	"settings.delete",
	"settings.deleted",
	"settings.deleting",
	"settings.disabled",
	"settings.downloaded",
	"settings.downloading",
	"settings.downloading_update_package",
	"settings.enabled",
	"settings.failed",
	"settings.new_password_min_length",
	"settings.no_changes",
	"settings.no_data",
	"settings.ntp_not_synced",
	"settings.ntp_synced",
	"settings.one_click_update",
	"settings.online_download",
	"settings.package_download_complete",
	"settings.package_not_installed",
	"settings.package_ready",
	"settings.wp_package_check_status_failed",
	"settings.wp_package_check_status_up_to_date",
	"settings.wp_package_check_status_updated",
	"settings.wp_package_never_checked",
	"settings.panel_restarting",
	"settings.passwords_not_match",
	"settings.preparing_update",
	"settings.proxy_required",
	"settings.refresh",
	"settings.restoring",
	"settings.panel_db_restore_status_unknown",
	"settings.save_account_settings",
	"settings.save_ai_settings",
	"settings.save_failed",
	"settings.save_settings",
	"settings.save_before_copy_command",
	"settings.saved",
	"settings.saving",
	"settings.success",
	"settings.running",
	"settings.waiting",
	"settings.skipped",
	"settings.info",
	"settings.unknown_status",
	"settings.system_update_already_running",
	"settings.system_update_completed",
	"settings.system_update_failed",
	"settings.system_update_start_failed",
	"settings.system_update_status_checking_packages",
	"settings.system_update_status_checking_services",
	"settings.system_update_status_failed",
	"settings.system_update_status_health_failed",
	"settings.system_update_status_interrupted",
	"settings.system_update_status_preflight",
	"settings.system_update_status_queued",
	"settings.system_update_status_refresh",
	"settings.system_update_status_start_failed",
	"settings.system_update_status_success",
	"settings.system_update_status_upgrading",
	"settings.test",
	"settings.test_connection",
	"settings.test_failed",
	"settings.testing",
	"settings.time_sync_triggered",
	"settings.total_records",
	"settings.unknown_error",
	"settings.up_to_date_message",
	"settings.update_completed_refresh",
	"settings.update_completed_restart",
	"settings.update_now",
	"settings.update_started",
	"settings.update_status_timeout",
	"settings.updated",
	"settings.updating",
	"settings.upload_failed",
	"settings.upload_package",
	"settings.upload_success",
	"settings.uploading",
	"settings.zip_only",
	"site_migration.connected",
	"site_migration.peer_status_paired",
	"site_migration.peer_status_pending",
	"site_migration.add_receiving_server",
	"site_migration.hide_pairing",
	"site_migration.copied",
	"site_migration.copy_failed",
	"site_migration.operation_failed",
	"site_migration.package_generated",
	"site_migration.preflight_complete",
	"site_migration.estimate_summary",
	"site_migration.direction_source",
	"site_migration.direction_target",
	"site_migration.sending_server",
	"site_migration.receiving_server",
	"site_migration.progress_waiting_source",
	"site_migration.progress_queued",
	"site_migration.progress_preparing_source",
	"site_migration.progress_receiving",
	"site_migration.progress_receiving_bytes",
	"site_migration.progress_receiving_speed",
	"site_migration.progress_sending",
	"site_migration.progress_sending_bytes",
	"site_migration.progress_sending_speed",
	"site_migration.progress_extracting",
	"site_migration.progress_remote_extracting",
	"site_migration.progress_building_target",
	"site_migration.progress_activating",
	"site_migration.progress_processing",
	"site_migration.progress_decision",
	"site_migration.progress_retryable_failure",
	"site_migration.progress_manual_failure",
	"site_migration.progress_interrupted",
	"site_migration.start_confirm",
	"site_migration.started",
	"site_migration.retry_queued",
	"site_migration.delete_task",
	"site_migration.delete_source_task_confirm",
	"site_migration.delete_target_task_confirm",
	"site_migration.task_deleted",
	"site_migration.completed",
	"site_migration.completed_delete_queued",
	"site_migration.restore_source_confirm",
	"site_migration.cancel_migration",
	"site_migration.cancel_migration_confirm",
	"site_migration.source_restored_dns_reminder",
	"site_migration.target_ready_dns_reminder",
	"site_migration.custom_command_warning",
	"alert.saving",
	"alert.send_failed",
	"alert.sending",
	"alert.smtp_copy",
	"alert.smtp_copy_failed",
	"alert.smtp_copy_success",
	"alert.smtp_config_saved",
	"alert.smtp_import",
	"alert.smtp_import_cancelled",
	"alert.smtp_import_prompt",
	"alert.smtp_import_success",
	"alert.smtp_overwrite_confirm",
	"alert.test_send",
	"alert.type_backup_failed",
	"alert.type_cpu_high_load",
	"alert.type_cron_failed",
	"alert.type_disk_pressure",
	"alert.type_memory_low",
	"alert.type_oom",
	"alert.type_panel_update",
	"alert.type_remote_backup_failed",
	"alert.type_service_abnormal",
	"alert.type_site_unavailable",
	"alert.type_ssl_expire",
	"alert.type_system_update",
	"alert.type_website_expiry",
	"alert.type_wp_fake_search_bot",
	"alert.type_wp_sqli_probe",
	"alert.webhook_config_saved",
	"alert.webhook_url_required",
	"alert.wp_security_config_saved",
	"cron.confirm_delete",
	"cron.confirm_run_paused",
	"cron.deleted_success",
	"cron.job_created",
	"cron.job_run_success",
	"cron.job_running",
	"cron.job_updated",
	"cron.load_failed",
	"cron.load_failed_with_error",
	"cron.run",
	"cron.full_backup",
	"cron.smart_incremental",
	"cron.select_target_site",
	"cron.status_disabled",
	"cron.status_enabled",
	"cron.status_migration_locked",
	"cron.status_site_paused",
	"cron.task_type_command",
	"cron.task_type_file_backup",
	"cron.task_type_wp_cron",
	"cron.wp_cron_target",
	"cron.every_5_minutes",
	"database.backup_count",
	"database.collapse_backups",
	"database.never_backed_up",
	"database.no_databases",
	"database.no_search_results",
	"database.php_password_help",
	"database.refresh",
	"database.refreshing",
	"database.search_placeholder",
	"database.show_more_backups",
	"database.size_unavailable",
	"database.wordpress_password_help",
	"website.status_paused",
	"website.status_running",
	"website.status_migrated",
	"website.status_deleting",
	"website.restore_migrated",
	"website.restore_migrated_detail",
	"website.restore_migrated_confirm",
	"website.restore_migrated_success",
	"website.generic_php_site",
	"website.auto_detect",
	"website.detecting",
	"website.backup_auto",
	"website.backup_manual",
	"website.backup_list",
	"website.save_other_cdn_settings",
	"website.save_settings",
	"website.wp_optimization",
	"website.performance_cache",
	"website.performance_cache_help",
	"website.litespeed_plugin",
	"website.page_cache",
	"website.page_cache_help",
	"website.redis_object_cache",
	"website.server_page_cache",
	"website.enable_server_page_cache",
	"website.open_litespeed_settings",
	"website.clear_page_cache",
	"website.apply_recommended_cache",
	"website.apply_recommended_cache_confirm",
	"website.applying_recommended_cache",
	"website.cache_status_checking",
	"website.clear_redis_cache",
	"website.clearing_redis_cache",
	"dashboard.data_stale",
	"settings.panel_certificate_confirm",
	"settings.panel_domain_verified",
	"settings.certificate_source_self_signed",
	"settings.certificate_source_lets_encrypt",
	"settings.certificate_source_custom",
	"settings.panel_domain",
	"settings.check_address",
	"settings.check_address_family",
	"settings.check_http_status",
	"settings.check_redirect_location",
	"settings.panel_domain_invalid",
	"settings.panel_domain_dns_failed",
	"settings.panel_domain_dns_empty",
	"settings.panel_domain_dns_not_public",
	"settings.panel_domain_route_unavailable",
	"settings.panel_domain_http_unreachable",
	"settings.panel_domain_http_redirect",
	"settings.panel_domain_http_status",
	"settings.panel_domain_challenge_mismatch",
	"settings.panel_certificate_failed",
	"settings.panel_certificate_running",
	"firewall.policy_drop",
	"firewall.policy_accept",
	"firewall.access_policy_restricted",
	"firewall.panel_port_unknown",
	"settings.update_check_failed",
	"website.cache_settings_migrated",
	"website.cache_status_unknown",
	"website.cache_status_failed",
	"website.created_at",
	"website.refresh",
	"website.loading",
	"website.reinstall_warning",
	"website.reinstall_wordpress",
	"website.list_security",
	"website.list_monitoring",
	"website.list_policies",
	"website.list_dates",
	"website.more_actions",
	"website.more_actions_for",
	"website.list_load_failed",
	"website.detail_nav_security",
	"website.security_status_title",
	"website.security_status_help",
	"website.security_checking",
	"website.security_refresh",
	"website.security_checked_at",
	"website.security_load_failed",
	"website.security_group_requests",
	"website.security_group_wordpress",
	"website.security_group_operations",
	"website.security_login_settings",
	"website.security_access_settings",
	"website.security_view_logs",
	"website.security_wp_policy",
	"website.security_wp_policy_help",
	"website.security_policy_saved",
	"website.security_save_failed",
	"website.security_recovery",
	"website.security_recovery_help",
	"website.security_wp_updates",
	"website.security_database_backups",
	"website.security_file_backups",
	"website.security_alerts",
	"website.security_state_effective",
	"website.security_state_configured",
	"website.security_state_disabled",
	"website.security_state_unsupported",
	"website.security_state_error",
	"website.security_state_unknown",
	"website.security_check_https",
	"website.security_help_https",
	"website.security_check_login_protection",
	"website.security_help_login_protection",
	"website.security_check_sensitive_files",
	"website.security_help_sensitive_files",
	"website.security_check_uploads_php",
	"website.security_help_uploads_php",
	"website.security_check_sql_injection",
	"website.security_help_sql_injection",
	"website.security_check_xmlrpc",
	"website.security_help_xmlrpc",
	"website.security_check_application_passwords",
	"website.security_help_application_passwords",
	"website.security_check_file_editing",
	"website.security_help_file_editing",
	"website.security_check_file_lock",
	"website.security_help_file_lock",
	"website.security_check_debug_display",
	"website.security_help_debug_display",
	"website.security_check_uptime_monitor",
	"website.security_help_uptime_monitor",
	"website.security_check_anomaly_monitor",
	"website.security_help_anomaly_monitor",
	"website.security_check_wp_updates",
	"website.security_help_wp_updates",
	"website.security_check_backup",
	"website.security_help_backup",
	"website.migrate_cache_settings",
	"website.migrate_cache_settings_confirm",
	"vps.confirm_tool",
	"vps.cleanup_help",
	"website.configured",
	"website.confirm_clear_redis_cache",
	"website.litespeed_recommended_applied",
	"website.litespeed_recommended_failed",
	"website.not_configured",
	"website.redis_cache_cleared",
	"website.redis_cache_clear_failed",
	"website.refresh_cache_status",
	"website.litespeed_cache_title",
	"website.restore",
	"website.processing",
	"website.sync_db_info",
	"website.clear_database",
	"website.clearing",
	"website.backing_up",
	"website.manual_backup",
	"website.restoring",
	"website.upload_restore",
	"website.unknown",
	"website.save_apply",
	"website.enable_lock",
	"website.unlock",
	"website.file_locked",
	"website.file_unlocked",
	"website.installing",
	"website.install_companion_plugin",
	"website.updating",
	"website.update_companion_plugin",
	"website.rebuild_plugin_config",
	"website.rebuilding_plugin_config",
	"website.rebuild_plugin_config_confirm",
	"website.ssl_enabled",
	"website.ssl_not_enabled",
	"website.ssl_pending",
	"website.online_monitoring",
	"website.anomaly_monitoring",
	"website.monitoring_enabled",
	"website.monitoring_disabled",
	"website.not_applicable",
	"website.access_log_full",
	"website.access_log_error_only",
	"website.access_log_off",
	"website.enabled",
	"website.disabled",
	"website.never_expires",
	"website.delete_confirm",
	"website.pause_confirm",
	"website.delete_success",
	"website.delete_has_backups_warning",
	"website.delete_backup_check_failed_warning",
	"website.backup_conflict_db_count",
	"website.backup_conflict_file_count",
	"website.backup_conflict_auto_enabled",
	"website.backup_conflict_cron_jobs",
	"website.site_pause",
	"website.site_enable",
	"website.reinstall",
	"website.reinstalling",
	"website.reinstalling_with_domain",
	"website.reinstall_completed",
	"wp_fleet.backup",
	"wp_fleet.cache",
	"wp_fleet.empty",
	"wp_fleet.expires_at",
	"wp_fleet.filter_php",
	"wp_fleet.filter_wordpress",
	"wp_fleet.health_critical",
	"wp_fleet.health_healthy",
	"wp_fleet.health_unknown",
	"wp_fleet.health_warning",
	"wp_fleet.inventory_complete",
	"wp_fleet.inventory_failed",
	"wp_fleet.inventory_queued",
	"wp_fleet.inventory_running",
	"wp_fleet.inventory_stale",
	"wp_fleet.inventory_unknown",
	"wp_fleet.issue_inventory_failed",
	"wp_fleet.issue_inventory_stale",
	"wp_fleet.issue_inventory_uncollected",
	"wp_fleet.issue_site_error",
	"wp_fleet.issue_ssl_expired",
	"wp_fleet.issue_ssl_expiring",
	"wp_fleet.issue_ssl_expiry_unknown",
	"wp_fleet.issue_ssl_setup_failed",
	"wp_fleet.issue_updates_available",
	"wp_fleet.more_issues",
	"wp_fleet.never",
	"wp_fleet.no_matches",
	"wp_fleet.overview_failed",
	"wp_fleet.plugin_updates",
	"wp_fleet.search_too_long",
	"wp_fleet.showing_sites",
	"wp_fleet.showing_stale_overview",
	"wp_fleet.ssl_disabled",
	"wp_fleet.ssl_expired",
	"wp_fleet.ssl_expiring",
	"wp_fleet.ssl_expiry_unknown",
	"wp_fleet.ssl_pending_error",
	"wp_fleet.ssl_valid",
	"wp_fleet.status_active",
	"wp_fleet.status_creating",
	"wp_fleet.status_deleting",
	"wp_fleet.status_error",
	"wp_fleet.status_paused",
	"wp_fleet.theme_updates",
	"wp_fleet.loading",
	"wp_fleet.retry_load",
	"wp_fleet.bulk_refresh",
	"wp_fleet.bulk_refresh_running",
	"wp_fleet.bulk_refresh_progress",
	"wp_fleet.bulk_refresh_complete",
	"wp_fleet.bulk_refresh_failed",
	"wp_fleet.site_refresh",
	"wp_fleet.site_refresh_running",
	"wp_fleet.site_refresh_created",
	"wp_fleet.site_refresh_existing",
	"wp_fleet.site_refresh_failed",
	"wp_fleet.site_refresh_timeout",
	"wp_fleet.update_checks_disabled_warning",
	"wp_fleet.update_checks_disabled",
	"wp_fleet.update_checks_enabled",
	"wp_fleet.update_checks_enabled_saved",
	"wp_fleet.update_checks_disabled_saved",
	"wp_fleet.update_checks_save_failed",
	"ai_diagnostics.analyzing",
	"ai_diagnostics.chat_role_ai",
	"ai_diagnostics.chat_role_user",
	"ai_diagnostics.collapse_details",
	"ai_diagnostics.confidence_prefix",
	"ai_diagnostics.diagnosing",
	"ai_diagnostics.diagnosis_completed",
	"ai_diagnostics.diagnosis_failed",
	"ai_diagnostics.diagnosis_running",
	"ai_diagnostics.expand_details",
	"ai_diagnostics.followup_failed",
	"ai_diagnostics.followup_running",
	"ai_diagnostics.history_summary",
	"ai_diagnostics.reply_ready",
	"ai_diagnostics.report_title",
	"ai_diagnostics.select_site_for_history",
	"ai_diagnostics.risk_high",
	"ai_diagnostics.risk_low",
	"ai_diagnostics.risk_medium",
	"ai_diagnostics.risk_text_high",
	"ai_diagnostics.risk_text_low",
	"ai_diagnostics.risk_text_medium",
	"ai_diagnostics.risk_unknown",
	"ai_diagnostics.select_site_to_start",
	"ai_diagnostics.send_to_ai",
	"ai_diagnostics.start_diagnosis_button",
	"ai_diagnostics.status_completed",
	"ai_diagnostics.status_failed",
	"ai_diagnostics.status_running",
	"ai_diagnostics.status_waiting",
	"ai_diagnostics.symptom_cache_issue",
	"ai_diagnostics.symptom_db_connection",
	"ai_diagnostics.symptom_performance",
	"ai_diagnostics.symptom_site_500",
	"ai_diagnostics.symptom_ssl_failure",
	"ai_diagnostics.symptom_wp_admin_down",
	"ai_diagnostics.symptom_log_analysis",
	"ai_diagnostics.log_context_description",
	"ai_diagnostics.data_read_count",
	"ai_diagnostics.tool_runtime_config",
	"ai_diagnostics.tool_security_config",
	"ai_diagnostics.tool_log_overview",
	"ai_diagnostics.tool_log_status",
	"ai_diagnostics.tool_log_path",
	"ai_diagnostics.tool_log_bot",
	"ai_diagnostics.tool_log_ip",
	"ai_diagnostics.tool_log_category",
	"ai_diagnostics.waiting",
	"ai_diagnostics.waiting_ai_request",
	"ai_diagnostics.waiting_analysis",
	"ai_diagnostics.waiting_collect",
	"ai_diagnostics.waiting_long",
	"log_analysis.analysis_failed",
	"log_analysis.analysis_finished",
	"log_analysis.analysis_running",
	"log_analysis.interrupted_by_restart",
	"log_analysis.load_failed",
	"log_analysis.risk_high",
	"log_analysis.risk_low",
	"log_analysis.risk_medium",
	"log_analysis.start_failed",
	"log_analysis.traffic_explanation",
	"log_analysis.category_security_rejected",
	"log_analysis.category_identified_automation",
	"log_analysis.category_http_error",
	"log_analysis.category_wordpress_endpoint",
	"log_analysis.category_static_asset",
	"log_analysis.category_page_like",
	"log_analysis.category_other",
	"log_analysis.detail_ai",
	"log_analysis.detail_ai_failed",
	"log_analysis.detail_ai_running",
	"log_analysis.ai_session_wait_help",
	"log_analysis.continue_diagnosis",
	"log_analysis.detail_load_failed",
	"log_analysis.currently_banned",
	"log_analysis.not_currently_banned",
	"log_analysis.banned_in_range",
	"log_analysis.security_event_sensitive_file_scan",
	"log_analysis.security_event_sqli_probe",
	"log_analysis.security_event_fake_search_bot",
	"log_analysis.security_event_suspicious_php",
	"log_analysis.security_event_client_ip_spoof",
	"security.cdn_mode_cloudflare_auto",
	"security.cdn_mode_compatible_missing_origin_ips",
	"security.cdn_mode_compatible_no_origin_ips",
	"security.cdn_mode_disabled_missing_origin_ips",
	"security.cdn_ranges_required",
	"security.status_unknown",
	"security.status_active_enabled",
	"security.status_active_not_enabled",
	"security.status_inactive",
	"security.status_disabled_by_setting",
	"security.status_normal",
	"security.status_attention",
	"security.active_bans",
	"security.next_run",
	"security.next_run_unknown",
	"security.cdn_status_summary",
	"security.entries_count",
	"security.confirm_delete_cdn_group",
	"security.fetch_cdn_groups_failed",
	"security.got_it",
	"security.help_title",
	"security.last_update_label",
	"security.refresh_triggered",
	"security.googlebot_last_success",
	"security.googlebot_last_error",
	"security.googlebot_source_official",
	"security.googlebot_source_relay",
	"security.googlebot_source_manual",
	"security.googlebot_source_unknown",
	"security.telemetry_disable_confirm",
	"security.telemetry_disabled",
	"security.telemetry_url_required",
	"security.sqli_protection",
	"security.sqli_protection_help",
	"security.sqli_block_enabled",
	"security.sqli_autoban_enabled",
	"security.sqli_proxy_boundary",
	"security.sqli_ban_threshold",
	"security.sqli_ban_window",
	"security.telemetry_enabled",
	"security.cdn_mode_strict_trusted_ips",
	"common.saved",
	"files.chunk_upload_failed",
	"files.clipboard_copy",
	"files.clipboard_cut",
	"files.clipboard_label",
	"files.compress_completed",
	"files.compress_directory_title",
	"files.compress_file_title",
	"files.compression_busy",
	"files.confirm_delete_items",
	"files.confirm_extract",
	"files.confirm_fix_permissions",
	"files.confirm_overwrite_existing",
	"files.copied_to_clipboard",
	"files.current_selection",
	"files.cut_to_clipboard",
	"files.decompression_busy",
	"files.delete_completed",
	"files.delete_failed",
	"files.deleted_item",
	"files.existing_items_conflict",
	"files.extract_completed",
	"files.extract_overwrite_conflict",
	"files.file_type_dir",
	"files.file_type_file",
	"files.file_lock_active_title",
	"files.file_lock_inactive_help",
	"files.file_lock_inactive_title",
	"files.file_lock_notice",
	"files.item_count",
	"files.mkdir_success",
	"files.pagination_summary",
	"files.paste_target_required",
	"files.permissions_fixed",
	"files.prompt_archive_name",
	"files.remote_import_completed",
	"files.remote_import_failed",
	"files.remote_import_in_progress",
	"files.remote_import_preparing",
	"files.remote_import_start",
	"files.remote_import_url_placeholder",
	"files.rename_success",
	"files.search_failed",
	"files.search_result_path",
	"files.search_results_for",
	"files.search_truncated_match_limit",
	"files.search_truncated_scan_limit",
	"files.skip_existing_prompt",
	"files.unknown_size",
	"files.upload",
	"files.upload_completed",
	"files.upload_failed_with_error",
	"files.upload_init_failed",
	"files.upload_merge_failed",
	"files.uploading",
	"firewall.added_to_blacklist",
	"firewall.analyzing",
	"firewall.ban",
	"firewall.ban_level_10m",
	"firewall.ban_level_24h",
	"firewall.ban_level_30d",
	"firewall.ban_level_empty",
	"firewall.ban_level_permanent",
	"firewall.ban_level_rate_limit",
	"firewall.ban_success",
	"firewall.banning",
	"firewall.clear_rescan",
	"firewall.confirm_clear_history",
	"firewall.confirm_permanent_ban",
	"firewall.confirm_unban",
	"firewall.confirm_open_port",
	"firewall.confirm_close_port",
	"firewall.confirm_any_source",
	"firewall.confirm_enable_protection",
	"firewall.any_source",
	"firewall.core_ports_summary",
	"firewall.current_ip_help",
	"firewall.custom_service",
	"firewall.duration_required",
	"firewall.enable_protected_mode",
	"firewall.exposure_allowed_by_default",
	"firewall.exposure_local_only",
	"firewall.exposure_rule_dependent",
	"firewall.local_only",
	"firewall.listening_ports_summary",
	"firewall.network_listening",
	"firewall.port_opened",
	"firewall.port_closed",
	"firewall.protection_confirmation_failed",
	"firewall.protection_enabled",
	"firewall.protection_rollback_pending",
	"firewall.refresh",
	"firewall.applied",
	"firewall.open_port",
	"firewall.pending_reconcile",
	"firewall.source_required",
	"firewall.source_scope_help",
	"firewall.unknown_process",
	"alert.configured",
	"alert.not_configured",
	"firewall.copy_failed_manual",
	"firewall.copy_line_count",
	"firewall.copy_line_ip",
	"firewall.copy_line_last_seen",
	"firewall.copy_line_note",
	"firewall.copy_line_path",
	"firewall.copy_line_risk",
	"firewall.copy_line_site",
	"firewall.copy_line_source",
	"firewall.copy_line_status",
	"firewall.copy_line_type",
	"firewall.enter_ip",
	"firewall.expected_unban_at",
	"firewall.event_runtime_php_access",
	"firewall.event_suspicious_php_file",
	"firewall.event_integrity_added",
	"firewall.event_integrity_modified",
	"firewall.event_integrity_deleted",
	"firewall.event_integrity_link",
	"firewall.event_integrity_unavailable",
	"firewall.source_integrity",
	"firewall.file_event_copied",
	"firewall.file_security_summary",
	"firewall.found",
	"firewall.incremental_refresh",
	"firewall.ip_filled_notice",
	"firewall.load_wp_report_failed",
	"firewall.load_more_history",
	"firewall.permanent",
	"firewall.fail2ban_managed",
	"firewall.fail2ban_managed_help",
	"firewall.current_bans_partial_read",
	"firewall.ban_sync_anomalies",
	"firewall.ban_sync_anomalies_help",
	"firewall.ban_rule_missing",
	"firewall.ban_status_unverified",
	"firewall.metadata_unknown",
	"firewall.refresh_analysis",
	"firewall.refresh_file_security_failed",
	"firewall.refreshing",
	"firewall.report_copied",
	"firewall.risk_high",
	"firewall.risk_low",
	"firewall.risk_medium",
	"firewall.scanning",
	"firewall.source_404",
	"firewall.source_login",
	"firewall.source_sqli",
	"firewall.source_manual",
	"firewall.source_nftables",
	"firewall.source_persistent_firewall",
	"firewall.source_panel",
	"firewall.source_scan",
	"firewall.source_scanner",
	"firewall.source_ssh",
	"firewall.source_web_protect",
	"firewall.status_current_risk",
	"firewall.status_handled",
	"firewall.total_records",
	"firewall.type_fake_search_bot",
	"firewall.type_sensitive_file_scan",
	"firewall.type_sqli_probe",
	"firewall.type_sqli_blocked",
	"firewall.type_wp_login_failed",
	"firewall.type_xmlrpc_blocked",
	"log_analysis.security_event_xmlrpc_blocked",
	"log_analysis.security_event_wp_login_failed",
	"log_analysis.security_event_sqli_blocked",
	"firewall.rule_summary_sqli",
	"firewall.rule_sqli_title",
	"firewall.rule_sqli_detail",
	"firewall.rule_sqli_boundary",
	"firewall.type_suspicious_php",
	"firewall.unbanned",
	"firewall.unknown",
	"firewall.view_source_rule",
	"name",
	"overwrite",
	"site_id",
	"size",
	"skip",
	"symptom",
	"textarea",
	"time",
	"type",
	"website.at_least_one_url",
	"website.backup_completed",
	"website.backup_settings_saved",
	"website.cache_cleared",
	"website.cdn_header_mismatch",
	"website.cdn_realip_saved",
	"website.cdn_select_non_cloudflare_help",
	"website.cdn_select_non_cloudflare_required",
	"website.cdn_strict_origin_ips",
	"website.cdn_unavailable_no_origin_ips",
	"website.confirm_change",
	"website.confirm_clear_cache",
	"website.confirm_clear_database",
	"website.confirm_clear_logs",
	"website.confirm_continue",
	"website.confirm_delete_backup",
	"website.confirm_delete_ssl",
	"website.confirm_restore_backup",
	"website.confirm_restore_upload",
	"website.confirm_update",
	"website.confirm_update_site_urls",
	"website.database_cleared",
	"website.deleted",
	"website.detect_failed",
	"website.detect_multiple_prefixes",
	"website.detect_prefix_found",
	"website.detect_prefix_missing",
	"website.document_root_saved",
	"website.domain_required",
	"website.domain_change_resources_warning",
	"website.sync_wp_site_urls",
	"website.sync_wp_site_urls_help",
	"website.sync_wp_site_urls_enter_domain",
	"website.wp_site_urls_domain_mismatch",
	"website.wp_site_urls_read_failed",
	"website.expiry_saved",
	"website.file_lock_disable_confirm",
	"website.file_lock_disabled",
	"website.file_lock_apply_confirm",
	"website.file_lock_apply_failed",
	"website.file_lock_apply_mode",
	"website.file_lock_check_impact",
	"website.file_lock_checking",
	"website.file_lock_enable_confirm",
	"website.file_lock_enabled",
	"website.file_lock_executable_warning",
	"website.file_editing_saved",
	"website.file_lock_legacy",
	"website.file_lock_mode_standard",
	"website.file_lock_mode_strict",
	"website.file_lock_preview_truncated",
	"website.file_lock_path_advanced_cache",
	"website.file_lock_path_cache",
	"website.file_lock_path_db_dropin",
	"website.file_lock_path_languages",
	"website.file_lock_path_mu_plugins",
	"website.file_lock_path_object_cache",
	"website.file_lock_path_php_ini",
	"website.file_lock_path_plugins",
	"website.file_lock_path_sunrise",
	"website.file_lock_path_themes",
	"website.file_lock_path_uploads",
	"website.file_lock_path_user_ini",
	"website.file_lock_path_wflogs",
	"website.file_lock_path_wordfence_waf",
	"website.file_lock_path_wp_config",
	"website.file_lock_readonly_dirs",
	"website.file_lock_sensitive_files",
	"website.file_lock_standard",
	"website.file_lock_standard_help",
	"website.file_lock_strict",
	"website.file_lock_strict_help",
	"website.file_lock_symlink_warning",
	"website.file_lock_writable_dirs",
	"website.save_file_editing",
	"website.save_password_reset",
	"website.password_reset_saved",
	"website.installed",
	"website.load_current_url_failed",
	"website.load_failed_with_error",
	"website.load_log_files_failed",
	"website.load_logs_failed",
	"website.log_empty_or_missing",
	"website.log_type_access",
	"website.log_type_error",
	"website.log_type_security",
	"website.logs_cleared",
	"website.monitoring_saved",
	"website.new_password_placeholder",
	"website.operation_failed_with_error",
	"website.optimization_saved",
	"website.password_updated",
	"website.processing_update",
	"website.reading",
	"website.save_failed",
	"website.save_failed_with_error",
	"website.site_urls_updated",
	"website.wp_admin_confirm",
	"website.wp_admin_load_failed",
	"website.wp_admin_password_generated",
	"website.wp_admin_password_mismatch",
	"website.wp_admin_password_short",
	"website.wp_admin_required",
	"website.wp_admin_update_failed",
	"website.wp_admin_updated",
	"website.ssl_deleted",
	"website.ssl_export_saved",
	"website.ssl_manual_required",
	"website.sync_wp_config_base",
	"website.sync_wp_config_prefix",
	"website.unchanged",
	"website.update_failed",
	"website.update_failed_with_error",
	"website.updated",

	"2006-01-02",
	"20060102",
	"20060102_150405",
	"2d",
	"Cache-Control",
	"Content-Disposition",
	"Content-Type",
	"ai_diagnostics.already_running",
	"ai_diagnostics.already_running_followup",
	"ai_diagnostics.api_key_required",
	"ai_diagnostics.build_context_failed",
	"ai_diagnostics.collect_context_failed",
	"ai_diagnostics.create_session_failed",
	"ai_diagnostics.followup_required",
	"ai_diagnostics.followup_too_long",
	"ai_diagnostics.followup_wait",
	"ai_diagnostics.invalid_session_id",
	"ai_diagnostics.invalid_symptom",
	"ai_diagnostics.load_context_failed",
	"ai_diagnostics.load_messages_failed",
	"ai_diagnostics.load_sessions_failed",
	"ai_diagnostics.not_enabled",
	"ai_diagnostics.result_ready",
	"ai_diagnostics.save_followup_failed",
	"ai_diagnostics.save_reply_failed",
	"ai_diagnostics.save_result_failed",
	"ai_diagnostics.session_interrupted",
	"ai_diagnostics.session_not_found",
	"ai_diagnostics.user_error_bad_response",
	"ai_diagnostics.user_error_empty_response",
	"ai_diagnostics.user_error_network",
	"ai_diagnostics.user_error_rate_limited",
	"ai_diagnostics.user_error_timeout",
	"ai_diagnostics.user_error_unauthorized",
	"ai_settings.invalid_provider",
	"ai_settings.load_failed",
	"ai_settings.save_failed",
	"auth.invalid_credentials",
	"auth.missing_csrf",
	"auth.not_logged_in",
	"auth.provide_credentials",
	"common.invalid_params",
	"files.path_out_of_bounds",
	"files.remote_import_chmod_failed",
	"files.remote_import_completed_fix_permissions",
	"files.remote_import_create_file_failed",
	"files.remote_import_disk_full",
	"files.remote_import_disk_space_low",
	"files.remote_import_downloading",
	"files.remote_import_failed_with_error",
	"files.remote_import_filename_required",
	"files.remote_import_host_invalid",
	"files.remote_import_host_local",
	"files.remote_import_host_private",
	"files.remote_import_host_resolve_failed",
	"files.remote_import_https_only",
	"files.remote_import_read_failed",
	"files.remote_import_rename_failed",
	"files.remote_import_request_failed",
	"files.remote_import_save_failed",
	"files.remote_import_status_code",
	"files.remote_import_task_missing",
	"files.remote_import_too_large",
	"files.remote_import_too_many_redirects",
	"files.remote_import_url_invalid",
	"files.remote_import_url_no_userinfo",
	"files.remote_import_url_required",
	"files.remote_import_waiting",
	"files.select_website_first",
	"files.target_directory_missing",
	"files.target_is_directory",
	"session_username",
	"ai_development.disable_confirm",
	"ai_development.disabled",
	"ai_development.disabled_status",
	"ai_development.enable_button",
	"ai_development.enable_confirm",
	"ai_development.enable_busy_force_confirm",
	"ai_development.enabled",
	"ai_development.enabled_downloaded",
	"ai_development.processing",
	"ai_development.stage_installing_wp_cli",
	"ai_development.stage_installing_nodejs",
	"ai_development.stage_configuring_access",
	"ai_development.stage_rotating_package",
	"ai_development.enabled_ready_download",
	"ai_development.first_prompt",
	"ai_development.first_prompt_copied",
	"ai_development.download_package",
	"ai_development.regenerate_package",
	"ai_development.package_downloaded",
	"ai_development.redownload_rotates_confirm",
	"ai_development.rotate_confirm",
	"ai_development.rotated_downloaded",
	"software.action_success",
	"software.clear_failed",
	"software.client_max_body_size_hint",
	"software.client_max_body_size_label",
	"software.config_not_found",
	"software.config_updated_reloaded",
	"software.create_php_config_failed",
	"software.innodb_buffer_pool_size_hint",
	"software.innodb_buffer_pool_size_label",
	"software.installed",
	"software.development_tool_install_confirm",
	"software.development_tool_installed",
	"software.install",
	"software.installing",
	"software.nodejs_development_help",
	"software.recommended",
	"software.wp_cli_development_help",
	"software.invalid_action",
	"software.log_cleared",
	"software.log_empty_or_unreadable",
	"software.max_execution_time_hint",
	"software.max_execution_time_label",
	"software.max_input_time_hint",
	"software.max_input_time_label",
	"software.max_input_vars_hint",
	"software.max_input_vars_label",
	"software.maxmemory_hint",
	"software.maxmemory_label",
	"software.manage_service_updates",
	"software.memory_limit_hint",
	"software.memory_limit_label",
	"software.openlitespeed_value_no_semicolon",
	"software.operation_failed_with_error",
	"software.php_installed_extensions",
	"software.php_int_invalid",
	"software.php_runtime_install_confirm",
	"software.php_runtime_installed",
	"software.php_runtime_site_count",
	"software.php_size_invalid",
	"software.post_max_size_hint",
	"software.post_max_size_label",
	"software.read_config_failed",
	"software.running",
	"software.stopped",
	"software.syntax_check_failed_with_rollback",
	"software.unknown_software",
	"software.unsupported_config_item",
	"software.update_available_candidate",
	"software.upload_max_filesize_hint",
	"software.upload_max_filesize_label",
	"software.value_no_newline",
	"software.write_config_failed",
	"website.invalid_site_id",
	"website.not_found",
	"website.php_runtime_switch",
	"website.php_runtime_switch_confirm",
	"website.php_runtime_switched",
	"website.php_runtime_switching",
	"website.restore_failed",
	"website.restore_file_invalid",
	"website.restore_long_running_help",
	"website.restore_running_elapsed",
	"website.restore_started",
	"website.restore_still_running",
	"website.restore_success",
	"website.restore_success_elapsed",
	"website.restore_task_failed",
	"website.restore_uploading",
	"website.restore_waiting",
	"wp_inventory.active",
	"wp_inventory.active_plugins",
	"wp_inventory.core_update_available",
	"wp_inventory.core_update_none",
	"wp_inventory.current_theme_badge",
	"wp_inventory.error_bootstrap",
	"wp_inventory.error_code",
	"wp_inventory.error_generic",
	"wp_inventory.error_inventory_limit",
	"wp_inventory.error_memory_limit",
	"wp_inventory.error_output_limit",
	"wp_inventory.error_policy",
	"wp_inventory.error_policy_mismatch",
	"wp_inventory.error_protocol",
	"wp_inventory.error_site_changed",
	"wp_inventory.error_start_failed",
	"wp_inventory.error_php_runtime",
	"wp_inventory.error_site_path",
	"wp_inventory.error_site_user",
	"wp_inventory.error_permissions",
	"wp_inventory.error_terminated",
	"wp_inventory.error_timeout",
	"wp_inventory.error_unknown",
	"wp_inventory.error_worker",
	"wp_inventory.how_it_works_title",
	"wp_inventory.inactive",
	"wp_inventory.load_failed",
	"wp_inventory.loading",
	"wp_inventory.network_active",
	"wp_inventory.never",
	"wp_inventory.next",
	"wp_inventory.page_summary",
	"wp_inventory.previous",
	"wp_inventory.refresh",
	"wp_inventory.refresh_created",
	"wp_inventory.refresh_existing",
	"wp_inventory.refresh_failed",
	"wp_inventory.refreshing",
	"wp_inventory.retry",
	"wp_inventory.retry_hint",
	"wp_inventory.retry_useless",
	"wp_inventory.stale_notice",
	"wp_inventory.status_complete",
	"wp_inventory.status_failed_empty",
	"wp_inventory.status_failed_stale",
	"wp_inventory.status_queued",
	"wp_inventory.status_running",
	"wp_inventory.status_unexpected",
	"wp_inventory.status_unknown",
	"wp_inventory.status_unknown_updates",
	"wp_inventory.status_unknown_updates_label",
	"wp_inventory.status_up_to_date",
	"wp_inventory.status_updates_available",
	"wp_inventory.task_read_failed",
	"wp_inventory.tech_details",
	"wp_inventory.type_core",
	"wp_inventory.type_plugin",
	"wp_inventory.type_theme",
	"wp_inventory.wordpress_only",
	"wp_inventory.yes",
	"wp_inventory.no",
	"wp_core_update.preparing",
	"wp_core_update.recheck",
	"wp_core_update.confirm_message",
	"wp_core_update.preview_failed",
	"wp_core_update.preview_invalid",
	"wp_core_update.stage_backups_ready",
	"wp_core_update.stage_claimed",
	"wp_core_update.stage_complete",
	"wp_core_update.stage_health_check",
	"wp_core_update.stage_queued",
	"wp_core_update.stage_restoring_file_lock",
	"wp_core_update.stage_rollback",
	"wp_core_update.stage_unknown",
	"wp_core_update.stage_unlocking",
	"wp_core_update.stage_updating_core",
	"wp_core_update.stage_value",
	"wp_core_update.start_update",
	"wp_core_update.cancel_preparation",
	"wp_core_update.recent_backup_found",
	"wp_core_update.status_failed",
	"wp_core_update.status_interrupted_unknown",
	"wp_core_update.status_queued",
	"wp_core_update.status_running",
	"wp_core_update.status_success",
	"wp_core_update.status_unknown",
	"wp_core_update.submit_failed",
	"wp_core_update.submitted",
	"wp_core_update.submission_recovered",
	"wp_core_update.submitting",
	"wp_core_update.task_invalid",
	"wp_core_update.task_read_failed",
	"wp_core_update.up_to_date",
	"wp_plugin_update.action",
	"wp_plugin_update.checking",
	"wp_plugin_update.confirm",
	"wp_plugin_update.confirm_warning",
	"wp_plugin_update.cancel_preparation",
	"wp_plugin_update.description",
	"wp_plugin_update.not_found",
	"wp_plugin_update.not_in_repository",
	"wp_plugin_update.license_invalid",
	"wp_plugin_update.plugin",
	"wp_plugin_update.preview_failed",
	"wp_plugin_update.preview_invalid",
	"wp_plugin_update.recent_backup_found",
	"wp_plugin_update.backup_scope_value",
	"wp_plugin_update.rescan_after_success",
	"wp_plugin_update.stage_backups_ready",
	"wp_plugin_update.stage_claimed",
	"wp_plugin_update.stage_complete",
	"wp_plugin_update.stage_health_check",
	"wp_plugin_update.stage_queued",
	"wp_plugin_update.stage_reactivating",
	"wp_plugin_update.stage_restoring_file_lock",
	"wp_plugin_update.stage_rollback",
	"wp_plugin_update.stage_unknown",
	"wp_plugin_update.stage_unlocking",
	"wp_plugin_update.stage_updating_component",
	"wp_plugin_update.stage_value",
	"wp_plugin_update.status_failed",
	"wp_plugin_update.status_interrupted_unknown",
	"wp_plugin_update.status_preparing",
	"wp_plugin_update.status_queued",
	"wp_plugin_update.status_running",
	"wp_plugin_update.status_success",
	"wp_plugin_update.status_unknown",
	"wp_plugin_update.submit_failed",
	"wp_plugin_update.submitted",
	"wp_plugin_update.submission_recovered",
	"wp_plugin_update.submitting",
	"wp_plugin_update.task_invalid",
	"wp_plugin_update.task_read_failed",
	"wp_plugin_update.tracking",
	"wp_plugin_update.title",
	"wp_plugin_batch.button",
	"wp_plugin_batch.button_tracking",
	"wp_plugin_batch.theme_not_supported",
	"wp_plugin_batch.ignore_button",
	"wp_plugin_batch.ignore_confirm",
	"wp_plugin_batch.ignore_failed",
	"wp_plugin_batch.ignore_success",
	"wp_plugin_batch.item_dispatch_failed",
	"wp_plugin_batch.item_failed_awaiting_decision",
	"wp_plugin_batch.item_failed_generic",
	"wp_plugin_batch.item_failed_rollback_failed",
	"wp_plugin_batch.item_failed_rolled_back",
	"wp_plugin_batch.item_interrupted",
	"wp_plugin_batch.item_interrupted_acknowledged",
	"wp_plugin_batch.item_pending",
	"wp_plugin_batch.item_success",
	"wp_plugin_batch.item_updating",
	"wp_plugin_batch.load_failed",
	"wp_plugin_batch.rollback_button",
	"wp_plugin_batch.rollback_confirm",
	"wp_plugin_batch.rollback_reuse_confirm",
	"wp_plugin_batch.rollback_failed",
	"wp_plugin_batch.rollback_submitting",
	"wp_plugin_batch.rollback_success",
	"wp_plugin_batch.selected_count",
	"wp_plugin_batch.start",
	"wp_plugin_batch.start_failed",
	"wp_plugin_batch.start_invalid",
	"wp_plugin_batch.starting",
	"wp_plugin_batch.status_completed",
	"wp_plugin_batch.status_running",
	"wp_plugin_batch.task_invalid",
	"wp_theme_update.action",
	"wp_theme_update.backup_scope_value",
	"wp_theme_update.checking",
	"wp_theme_update.confirm",
	"wp_theme_update.confirm_warning",
	"wp_theme_update.current_theme_warning",
	"wp_theme_update.description",
	"wp_theme_update.not_found",
	"wp_theme_update.not_in_repository",
	"wp_theme_update.license_invalid",
	"wp_theme_update.preview_failed",
	"wp_theme_update.preview_invalid",
	"wp_theme_update.rescan_after_success",
	"wp_theme_update.stage_backups_ready",
	"wp_theme_update.stage_claimed",
	"wp_theme_update.stage_complete",
	"wp_theme_update.stage_health_check",
	"wp_theme_update.stage_queued",
	"wp_theme_update.stage_reactivating",
	"wp_theme_update.stage_restoring_file_lock",
	"wp_theme_update.stage_rollback",
	"wp_theme_update.stage_unknown",
	"wp_theme_update.stage_unlocking",
	"wp_theme_update.stage_updating_component",
	"wp_theme_update.status_failed",
	"wp_theme_update.status_interrupted_unknown",
	"wp_theme_update.status_preparing",
	"wp_theme_update.status_queued",
	"wp_theme_update.status_running",
	"wp_theme_update.status_success",
	"wp_theme_update.status_unknown",
	"wp_theme_update.submit_failed",
	"wp_theme_update.submitted",
	"wp_theme_update.submission_recovered",
	"wp_theme_update.submitting",
	"wp_theme_update.task_invalid",
	"wp_theme_update.task_read_failed",
	"wp_theme_update.theme",
	"wp_theme_update.title",
	"wp_theme_update.tracking",
	"wp_update_backup.kind_database",
	"wp_update_backup.kind_core_files",
	"wp_update_backup.kind_plugin_files",
	"wp_update_backup.kind_theme_files",
	"wp_update_backup.load_failed",
	"wp_update_backup.restore",
	"wp_update_backup.restore_failed",
	"wp_update_backup.restoring",
	"wp_update_backup.restore_confirm",
	"wp_update_backup.restore_batch_confirm",
	"wp_update_backup.batch_shared",
	"wp_update_backup.restore_started",
	"wp_update_backup.restore_success",
	"wp_update_backup.restore_task_failed",
	"wp_update_backup.restore_status_failed",
	"wp_update_log.load_failed",
	"wp_update_log.copy",
	"wp_update_log.copied",
	"wp_update_log.copy_failed",
	"wp_update_log.copy_title",
	"wp_update_log.copy_site",
	"wp_update_log.copy_task",
	"wp_update_log.copy_type",
	"wp_update_log.copy_component",
	"wp_update_log.copy_version",
	"wp_update_log.copy_status",
	"wp_update_log.copy_rollback",
	"wp_update_log.copy_started",
	"wp_update_log.copy_finished",
	"wp_update_log.copy_events_divider",
	"wp_update_log.kind_update",
	"wp_update_log.kind_rollback",
	"wp_update_log.requires_attention",
	"wp_update_log.rollback_failed",
	"wp_update_log.status_success",
	"wp_update_log.status_failed",
	"wp_update_log.status_running",
	"wp_update_log.status_queued",
	"wp_update_log.status_preparing",
	"wp_update_log.status_interrupted_unknown",
	"wp_update_log.no_events",
	"wp_update_log.event_result_info",
	"wp_update_log.event_result_success",
	"wp_update_log.event_result_failed",
	"wp_update_log.event_result_interrupted",
	"wp_update_log.event_result_manual",
	"cache_status.attempt",
	"cache_status.checked_at",
	"cache_status.plugin_help",
	"cache_status.redis_help",
	"cache_status.result_bypass",
	"cache_status.result_hit",
	"cache_status.result_miss",
	"cache_status.result_not_verified",
	"cache_status.result_unknown",
	"cache_status.server_configured",
	"cache_status.server_misconfigured",
	"cache_status.server_title",
	"cache_status.server_unknown",
	"cache_status.server_unsupported",
	"cache_status.source_local",
	"cache_status.verification_failed",
	"cache_status.verify",
	"cache_status.verify_help",
	"cache_status.verify_title",
	"cache_status.verifying",
	"common.copied",
	"common.copy",
	"common.refresh",
	"site_security.certificate_expiry",
	"site_security.collected_at",
	"site_security.data_unavailable",
	"site_security.evidence",
	"site_security.invalid_request",
	"site_security.rate_limited",
	"site_security.reason_configuration_check_failed",
	"site_security.reason_configuration_unavailable",
	"site_security.reason_configured_not_run",
	"site_security.reason_core_application_passwords_disabled",
	"site_security.reason_core_debug_display_disabled",
	"site_security.reason_core_file_editor_disabled",
	"site_security.reason_core_policy_not_enforced",
	"site_security.reason_core_policy_verified",
	"site_security.reason_core_runtime_unavailable",
	"site_security.reason_core_updates_allowed",
	"site_security.reason_disabled_by_policy",
	"site_security.reason_http_control_not_verified",
	"site_security.reason_https_setting_enabled",
	"site_security.reason_invalid_host",
	"site_security.reason_login_audit_not_ready",
	"site_security.reason_login_audit_verified",
	"site_security.reason_login_jail_not_monitoring",
	"site_security.reason_login_ready_no_event",
	"site_security.reason_native_policy_not_confirmed",
	"site_security.reason_not_applicable",
	"site_security.reason_not_checked",
	"site_security.reason_ols_rules_not_confirmed",
	"site_security.reason_path_denial_verified",
	"site_security.reason_request_verified",
	"site_security.reason_service_ready",
	"site_security.reason_site_not_active",
	"site_security.reason_sqli_request_verified",
	"site_security.reason_sqli_service_ready_no_event",
	"site_security.reason_tls_certificate_invalid",
	"site_security.reason_tls_connection_unavailable",
	"site_security.reason_tls_domain_mismatch",
	"site_security.reason_tls_untrusted",
	"site_security.reason_tls_verified",
	"site_security.reason_wp_policy_not_confirmed",
	"site_security.recent_event",
	"site_security.settings",
	"site_security.site_busy",
	"site_security.site_not_active",
	"site_security.site_not_found",
	"site_security.source_fail2ban_logpath",
	"site_security.source_isolated_wp_core",
	"site_security.source_loopback_http",
	"site_security.source_loopback_tls",
	"site_security.source_ols_configuration",
	"site_security.source_ols_security_log",
	"site_security.source_saved_configuration",
	"site_security.source_wp_config",
	"site_security.source_wp_login_audit",
	"site_security.state_ready",
	"site_security.state_runtime_verified",
	"site_security.summary_help",
	"site_security.verification_failed",
	"site_security.verify",
	"site_security.verifying",
	"website.all_statuses",
	"website.file_manage",
	"website.filter_status",
	"website.registry_clear_filters",
	"website.registry_connection",
	"website.registry_count",
	"website.registry_expired",
	"website.registry_files_for",
	"website.registry_https_configured",
	"website.registry_https_missing",
	"website.registry_intro",
	"website.registry_manage",
	"website.registry_monitoring",
	"website.registry_no_matches",
	"website.registry_site",
	"website.registry_status_creating",
	"website.registry_status_error",
	"website.search_sites",
	"wp_access.administrator",
	"wp_access.authentication_conflict",
	"wp_access.authorize_login",
	"wp_access.authorizing",
	"wp_access.choose_administrator",
	"wp_access.custom_suffix",
	"wp_access.enable_help",
	"wp_access.enable_sso",
	"wp_access.external_control",
	"wp_access.install_address",
	"wp_access.install_notice",
	"wp_access.invalid_ticket",
	"wp_access.invalid_url",
	"wp_access.login_address",
	"wp_access.manual_help",
	"wp_access.manual_url",
	"wp_access.one_click",
	"wp_access.open_install",
	"wp_access.open_login",
	"wp_access.panel_code",
	"wp_access.panel_password",
	"wp_access.popup_blocked",
	"wp_access.reason_unavailable",
	"wp_access.recovery_help",
	"wp_access.revoke",
	"wp_access.revoked",
	"wp_access.settings_title",
	"wp_access.source_manual",
	"wp_access.source_native",
	"wp_access.source_panel",
	"wp_access.source_plugin",
	"wp_access.subtitle",
	"wp_access.suffix_help",
	"wp_access.ticket_notice",
	"wp_access.title",
	"cache_status.reason_cache_header_absent",
	"cache_status.reason_cache_header_ambiguous",
	"cache_status.reason_cache_header_unrecognized",
	"cache_status.reason_cache_hit_observed",
	"cache_status.reason_cache_miss_observed",
	"cache_status.reason_cache_module_invalid",
	"cache_status.reason_cache_module_missing",
	"cache_status.reason_config_unavailable",
	"cache_status.reason_http_status",
	"cache_status.reason_inactive_site",
	"cache_status.reason_inactive_vhost",
	"cache_status.reason_invalid_origin",
	"cache_status.reason_module_ready",
	"cache_status.reason_non_html_response",
	"cache_status.reason_not_verified",
	"cache_status.reason_origin_unreachable",
	"cache_status.reason_private_or_uncacheable_response",
	"cache_status.reason_redirect",
	"cache_status.reason_request_timeout",
	"cache_status.reason_response_unavailable",
	"cache_status.reason_tls_verification_failed",
	"cache_status.reason_unsafe_public_cache_default",
	"cache_status.reason_unsupported_site",
	"cache_status.reason_untrusted_vhost",
	"wp_access.error_administrator_not_found",
	"wp_access.error_authentication_plugin",
	"wp_access.error_bridge_unavailable",
	"wp_access.error_broker_unavailable",
	"wp_access.error_confirmation_required",
	"wp_access.error_curl_unavailable",
	"wp_access.error_database_mismatch",
	"wp_access.error_external_login_control",
	"wp_access.error_https_required",
	"wp_access.error_invalid_login_url",
	"wp_access.error_invalid_site_url",
	"wp_access.error_invalid_suffix",
	"wp_access.error_multisite_unsupported",
	"wp_access.error_not_installed",
	"wp_access.error_operation_failed",
	"wp_access.error_permalinks_required",
	"wp_access.error_rollback_failed",
	"wp_access.error_route_unavailable",
	"wp_access.error_runtime_unavailable",
	"wp_access.error_settings_unavailable",
	"wp_access.error_site_unavailable",
	"wp_access.error_sso_disabled",
	"wp_access.error_suffix_conflict",
	"wp_access.error_too_many_administrators",
	"wp_access.error_unmanaged_bridge",
	"wp_access.reason_administrator_not_found",
	"wp_access.reason_authentication_plugin",
	"wp_access.reason_bridge_unavailable",
	"wp_access.reason_broker_unavailable",
	"wp_access.reason_curl_unavailable",
	"wp_access.reason_external_login_control",
	"wp_access.reason_https_required",
	"wp_access.reason_not_installed",
	"wp_access.reason_sso_disabled",
}

func SetupRouter(cfg *config.Config, tmplFS embed.FS, staticFS embed.FS, version string, configPath string) *gin.Engine {
	r, _ := SetupRouterWithCleanup(cfg, tmplFS, staticFS, version, configPath)
	return r
}

// The server must stop notification delivery before closing its database.
func SetupRouterWithCleanup(cfg *config.Config, tmplFS embed.FS, staticFS embed.FS, version string, configPath string) (*gin.Engine, func()) {
	panelVersion = version
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.SetTrustedProxies(nil)
	messageCatalog, err := i18n.NewTemplateMessages(tmplFS, i18nKeys)
	if err != nil {
		log.Panicf("cannot initialize page translations: %v", err)
	}

	r.Use(middleware.CustomRecovery())
	r.Use(middleware.SecurityHeaders())

	// /healthz 必须在 ScanDefense 之前注册，否则本机健康检查会被扫描防御误封
	r.GET("/healthz", func(c *gin.Context) {
		ip := net.ParseIP(c.ClientIP())
		if ip == nil || !ip.IsLoopback() {
			c.Status(http.StatusNotFound)
			return
		}
		db := database.GetDB()
		if db == nil {
			c.Status(http.StatusServiceUnavailable)
			return
		}
		var schemaVersion string
		if err := db.QueryRow("SELECT version FROM schema_version ORDER BY updated_at DESC, rowid DESC LIMIT 1").Scan(&schemaVersion); err != nil || schemaVersion == "" {
			c.Status(http.StatusServiceUnavailable)
			return
		}
		for _, table := range []string{"admin_users", "websites", "security_settings"} {
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM " + table + " LIMIT 1").Scan(&count); err != nil {
				c.Status(http.StatusServiceUnavailable)
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "version": version})
	})

	db := database.GetDB()
	dbPath := cfg.SQLite.Path
	if dbPath == "" {
		if err := db.QueryRow("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&dbPath); err != nil || dbPath == "" {
			panic("account security requires a persistent database path")
		}
	}
	mfaService, err := accountsecurity.NewMFAService(db, filepath.Join(filepath.Dir(dbPath), "account-mfa.key"))
	if err != nil {
		log.Panicf("cannot initialize account security: %v", err)
	}
	auditService := accountsecurity.NewAuditService(db)
	auditService.SetNotifier(executor.SendAccountSecurityNotification)
	r.Use(middleware.ScanDefense(db, cfg.Panel.RandomSuffix))

	// Site migration remains disabled for the OLS release line. The inherited protocol edits
	// OpenLiteSpeed/LSPHP state and must not be reachable until it has an OLS-native
	// implementation and recovery tests.

	attemptTracker := middleware.NewLoginAttemptTracker(
		db,
		cfg.Security.MaxLoginAttempts,
		cfg.Security.AttemptWindowMinutes,
		cfg.Security.BanDurationHours,
	)
	attemptTracker.Audit = auditService

	basicAuthChecker := &middleware.BasicAuthChecker{
		RecordAttempt: attemptTracker.RecordAttempt,
		IsBanned:      attemptTracker.IsBanned,
	}

	staticPrefix := "/" + cfg.Panel.RandomSuffix + "/assets"
	staticFileSystem, _ := fs.Sub(staticFS, ".")
	r.Use(middleware.VersionedStaticCache(staticPrefix, version, staticFileSystem))
	r.StaticFS(staticPrefix, http.FS(staticFileSystem))

	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusNotFound, "Not Found")
	})
	r.GET("/favicon.ico", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	suffix := cfg.Panel.RandomSuffix
	prefix := "/" + suffix

	panelGroup := r.Group(prefix)
	panelGroup.Use(middleware.RandomPath(suffix))
	panelGroup.Use(middleware.BasicAuth(basicAuthChecker))
	authHandler := &handlers.AuthHandler{DB: db, Prefix: suffix, Tracker: attemptTracker, MFA: mfaService, Audit: auditService}

	// 面板根路径重定向到登录页（解决用户访问面板地址不带 /login 的问题）
	panelGroup.GET("", func(c *gin.Context) {
		if c.Request.URL.Path == "/"+suffix {
			c.Redirect(http.StatusFound, "/"+suffix+"/login")
			return
		}
		c.Next()
	})

	panelGroup.GET("/login", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
		c.Header("Pragma", "no-cache")
		i18n.MaybeSetLanguageCookie(c.Writer, c.Request)
		lang := i18n.LangFromRequest(c.Request)
		if !middleware.SetCSRFToken(c) {
			return
		}
		csrfToken := middleware.GetCSRFToken(c)
		c.HTML(http.StatusOK, "login.html", gin.H{
			"Title":        i18n.T(lang, "auth.login"),
			"PanelTitle":   handlers.GetPanelTitle(),
			"PanelVersion": version,
			"AssetVersion": version,
			"RandomSuffix": suffix,
			"Active":       "login",
			"AssetPrefix":  prefix + "/assets",
			"CSRFToken":    csrfToken,
			"Lang":         lang,
			"MessagesJSON": messageCatalog.JSON(lang, "login"),
		})
	})
	panelGroup.GET("/api/auth/csrf-token", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		if !middleware.SetCSRFToken(c) {
			return
		}
		authHandler.CSRFToken(c)
	})

	panelGroup.POST("/api/auth/login", middleware.CSRF(), func(c *gin.Context) {
		authHandler.Login(c)
	})

	cacheHelper := &handlers.CacheHelperHandler{}
	pluginImageOptimizer := &handlers.ImageOptimizerHandler{}

	pluginGroup := r.Group(prefix)
	pluginGroup.Use(middleware.RandomPath(suffix))
	pluginGroup.GET("/api/sites/find", cacheHelper.FindByDomain)
	pluginGroup.POST("/api/sites/companion/update", cacheHelper.UpdateCompanionPlugin)
	maintenanceHandler := &handlers.MaintenanceHandler{}
	pluginGroup.GET("/api/sites/maintenance", maintenanceHandler.Plugin)
	pluginGroup.POST("/api/sites/maintenance/:action", maintenanceHandler.Plugin)
	pluginGroup.GET("/api/sites/ssl/export", cacheHelper.ExportSSLCertificate)
	pluginGroup.DELETE("/api/sites/clear-cache", cacheHelper.ClearByDomain)
	pluginGroup.PUT("/api/sites/cache-settings", cacheHelper.UpdateCacheSettings)
	pluginGroup.PUT("/api/sites/optimizer-settings", cacheHelper.UpdateOptimizerSettings)
	pluginGroup.POST("/api/sites/image-optimizer/start", pluginImageOptimizer.PluginStart)
	pluginGroup.GET("/api/sites/image-optimizer/status", pluginImageOptimizer.PluginStatus)
	pluginGroup.POST("/api/sites/image-optimizer/stop", pluginImageOptimizer.PluginStop)

	protected := panelGroup.Group("")
	protected.Use(middleware.SessionRequired())
	protected.Use(func(c *gin.Context) {
		if !middleware.SetCSRFToken(c) {
			return
		}
		c.Next()
	})
	protected.Use(middleware.CSRF())
	protected.GET("/api/websites/:id/maintenance", maintenanceHandler.Panel)
	protected.PUT("/api/websites/:id/maintenance", maintenanceHandler.Panel)
	protected.POST("/api/websites/:id/maintenance/relock", maintenanceHandler.Panel)
	protected.POST("/api/websites/:id/maintenance/password", maintenanceHandler.Password)
	anomalyHandler := &handlers.WPAnomalyHandler{Monitor: executor.DefaultWPAnomalyMonitor(cfg)}
	protected.GET("/api/websites/:id/anomaly-monitor", anomalyHandler.Handle)
	protected.PUT("/api/websites/:id/anomaly-monitor", anomalyHandler.Handle)
	protected.POST("/api/websites/:id/anomaly-monitor/check", anomalyHandler.Handle)

	// Adminer has its own CSRF tokens. Keep it behind both panel authentication
	// layers, but do not apply the panel API CSRF header requirement to its HTML forms.
	adminerTool := panelGroup.Group("")
	adminerTool.Use(middleware.SessionRequired())
	adminerHandler := &handlers.AdminerHandler{}
	adminerTool.Any("/tools/adminer/:id", adminerHandler.Proxy)
	adminerTool.Any("/tools/adminer/:id/*path", adminerHandler.Proxy)

	protected.POST("/api/auth/logout", authHandler.Logout)
	protected.GET("/api/auth/check", authHandler.Check)
	protected.GET("/api/auth/mfa", authHandler.MFAStatus)
	protected.POST("/api/auth/mfa/setup", authHandler.MFASetup)
	protected.POST("/api/auth/mfa/confirm", authHandler.MFAConfirm)
	protected.POST("/api/auth/mfa/disable", authHandler.MFADisable)
	protected.POST("/api/auth/mfa/recovery-codes", authHandler.MFARecoveryCodes)
	protected.GET("/api/auth/sessions", authHandler.ListSessions)
	protected.DELETE("/api/auth/sessions/:id", authHandler.RevokeSession)
	protected.POST("/api/auth/sessions/revoke-others", authHandler.RevokeOtherSessions)
	protected.GET("/api/auth/audit", authHandler.AuditLog)
	protected.GET("/api/auth/security-notifications", authHandler.GetSecurityNotifications)
	protected.PUT("/api/auth/security-notifications", authHandler.SetSecurityNotifications)
	vpsHandler := &handlers.VPSHandler{}
	protected.GET("/api/vps/overview", vpsHandler.Overview)
	protected.GET("/api/vps/swap", vpsHandler.SwapStatus)
	protected.GET("/api/vps/dns", vpsHandler.DNSStatus)

	websiteHandler := &handlers.WebsiteHandler{DB: db}
	wpInventoryHandler := &handlers.WPInventoryHandler{DB: db}
	wpFleetOverviewHandler := &handlers.WPFleetOverviewHandler{DB: db}
	wpCoreUpdateHandler := newWPCoreUpdateHandler(db, cfg.Panel.BackupDir)
	wpPluginUpdateHandler := newWPPluginUpdateHandler(db, cfg.Panel.BackupDir)
	wpPluginBatchHandler := newWPPluginBatchHandler(db, cfg.Panel.BackupDir, cfg.Paths.WWWRoot)
	wpThemeUpdateHandler := newWPThemeUpdateHandler(db, cfg.Panel.BackupDir)
	wpUpdateBackupHandler := &handlers.WPUpdateBackupHandler{BackupDir: cfg.Panel.BackupDir}
	wpUpdateLogHandler := &handlers.WPUpdateLogHandler{}
	protected.GET("/api/websites", websiteHandler.List)
	protected.GET("/api/wp-fleet/overview", wpFleetOverviewHandler.Overview)
	protected.POST("/api/wp-fleet/inventory-refresh", wpFleetOverviewHandler.RefreshAll)
	protected.POST("/api/websites", websiteHandler.Create)
	protected.POST("/api/websites/ssl-preflight", websiteHandler.SSLPreflight)
	protected.GET("/api/websites/:id", websiteHandler.Get)
	protected.GET("/api/websites/:id/security-status", websiteHandler.SecurityStatus)
	protected.POST("/api/websites/:id/security-verify", websiteHandler.VerifySecurityStatus)
	wpPanelAccessHandler := &handlers.WPPanelAccessHandler{Auth: authHandler}
	protected.GET("/api/websites/:id/wp-panel-access", wpPanelAccessHandler.Status)
	protected.PUT("/api/websites/:id/wp-panel-access", wpPanelAccessHandler.Save)
	protected.POST("/api/websites/:id/wp-panel-access/login", wpPanelAccessHandler.Login)
	protected.POST("/api/websites/:id/wp-panel-access/revoke", wpPanelAccessHandler.Revoke)
	protected.GET("/api/websites/:id/wp-inventory", wpInventoryHandler.Summary)
	protected.POST("/api/websites/:id/wp-inventory/refresh", wpInventoryHandler.Refresh)
	protected.GET("/api/websites/:id/wp-inventory/tasks/:task_id", wpInventoryHandler.Task)
	protected.GET("/api/websites/:id/wp-inventory/components", wpInventoryHandler.Components)
	protected.GET("/api/websites/:id/wp-inventory/updates", wpInventoryHandler.Updates)
	protected.GET("/api/websites/:id/wp-core-update/preview", wpCoreUpdateHandler.Preview)
	protected.POST("/api/websites/:id/wp-core-update/confirm", wpCoreUpdateHandler.Confirm)
	protected.GET("/api/websites/:id/wp-core-update/tasks/latest", wpCoreUpdateHandler.LatestTask)
	protected.GET("/api/websites/:id/wp-core-update/tasks/:task_id", wpCoreUpdateHandler.Task)
	protected.GET("/api/websites/:id/wp-plugin-update/preview", wpPluginUpdateHandler.Preview)
	protected.POST("/api/websites/:id/wp-plugin-update/confirm", wpPluginUpdateHandler.Confirm)
	protected.GET("/api/websites/:id/wp-plugin-update/tasks/latest", wpPluginUpdateHandler.LatestTask)
	protected.GET("/api/websites/:id/wp-plugin-update/tasks/:task_id", wpPluginUpdateHandler.Task)
	protected.POST("/api/websites/:id/wp-plugin-batch", wpPluginBatchHandler.Create)
	protected.GET("/api/websites/:id/wp-plugin-batch", wpPluginBatchHandler.List)
	protected.GET("/api/websites/:id/wp-plugin-batch/:batch_id", wpPluginBatchHandler.Get)
	protected.POST("/api/websites/:id/wp-plugin-batch/tasks/:task_id/rollback", wpPluginBatchHandler.Rollback)
	protected.POST("/api/websites/:id/wp-plugin-batch/tasks/:task_id/ignore", wpPluginBatchHandler.Ignore)
	protected.GET("/api/websites/:id/wp-theme-update/preview", wpThemeUpdateHandler.Preview)
	protected.POST("/api/websites/:id/wp-theme-update/confirm", wpThemeUpdateHandler.Confirm)
	protected.GET("/api/websites/:id/wp-theme-update/tasks/latest", wpThemeUpdateHandler.LatestTask)
	protected.GET("/api/websites/:id/wp-theme-update/tasks/:task_id", wpThemeUpdateHandler.Task)
	protected.GET("/api/websites/:id/wp-update-backups", wpUpdateBackupHandler.List)
	protected.POST("/api/websites/:id/wp-update-backups/:backup_id/restore", wpUpdateBackupHandler.Restore)
	protected.GET("/api/websites/:id/wp-update-logs", wpUpdateLogHandler.List)
	protected.DELETE("/api/websites/:id", websiteHandler.Delete)
	protected.GET("/api/websites/:id/backup-usage", websiteHandler.BackupUsage)
	protected.PATCH("/api/websites/:id/status", websiteHandler.ToggleStatus)
	protected.POST("/api/websites/:id/ssl", websiteHandler.EnableSSL)
	protected.GET("/api/websites/:id/ssl/download", websiteHandler.DownloadSSLPackage)
	protected.PUT("/api/websites/:id/ssl/export", websiteHandler.SetSSLExport)
	protected.GET("/api/websites/:id/ssl/renewal", websiteHandler.SSLRenewal)
	protected.PUT("/api/websites/:id/ssl/renewal", websiteHandler.SSLRenewal)
	protected.DELETE("/api/websites/:id/ssl", websiteHandler.RemoveSSL)
	protected.PUT("/api/websites/:id/db-password", websiteHandler.ChangeDBPassword)
	protected.POST("/api/websites/:id/fix-wp-config", websiteHandler.FixWPConfig)
	protected.GET("/api/websites/:id/detect-table-prefix", websiteHandler.DetectDBTablePrefix)
	protected.GET("/api/websites/:id/wp-site-urls", websiteHandler.GetWPSiteURLs)
	protected.PUT("/api/websites/:id/wp-site-urls", websiteHandler.UpdateWPSiteURLs)
	protected.GET("/api/websites/:id/wp-administrators", websiteHandler.ListWPAdministrators)
	protected.PUT("/api/websites/:id/wp-administrators", websiteHandler.UpdateWPAdministrator)
	protected.GET("/api/websites/:id/logs", websiteHandler.ViewLogs)
	protected.GET("/api/websites/:id/log-files", websiteHandler.ListLogFiles)
	protected.GET("/api/websites/:id/logs/download", websiteHandler.DownloadLogFile)
	protected.DELETE("/api/websites/:id/logs", websiteHandler.ClearLogs)
	protected.PUT("/api/websites/:id/domains", websiteHandler.UpdateDomains)
	protected.PUT("/api/websites/:id/cache", websiteHandler.UpdateCache)
	protected.DELETE("/api/websites/:id/cache", websiteHandler.ClearCache)
	protected.GET("/api/websites/:id/litespeed-cache/status", websiteHandler.LiteSpeedCacheStatus)
	protected.POST("/api/websites/:id/litespeed-cache/verify", websiteHandler.VerifyLiteSpeedPageCache)
	protected.POST("/api/websites/:id/litespeed-cache/migrate", websiteHandler.MigrateLiteSpeedCacheSettings)
	protected.DELETE("/api/websites/:id/redis-object-cache", websiteHandler.ClearRedisObjectCache)
	protected.PUT("/api/websites/:id/wp-optimizations", websiteHandler.SaveWPOptimizations)
	protected.PUT("/api/websites/:id/wp-update-checks", websiteHandler.SetWPUpdateChecks)
	protected.PUT("/api/websites/:id/file-editor", websiteHandler.SetFileEditingProtection)
	protected.PUT("/api/websites/:id/password-reset", websiteHandler.SetPasswordResetMode)
	protected.PUT("/api/websites/:id/file-lock", websiteHandler.SetFileLock)
	protected.GET("/api/websites/:id/file-lock/preview", websiteHandler.PreviewFileLock)
	protected.PUT("/api/websites/:id/monitoring", websiteHandler.SaveMonitoring)
	protected.POST("/api/websites/:id/retire-optimizer", websiteHandler.RetireOptimizer)
	protected.GET("/api/websites/:id/install-plugin/status", websiteHandler.InstallPluginStatus)
	protected.POST("/api/websites/:id/reinstall-wp", websiteHandler.ReinstallWordPress)
	aiDevelopmentHandler := &handlers.AIDevelopmentAccessHandler{}
	protected.GET("/api/websites/:id/ai-development-access", aiDevelopmentHandler.Status)
	protected.POST("/api/websites/:id/ai-development-access", aiDevelopmentHandler.Enable)
	protected.POST("/api/websites/:id/ai-development-access/rotate", aiDevelopmentHandler.Rotate)
	protected.DELETE("/api/websites/:id/ai-development-access", aiDevelopmentHandler.Disable)
	protected.PUT("/api/websites/:id/access-log", websiteHandler.SetAccessLogMode)
	protected.PUT("/api/websites/:id/document-root", websiteHandler.SetDocumentRoot)
	protected.PUT("/api/websites/:id/php-version", websiteHandler.SetPHPVersion)
	protected.PUT("/api/websites/:id/cdn-realip", websiteHandler.SetCDNRealIP)
	protected.PUT("/api/websites/:id/log-retention", websiteHandler.SetLogRetention)
	protected.PUT("/api/websites/:id/expiry", websiteHandler.UpdateExpiry)
	backupHandler := &handlers.BackupHandler{}
	protected.GET("/api/websites/:id/backups", backupHandler.List)
	protected.POST("/api/websites/:id/backups", backupHandler.Create)
	protected.DELETE("/api/websites/:id/backups/:bid", backupHandler.Delete)
	protected.GET("/api/websites/:id/backups/:bid/download", backupHandler.Download)
	protected.POST("/api/websites/:id/backups/:bid/restore", backupHandler.Restore)
	protected.DELETE("/api/websites/:id/file-backups/:bid", backupHandler.DeleteFileBackup)
	protected.GET("/api/websites/:id/file-backups/:bid/download", backupHandler.DownloadFileBackup)
	protected.POST("/api/websites/:id/backups/upload-restore", backupHandler.UploadRestore)
	protected.GET("/api/websites/:id/backups/restore-tasks/:task_id", backupHandler.RestoreStatus)
	protected.GET("/api/websites/:id/backups/settings", backupHandler.GetSettings)
	protected.PUT("/api/websites/:id/backups/settings", backupHandler.UpdateSettings)
	protected.POST("/api/websites/:id/backups/clear-database", backupHandler.ClearDatabase)
	databaseManagerHandler := &handlers.DatabaseManagerHandler{}
	protected.GET("/api/databases", databaseManagerHandler.List)
	protected.GET("/api/websites/:id/adminer/status", adminerHandler.Status)
	protected.POST("/api/websites/:id/adminer/enable", adminerHandler.Enable)
	protected.POST("/api/websites/:id/adminer/disable", adminerHandler.Disable)
	protected.GET("/api/backups/overview", handlers.GetBackupOverview)
	protected.GET("/api/backups/policy", handlers.GetBackupPolicy)
	protected.PUT("/api/backups/policy", handlers.SaveBackupPolicy)
	protected.POST("/api/backups/reconcile-status", handlers.ReconcileBackupStatus)

	dashboardHandler := &handlers.DashboardHandler{}
	protected.GET("/api/dashboard/stats", dashboardHandler.GetStats)
	protected.GET("/api/dashboard/metrics", dashboardHandler.GetMetrics)
	protected.GET("/api/dashboard/site-resources", dashboardHandler.GetSiteResources)
	protected.GET("/api/announcement", handlers.GetAnnouncement)

	firewallHandler := &handlers.FirewallHandler{}
	protected.GET("/api/firewall/bans", firewallHandler.ListBans)
	protected.GET("/api/firewall/wp-security-report", firewallHandler.WPSecurityReport)
	protected.GET("/api/firewall/file-security-events", firewallHandler.ListFileSecurityEvents)
	protected.POST("/api/firewall/file-security-events/refresh", firewallHandler.RefreshFileSecurityEvents)
	protected.POST("/api/firewall/bans", firewallHandler.ManualBan)
	protected.DELETE("/api/firewall/bans/:id", firewallHandler.Unban)
	protected.POST("/api/firewall/bans/:id/permanent", firewallHandler.PermanentBan)
	protected.GET("/api/firewall/ports", firewallHandler.PortStatus)
	protected.POST("/api/firewall/ports", firewallHandler.AddPortRule)
	protected.POST("/api/firewall/ports/protection", firewallHandler.EnablePortProtection)
	protected.POST("/api/firewall/ports/access/preview", firewallHandler.PreviewAccess)
	protected.POST("/api/firewall/ports/access/apply", firewallHandler.ApplyAccess)
	protected.POST("/api/firewall/ports/access/confirm", firewallHandler.ConfirmAccess)
	protected.GET("/api/firewall/ssh-port", firewallHandler.SSHPortStatus)
	protected.POST("/api/firewall/ssh-port", firewallHandler.ChangeSSHPort)
	protected.POST("/api/firewall/ssh-port/confirm", firewallHandler.ConfirmSSHPort)
	protected.POST("/api/firewall/ports/protection/confirm", firewallHandler.ConfirmPortProtection)
	protected.DELETE("/api/firewall/ports/:id", firewallHandler.DeletePortRule)

	securityHandler := &handlers.SecurityHandler{}
	protected.GET("/api/security/settings", securityHandler.GetSettings)
	protected.GET("/api/security/status", securityHandler.GetStatus)
	protected.PUT("/api/security/settings", securityHandler.UpdateSettings)
	protected.POST("/api/security/whitelist/refresh", securityHandler.RefreshWhitelist)
	protected.PUT("/api/security/whitelist/googlebot", securityHandler.ImportGooglebotRanges)
	protected.GET("/api/security/cdn-realip-groups", securityHandler.ListCDNRealIPGroups)
	protected.POST("/api/security/cdn-realip-groups", securityHandler.CreateCDNRealIPGroup)
	protected.PUT("/api/security/cdn-realip-groups/:id", securityHandler.UpdateCDNRealIPGroup)
	protected.DELETE("/api/security/cdn-realip-groups/:id", securityHandler.DeleteCDNRealIPGroup)

	alertHandler := &handlers.AlertHandler{}
	protected.GET("/api/alert/settings", alertHandler.GetSettings)
	protected.PUT("/api/alert/settings", alertHandler.SaveSettings)
	protected.POST("/api/alert/smtp-config/export", alertHandler.ExportSMTPConfig)
	protected.POST("/api/alert/smtp-config/import", alertHandler.ImportSMTPConfig)
	protected.POST("/api/alert/test-smtp", alertHandler.TestSMTP)
	protected.POST("/api/alert/test-webhook", alertHandler.TestWebhook)
	protected.GET("/api/alert/log", alertHandler.GetLog)

	cronHandler := &handlers.CronHandler{}
	protected.GET("/api/cron", cronHandler.List)
	protected.POST("/api/cron", cronHandler.Create)
	protected.PUT("/api/cron/:id", cronHandler.Update)
	protected.DELETE("/api/cron/:id", cronHandler.Delete)
	protected.POST("/api/cron/:id/run", cronHandler.Run)
	protected.GET("/api/cron/system", cronHandler.SystemList)
	protected.GET("/api/cron/logs", cronHandler.ViewLogs)

	fileHandler := &handlers.FileHandler{}
	protected.GET("/api/files/list", fileHandler.List)
	protected.GET("/api/files/search", fileHandler.Search)
	protected.GET("/api/files/size", fileHandler.DirectorySize)
	protected.POST("/api/files/upload", fileHandler.Upload)
	protected.POST("/api/files/upload/init", fileHandler.UploadInit)
	protected.POST("/api/files/upload/chunk", fileHandler.UploadChunk)
	protected.POST("/api/files/upload/complete", fileHandler.UploadComplete)
	protected.POST("/api/files/remote-import", fileHandler.RemoteImport)
	protected.GET("/api/files/remote-import/:id", fileHandler.RemoteImportStatus)
	protected.GET("/api/files/download", fileHandler.Download)
	protected.DELETE("/api/files/delete", fileHandler.Delete)
	protected.PUT("/api/files/rename", fileHandler.Rename)
	protected.GET("/api/files/permissions", fileHandler.Permissions)
	protected.POST("/api/files/batch-zip", fileHandler.BatchCompress)
	protected.POST("/api/files/move", fileHandler.Move)
	protected.POST("/api/files/copy", fileHandler.Copy)
	protected.POST("/api/files/zip", fileHandler.Compress)
	protected.POST("/api/files/unzip", fileHandler.Decompress)
	protected.POST("/api/files/mkdir", fileHandler.CreateDir)
	protected.POST("/api/files/fix-permissions", fileHandler.FixPermissions)

	wpPackageService, err := executor.SharedWPPackageService(cfg)
	if err != nil {
		log.Printf("WordPress package service disabled: code=%s", executor.ArchiveErrorCode(err))
	}
	settingsHandler := &handlers.SettingsHandler{WPPackageService: wpPackageService, ConfigPath: configPath, Auth: authHandler}
	aiHandler := &handlers.AIHandler{}
	logAnalysisHandler := &handlers.LogAnalysisHandler{}
	protected.GET("/api/settings", settingsHandler.GetSettings)
	protected.GET("/api/settings/panel-certificate", settingsHandler.PanelCertificateStatus)
	protected.POST("/api/settings/panel-domain/check", settingsHandler.CheckPanelDomain)
	protected.POST("/api/settings/panel-certificate", settingsHandler.ApplyPanelCertificate)
	protected.PUT("/api/settings", settingsHandler.UpdateSettings)
	protected.GET("/api/settings/logs", settingsHandler.GetOperationLogs)
	protected.GET("/api/settings/wp-package", settingsHandler.GetWPPackage)
	protected.POST("/api/settings/wp-package/upload", settingsHandler.UploadWPPackage)
	protected.POST("/api/settings/wp-package/download", settingsHandler.DownloadWPPackage)
	protected.DELETE("/api/settings/wp-package", settingsHandler.DeleteWPPackage)
	protected.GET("/api/settings/remote-backup", handlers.GetRemoteBackup)
	protected.PUT("/api/settings/remote-backup", handlers.SaveRemoteBackup)
	protected.POST("/api/settings/remote-backup/test", handlers.TestRemoteBackup)
	protected.GET("/api/settings/db-backup", settingsHandler.GetDBBackups)
	protected.POST("/api/settings/db-backup", settingsHandler.CreateDBBackup)
	protected.POST("/api/settings/db-backup/restore", settingsHandler.RestoreDBBackup)
	protected.GET("/api/settings/db-backup/restore-status", settingsHandler.GetDBRestoreStatus)
	protected.DELETE("/api/settings/db-backup", settingsHandler.DeleteDBBackup)
	protected.GET("/api/settings/db-backup/:filename/download", settingsHandler.DownloadDBBackup)
	protected.GET("/api/proxy/test", settingsHandler.TestProxy)
	protected.GET("/api/ai/settings", aiHandler.GetSettings)
	protected.PUT("/api/ai/settings", aiHandler.SaveSettings)
	protected.POST("/api/ai/test", aiHandler.Test)
	protected.POST("/api/websites/:id/ai/diagnose", aiHandler.Diagnose)
	protected.GET("/api/websites/:id/ai/sessions", aiHandler.ListSessions)
	protected.GET("/api/websites/:id/ai/sessions/:session_id", aiHandler.GetSession)
	protected.GET("/api/websites/:id/ai/sessions/:session_id/messages", aiHandler.ListMessages)
	protected.POST("/api/websites/:id/ai/sessions/:session_id/messages", aiHandler.SendMessage)
	protected.POST("/api/log-analysis", logAnalysisHandler.Start)
	protected.GET("/api/log-analysis", logAnalysisHandler.List)
	protected.GET("/api/log-analysis/:id", logAnalysisHandler.Get)
	protected.GET("/api/log-analysis/:id/details", logAnalysisHandler.Details)
	protected.POST("/api/log-analysis/:id/diagnostic-session", logAnalysisHandler.CreateDiagnosticSession)

	protected.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", pageData(suffix, "dashboard", "dashboard_content", c, messageCatalog))
	})
	protected.GET("/websites", func(c *gin.Context) {
		c.HTML(http.StatusOK, "websites.html", pageData(suffix, "websites", "websites_content", c, messageCatalog))
	})
	protected.GET("/wordpress-overview", func(c *gin.Context) {
		c.HTML(http.StatusOK, "wordpress_overview.html", pageData(suffix, "wordpress_overview", "wordpress_overview_content", c, messageCatalog))
	})
	protected.GET("/websites/new", func(c *gin.Context) {
		c.HTML(http.StatusOK, "website_new.html", pageData(suffix, "websites", "websites_new_content", c, messageCatalog))
	})
	protected.GET("/websites/:id", func(c *gin.Context) {
		c.HTML(http.StatusOK, "website_detail.html", pageData(suffix, "websites", "websites_detail_content", c, messageCatalog))
	})
	protected.GET("/websites/:id/wordpress", func(c *gin.Context) {
		c.HTML(http.StatusOK, "wordpress_site_detail.html", pageData(suffix, "wordpress_overview", "wordpress_site_detail_content", c, messageCatalog))
	})
	protected.GET("/databases", func(c *gin.Context) {
		c.HTML(http.StatusOK, "databases.html", pageData(suffix, "databases", "databases_content", c, messageCatalog))
	})
	protected.GET("/databases/:id", func(c *gin.Context) {
		c.HTML(http.StatusOK, "database_detail.html", pageData(suffix, "databases", "database_detail_content", c, messageCatalog))
	})
	protected.GET("/ai-diagnostics", func(c *gin.Context) {
		c.HTML(http.StatusOK, "ai_diagnostics.html", pageData(suffix, "ai-diagnostics", "ai_diagnostics_content", c, messageCatalog))
	})
	protected.GET("/log-analysis", func(c *gin.Context) {
		c.HTML(http.StatusOK, "log_analysis.html", pageData(suffix, "log-analysis", "log_analysis_content", c, messageCatalog))
	})
	protected.GET("/cron", func(c *gin.Context) {
		c.HTML(http.StatusOK, "cron.html", pageData(suffix, "cron", "cron_content", c, messageCatalog))
	})
	protected.GET("/backups", func(c *gin.Context) {
		c.HTML(http.StatusOK, "backups.html", pageData(suffix, "backups", "backups_content", c, messageCatalog))
	})
	protected.GET("/backups/remote-settings", func(c *gin.Context) {
		data := pageData(suffix, "backups", "remote_backup_settings_content", c, messageCatalog)
		data["Title"] = i18n.T(i18n.LangFromRequest(c.Request), "backups.remote_settings")
		c.HTML(http.StatusOK, "remote_backup_settings.html", data)
	})
	protected.GET("/firewall", func(c *gin.Context) {
		c.HTML(http.StatusOK, "firewall.html", pageData(suffix, "firewall", "firewall_content", c, messageCatalog))
	})
	protected.GET("/files", func(c *gin.Context) {
		c.HTML(http.StatusOK, "files.html", pageData(suffix, "files", "files_content", c, messageCatalog))
	})
	protected.GET("/security", func(c *gin.Context) {
		c.HTML(http.StatusOK, "security.html", pageData(suffix, "security", "security_content", c, messageCatalog))
	})
	protected.GET("/alert", func(c *gin.Context) {
		c.HTML(http.StatusOK, "alert.html", pageData(suffix, "alert", "alert_content", c, messageCatalog))
	})
	protected.GET("/vps", func(c *gin.Context) {
		c.HTML(http.StatusOK, "vps.html", pageData(suffix, "vps", "vps_content", c, messageCatalog))
	})
	protected.GET("/settings", func(c *gin.Context) {
		c.HTML(http.StatusOK, "settings.html", pageData(suffix, "settings", "settings_content", c, messageCatalog))
	})
	protected.GET("/help", func(c *gin.Context) {
		c.HTML(http.StatusOK, "help.html", pageData(suffix, "help", "help_content", c, messageCatalog))
	})

	softwareHandler := &handlers.SoftwareHandler{}
	protected.GET("/software", func(c *gin.Context) {
		c.HTML(http.StatusOK, "software.html", pageData(suffix, "software", "software_content", c, messageCatalog))
	})
	protected.GET("/api/software", softwareHandler.List)
	protected.GET("/api/software/development-tools", softwareHandler.DevelopmentTools)
	protected.POST("/api/software/development-tools/install", softwareHandler.InstallDevelopmentTool)
	protected.GET("/api/software/php-runtimes", softwareHandler.PHPRuntimes)
	protected.POST("/api/software/php-runtimes/install", softwareHandler.InstallPHPRuntime)
	protected.GET("/api/software/recommend", softwareHandler.Recommend)
	protected.POST("/api/software/opcache/clear", softwareHandler.ClearOpcache)
	protected.GET("/api/software/guard", softwareHandler.GetGuardStatus)
	protected.POST("/api/software/guard/action", softwareHandler.GuardAction)
	protected.PUT("/api/software/config", softwareHandler.SaveConfig)
	protected.PUT("/api/software/php-config", softwareHandler.SavePHPBatchConfig)
	protected.GET("/api/software/log", softwareHandler.ViewLog)
	protected.DELETE("/api/software/log", softwareHandler.ClearLog)
	updateHandler := &handlers.UpdateHandler{CurrentVersion: version, ConfigPath: configPath, Config: cfg}
	protected.GET("/api/update/check", updateHandler.Check)
	protected.GET("/api/update/status", updateHandler.Status)
	protected.POST("/api/update/do", updateHandler.Update)
	sysUpdateHandler := &handlers.SystemUpdateHandler{Config: cfg}
	protected.GET("/api/system/updates", sysUpdateHandler.Check)
	protected.GET("/api/system/updates/status", sysUpdateHandler.Status)
	protected.POST("/api/system/updates/do", sysUpdateHandler.Update)

	tmpl := template.Must(template.New("").Funcs(i18n.FuncMap()).ParseFS(tmplFS, "templates/*.html"))
	r.SetHTMLTemplate(tmpl)

	return r, auditService.Close
}

func newWPCoreUpdateHandler(db *sql.DB, backupDir string) *handlers.WPCoreUpdateHandler {
	handler := &handlers.WPCoreUpdateHandler{}
	service, err := executor.NewWPCoreUpdateService(db, backupDir)
	if err != nil {
		log.Println("WordPress 核心更新 API 未启用")
		return handler
	}
	handler.Service = service
	return handler
}

func newWPPluginUpdateHandler(db *sql.DB, backupDir string) *handlers.WPPluginUpdateHandler {
	handler := &handlers.WPPluginUpdateHandler{}
	service, err := executor.NewWPPluginUpdateService(db, backupDir)
	if err != nil {
		log.Println("WordPress 插件更新 API 未启用")
		return handler
	}
	handler.Service = service
	return handler
}

func newWPPluginBatchHandler(db *sql.DB, backupDir, wwwRoot string) *handlers.WPPluginBatchHandler {
	handler := &handlers.WPPluginBatchHandler{}
	service, err := executor.NewWPPluginBatchService(db, backupDir, wwwRoot)
	if err != nil {
		log.Println("WordPress 插件批量更新 API 未启用")
		return handler
	}
	handler.Service = service
	return handler
}

func newWPThemeUpdateHandler(db *sql.DB, backupDir string) *handlers.WPThemeUpdateHandler {
	handler := &handlers.WPThemeUpdateHandler{}
	service, err := executor.NewWPThemeUpdateService(db, backupDir)
	if err != nil {
		log.Println("WordPress 主题更新 API 未启用")
		return handler
	}
	handler.Service = service
	return handler
}

var pageTitleKeys = map[string]string{
	"dashboard":          "nav.dashboard",
	"websites":           "nav.websites",
	"wordpress_overview": "nav.wordpress_overview",
	"databases":          "nav.databases",
	"ai-diagnostics":     "nav.ai_diagnostics",
	"log-analysis":       "nav.log_analysis",
	"cron":               "nav.cron",
	"backups":            "nav.backups",
	"firewall":           "nav.firewall",
	"security":           "nav.security",
	"files":              "nav.files",
	"software":           "nav.software",
	"alert":              "nav.alert",
	"vps":                "nav.vps",
	"settings":           "nav.settings",
	"help":               "nav.help",
}

func pageData(suffix string, active string, contentTpl string, c *gin.Context, catalog *i18n.TemplateMessages) gin.H {
	i18n.MaybeSetLanguageCookie(c.Writer, c.Request)
	lang := i18n.LangFromRequest(c.Request)
	csrfToken := middleware.GetCSRFToken(c)
	title := i18n.T(lang, pageTitleKeys[active])
	return gin.H{
		"Title":           title,
		"PanelTitle":      handlers.GetPanelTitle(),
		"PanelVersion":    panelVersion,
		"AssetVersion":    panelVersion,
		"ContentTemplate": contentTpl,
		"RandomSuffix":    suffix,
		"Active":          active,
		"AssetPrefix":     "/" + suffix + "/assets",
		"CSRFToken":       csrfToken,
		"Lang":            lang,
		"MessagesJSON":    catalog.JSON(lang, contentTpl),
	}
}
