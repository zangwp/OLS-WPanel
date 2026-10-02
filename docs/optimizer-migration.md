# Optimizer migration in v1.14.0

OLS WPanel no longer installs or automatically upgrades the standalone OLS WPanel Optimizer. Existing sites are migrated explicitly rather than deleting running plugins during a panel restart.

1. Upgrade the panel to v1.14.0.
2. Close any temporary maintenance window and disable site file protection in Website Details.
3. Open Cache & Performance and select **Migrate and remove old Optimizer**.
4. Re-enable the required file-protection mode after migration.

The migration applies the panel's recorded WordPress policies before deactivating Optimizer. It removes only Optimizer from the active plugin list, clears its cache-preload cron hook, archives its directory under `/var/ols-wpanel/retired-plugins/<site-id>/`, and revokes its panel API key and certificate-export permission. LiteSpeed Cache, other plugins and WordPress options are retained. The legacy uninstall hook is deliberately not executed because it also removes cache configuration.

If archival fails after deactivation, the error explicitly reports that the plugin is already inactive. Native policy remains in place. Retry the panel migration after correcting the archive issue. Never blindly re-enable Optimizer merely to clear the error. Multisite migrations are currently unsupported.

The panel directly manages file permissions, maintenance windows, wp-config constants and read-only anomaly monitoring. Monitoring executes only through the existing isolated site-user CLI runner and preserves the existing anomaly baseline. It no longer needs an active WordPress companion plugin.

WordPress-specific application-password and update-check restrictions still require PHP hooks. The panel now writes a small marked block in `wp-config.php`, using WordPress's preinitialized hook mechanism; it has no settings page, panel HTTP calls or periodic plugin work. The existing panel-managed password-reset MU rule remains when that protection is enabled. Removing Optimizer does not mean that every WordPress security rule can operate without PHP code.

Use LiteSpeed Cache for cache exclusions, page optimization, image optimization and cache crawling. Panel integration buttons formerly shown inside WordPress admin are removed along with Optimizer; use Website Details in the panel instead.
