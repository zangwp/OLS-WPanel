# Installation identity and upgrade compatibility

`v1.0.0` is the first OLS WPanel release. Current releases support fresh installation on Debian 13/Trixie, Ubuntu 24.04/Noble, and Ubuntu 26.04/Resolute for amd64 and arm64.

It is not an in-place upgrade for another panel or distribution identity. OpenLiteSpeed virtual hosts, LSPHP applications, service units, CLI entry points, site secrets, database records, certificates, and release-signing identities are managed as one distribution. Renaming or replacing only part of an existing installation can leave the server in an unsafe mixed state.

Use a clean server for `v1.0.0`. To move an existing WordPress site, first create a full snapshot and export the WordPress files, database, and certificates. Import them only after confirming that the new OLS WPanel host is healthy.

Repair mode is limited to installations already created by OLS WPanel with these identities:

- `/etc/cron.d/ols_wpanel_cron`
- `ols-wpanel`
- `/etc/systemd/system/ols-wpanel.service`
- `/usr/local/bin/ols-wpanel`

A mismatch fails closed. Do not bypass the check by editing `config.json`, adding service drop-ins, or manually renaming another panel.

## Upgrading an existing OLS WPanel installation to v1.18.0

Use the panel update flow or the signed installer in update / repair mode. Create a panel database backup and preserve the current configuration before starting. Do not select fresh installation or reinstallation to repair an installation that contains websites: the installer now refuses retained site registrations, files or runtime configuration, including files left after an ordinary uninstall.

All repair/update paths reject a release older than the installed version. If the installed version cannot be read and compared, repair stops before mutation; diagnose the binary and configuration instead of bypassing the guard. Ordinary uninstall retains the running website/database software and its package repositories and verification keys. It still removes panel-local state, so export the necessary backups before uninstalling.

The v1.18.0 account-security schema is created on startup. Existing administrators are not enrolled in two-factor authentication automatically. Wait for the update task and health check to finish, then sign in and deliberately enroll if desired. A service restart invalidates in-memory sessions, so browsers must sign in again.

## MFA backup and rollback boundary

The database directory gains a private `account-mfa.key` file. The database contains encrypted TOTP secrets; restoring it on another host also requires its original matching key. Save the key through a trusted host-management channel into a separate encrypted backup, preserving ownership and mode `0600`. Ordinary downloadable panel database backups do not include it. Private installer repair snapshots include the existing key.

Recovery codes solve loss of the authenticator, not loss of the encryption key. If an enrolled database loses its key, the service fails closed instead of generating a replacement or disabling MFA. See [account security and recovery](account-security.md) and [WAL-safe database recovery](operations-and-recovery.md).

Do not run a pre-v1.18.0 binary against an MFA-enabled account as a transparent rollback: that binary does not enforce the new authentication checks. Use a compatible build, and preserve the paired database and key when recovering. Restoring an older database also restores its old account settings and recovery-code usage state; review the MFA state and regenerate recovery codes after restoration.

## Website security in v1.20.0

The update adds schema migration `1.0.74` for independent security-log source positions. Startup installs the native WordPress login-failure audit block and rebuilds managed OpenLiteSpeed virtual hosts. Existing site settings determine XML-RPC and URL/query SQLi enforcement; the update does not enable every optional security feature automatically.

After the update and background configuration rebuild finish, refresh **Website details → Website security**. A saved setting or generated configuration is not proof of active protection: live denial responses, trusted recent audit evidence and the exact running login jail are checked separately. Without reliable evidence, the page reports configured or unverified rather than protected. The SQLi rules are narrow URL/query guards, not a complete WAF or request-body inspection.

LiteSpeed Cache remains the authority for WordPress cache settings. Refresh the site's cache status to read page-cache and Redis object-cache configuration; failed or unsupported checks do not imply the cache is disabled. The panel domain continues to use its configured listening port, while HTTP-01 certificate validation requires the dedicated domain to reach this server on port 80.

## WordPress access and caching since v1.21.0

WordPress administrator sign-in through the panel is optional and disabled by default. Saving access settings requires the panel password and configured MFA. Since v1.21.3, enabled passwordless sign-in uses the current authenticated panel session without asking for credentials again. Each authorization expires after 60 seconds and can be redeemed once. Existing website users and passwords remain unchanged; unfinished WordPress installations still open their setup wizard. Recognized conflicting authentication plugins disable the feature. Keep it off for unverified custom authentication systems.

Since v1.21.3, upgrade step `1.0.75` reconciles managed HTTP/HTTPS listeners on already running OpenLiteSpeed installations with usable local IPv6. Website configuration updates also recheck IPv6 availability. IPv4 is retained, and optional IPv6 failures use the validated IPv4 fallback. DNS and cloud firewall settings remain administrator-managed. See [OpenLiteSpeed networking and index files](openlitespeed-networking.md) for detection, mappings and reachability boundaries.

New WordPress sites created from a recorded official download clean unused bundled plugins and themes after the initial installation wizard. Existing sites, reinstalls, restores, imports and custom uploaded packages are left intact. See [WordPress new-install defaults](wordpress-new-install-defaults.md) for active-theme protection and download-origin checks.

Managed HTTPS listeners and website SNI blocks now allow TLS 1.2/1.3. Regenerating virtual hosts preserves each website's saved PHP concurrency limit, and successful automatic configuration writes enforce the existing seven-version configuration-history limit. Database and full-site backup retention is unchanged. New-site deployment prepares missing WordPress permalink rules before OpenLiteSpeed first loads the site; existing `.htaccess` files and generic reinstall/import deployment remain untouched.

Upgrade step `1.0.76` connects explicitly enabled CDN proxy ranges to the server ACL that OpenLiteSpeed reads. Only recognized, running and unpaused managed services are reconciled. Existing allow rules and file metadata are retained; server deny rules, ambiguous configuration or manual changes stop automatic trust additions and require review. Startup errors are logged without blocking the panel; normal settings saves report failed or incomplete restoration. See the trusted-proxy section of the networking guide before using a customized main configuration.

Migration `1.0.77` creates separate per-website Cloudflare settings. Existing sites are not connected or enabled automatically. Each site can bind its own Account ID and API Token; the panel identifies and retains the matching Zone automatically. Enabled sites share the website Fail2ban ban set through custom WAF rules covering the primary hostname and registered aliases within that Zone, including registered `www` hostnames. Aliases outside the authorized Zone are reported as incomplete coverage before any rule changes. SSH, panel and ambiguous manual bans are excluded. Google/Bing identification caches no longer automatically grant website Fail2ban exemptions. Review the [Cloudflare website protection guide](cloudflare-website-protection.md) before enabling synchronization.

Migration `1.0.78` stores the identified Zone name and the hostnames last confirmed in the panel's remote rule separately from the website's current domain list. After aliases change, synchronization remains pending until the new coverage is confirmed. An existing rule keeps its original binding during API Token replacement; after the old rule is removed, enabling the site identifies the Zone again.

Preserve the private `cloudflare-security.key` beside the database separately from downloadable SQLite backups. Private installer repair snapshots retain it. Restoring a database does not restore Cloudflare remote rules; after recovery, inspect site credentials and synchronization state. Missing keys and conflicting remote rule ownership are reported instead of silently replacing credentials or administrator rules.

The panel no longer provides a second WordPress page-cache switch. It prepares selective OpenLiteSpeed cache support and reads the active LiteSpeed Cache plugin policy. The cache verification action reports anonymous requests to the local origin separately from plugin configuration; a successful setup does not imply every request is cached. See the [WordPress access and cache guide](wordpress-access-and-cache.md).

## Release and installation entry

GitHub publication and the Cloudflare short-entry deployment are separate operations. A new GitHub Release does not change the deployed installer endpoint by itself. Until the endpoint is updated, use the explicit signed version in the [verified installation guide](verified-install.md) for a reproducible install or repair. Never replace versioned assets with mutable branch downloads.
