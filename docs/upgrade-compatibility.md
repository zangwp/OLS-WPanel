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

## Release and installation entry

GitHub publication and the Cloudflare short-entry deployment are separate operations. A new GitHub Release does not change the deployed installer endpoint by itself. Until the endpoint is updated, use the explicit signed version in the [verified installation guide](verified-install.md) for a reproducible install or repair. Never replace versioned assets with mutable branch downloads.
