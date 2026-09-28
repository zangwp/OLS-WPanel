# Installation identity and upgrade compatibility

`v1.0.0` is the first OLS WPanel release. It supports fresh installation on Debian 13/Trixie and Ubuntu 24.04/Noble for amd64 and arm64.

It is not an in-place upgrade for another panel or distribution identity. OpenLiteSpeed virtual hosts, LSPHP applications, service units, CLI entry points, site secrets, database records, certificates, and release-signing identities are managed as one distribution. Renaming or replacing only part of an existing installation can leave the server in an unsafe mixed state.

Use a clean server for `v1.0.0`. To move an existing WordPress site, first create a full snapshot and export the WordPress files, database, and certificates. Import them only after confirming that the new OLS WPanel host is healthy.

Repair mode is limited to installations already created by OLS WPanel with these identities:

- `/etc/cron.d/ols_wpanel_cron`
- `ols-wpanel`
- `/etc/systemd/system/ols-wpanel.service`
- `/usr/local/bin/ols-wpanel`

A mismatch fails closed. Do not bypass the check by editing `config.json`, adding service drop-ins, or manually renaming another panel.
