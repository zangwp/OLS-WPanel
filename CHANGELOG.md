# Changelog

## v1.0.0 — 2026-09-27

Initial OLS WPanel release.

- Uses OpenLiteSpeed with isolated per-site LSPHP 8.3 external applications.
- Creates OpenLiteSpeed virtual hosts, HTTP/HTTPS listener mappings, rewrite support, certificates, log paths, LSAPI sockets, and rollback-safe configuration updates automatically for every site.
- Removes the legacy web-server execution path, package assumptions, configuration templates, real-IP helpers, cache handlers, and duplicate per-site runtime files; the installer does not remove unrelated services already present on the host.
- Stores the real per-site LSPHP socket and OpenLiteSpeed virtual-host path, with PHP limits and isolation rendered directly into the OLS virtual host.
- Installs and activates the official LiteSpeed Cache plugin for new WordPress sites and preconfigures Redis object caching with a per-site key prefix.
- Uses `litespeed_cache_*` consistently across the database, API, panel UI, diagnostics, migration snapshots, and companion plugin.
- Supports Debian 13 and Ubuntu 24.04 LTS on amd64 and arm64; ARM64 hosts with unsupported 16 KiB page-size kernels fail closed before installation.
- Adds native-architecture CI checks for the panel, installer syntax, supported-platform detection, and availability of all required OpenLiteSpeed/LSPHP packages.
- Provides signed, architecture-qualified release assets and the verified `https://ols.zangyubin.top/install` entry point.
- Uses only `o` and `O` as panel management commands.
- Keeps the previous site-migration protocol disabled and unreachable until an OLS-native implementation has its own security and recovery test suite.
