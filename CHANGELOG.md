# Changelog

## v1.0.0 — 2026-09-27

Initial OLS WPanel release.

- Uses OpenLiteSpeed with isolated per-site LSPHP 8.3 external applications instead of Nginx/PHP-FPM.
- Creates OpenLiteSpeed virtual hosts, HTTP/HTTPS listener mappings, rewrite support, certificates, log paths, LSAPI sockets, and rollback-safe configuration updates automatically for every site.
- Installs and activates the official LiteSpeed Cache plugin for new WordPress sites and preconfigures Redis object caching with a per-site key prefix.
- Supports Debian 13 and Ubuntu 24.04 LTS on amd64 and arm64; ARM64 hosts with unsupported 16 KiB page-size kernels fail closed before installation.
- Adds native-architecture CI checks for the panel, installer syntax, supported-platform detection, and availability of all required OpenLiteSpeed/LSPHP packages.
- Provides signed, architecture-qualified release assets and the verified `https://ols.zangyubin.top/install` entry point.
- Uses only `o` and `O` as panel management commands.
