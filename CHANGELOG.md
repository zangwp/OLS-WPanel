# Changelog

## v1.2.4 — 2026-09-29

- Fixes OpenLiteSpeed startup timeouts on Ubuntu 24.04 by aligning the panel-owned systemd drop-in with the PID file actually maintained by `lswsctrl`.
- Replaces the deprecated `KillMode=none` behavior with bounded `KillMode=mixed` cleanup while preserving OpenLiteSpeed's graceful stop path.
- Defers the first required OpenLiteSpeed restart until after the fallback virtual host has been written and the complete configuration has passed validation.
- Migrates only recognized OLS WPanel drop-ins and preserves administrator-authored service policies.

## v1.2.3 — 2026-09-29

- Keeps OpenLiteSpeed runnable before the first website exists by installing a static, no-script fallback virtual host and mapping it to the managed HTTP/HTTPS listeners.
- Repairs existing zero-site installations during panel startup and standardizes service control on the canonical `lshttpd` unit.
- Adds pre-update OpenLiteSpeed configuration and service health checks so package updates stop before mutation when the runtime is already unhealthy.
- Replaces unbounded restart loops for managed infrastructure services with a rate-limited `on-failure` policy while preserving user-customized systemd drop-ins.
- Simplifies Software Management: fresh installs use MariaDB 11.8, existing databases receive same-series updates only, and Redis/nftables/Fail2ban follow authenticated APT candidates without hard-coded upstream-version clutter.
- Adds regression coverage for the fallback virtual host, service migration, package-update preflight, installer ordering, and amd64/arm64 release builds.

## v1.2.2 — 2026-09-29

- Fixes fresh Ubuntu/Debian installations aborting after MariaDB repository setup when `apt-cache policy` received SIGPIPE from an early-exiting `awk` under `pipefail`.
- Adds explicit unexpected-failure exit status and installer line diagnostics while keeping sensitive command arguments out of terminal output.

## v1.2.1 — 2026-09-29

- Improves light-mode contrast, constrains ultra-wide layouts, groups sidebar navigation, and keeps language/theme controls visible in a dedicated footer.
- Replaces dense Security, Firewall, and Software help dialogs with concise bilingual guidance and removes remaining user-visible hard-coded Chinese strings.
- Fixes the announcement feed URL so it targets the tracked `docs/announcement.md` document.
- Reduces the Chinese README to installation, support, feature, and documentation entry points; moves operational recovery details into `docs/operations-and-recovery.md`.
- Removes an unreferenced community QR image and renames stale internal identifiers while retaining only the installer compatibility path required to clean older service drop-ins.

## v1.2.0 — 2026-09-28

- Makes fresh installations use the latest release-verified defaults: LSPHP 8.5 and MariaDB 11.8.
- Keeps LSPHP 8.4 and 8.3 available as per-site compatibility runtimes instead of installing every PHP branch by default.
- Preserves the configured primary LSPHP branch on existing servers, including its CLI and managed PHP configuration path.
- Keeps existing MariaDB installations on their current series; normal package updates remain same-series patch and security updates.
- Updates the signed installer entry, documentation, and regression checks for the v1.2.0 release boundary.

## v1.1.0 — 2026-09-28

- Adds independently installable LSPHP 8.3, 8.4, and 8.5 runtimes with per-site selection for new and existing sites.
- Preserves the selected PHP runtime across SSL renewal, OpenLiteSpeed regeneration, WordPress inventory, administrator management, component updates, and site migration health checks.
- Adds fresh-install MariaDB series selection (10.11/11.4/11.8 on Ubuntu 24.04; 11.8 on Debian 13) using the official repository only after its signing-key fingerprint is verified; existing databases are never silently downgraded.
- Installs Redis 8.10.2 or newer from Redis' official signed APT repository on both supported operating systems and architectures.
- Shows APT candidate updates for OpenLiteSpeed, LSPHP, MariaDB, Redis, nftables, and Fail2ban while keeping service updates within authenticated package repositories.
- Shows the current upstream stable references for Redis 8.10.2, nftables 1.1.7, and Fail2ban 1.1.1 without unsafe source-level replacement of distribution firewall packages.
- Matches the official LiteSpeed packaging matrix where LSPHP 8.5 has no separate `lsphp85-opcache` package.
- Strengthens light-theme contrast for muted labels, table content, status values, and inline legacy colors.
- Adds schema, renderer, architecture, installer, and release-pinning regression coverage for the expanded runtime matrix.

## v1.0.2 — 2026-09-28

- Fixes WordPress inventory scans on OpenLiteSpeed hosts by trusting the configured LSPHP CLI directory instead of incorrectly requiring `/usr/bin`.
- Exposes a sanitized, actionable scan failure reason in the fleet overview and adds a per-site rescan action with bounded progress polling.
- Improves light-theme contrast for compiled table/label components, form placeholders, muted text, and version badges.
- Links service update information in Software Management to the existing signed and validated System Updates workflow.

## v1.0.1 — 2026-09-28

- Makes system-package updates wait for APT locks, retry repository downloads, wait for restarted services, and expose sanitized failure details and progress states in the panel.
- Corrects MariaDB and OpenLiteSpeed version parsing and shows available APT candidate updates without presenting unsafe cross-major upgrades as routine actions.
- Shows the effective Gzip, Brotli, HTTP/3/QUIC, and WebAdmin state managed by OLS WPanel.
- Completes light-theme coverage for tables, hover states, status cards, badges, and semantic alert panels.

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
