# Changelog

## v1.9.0 — 2026-09-30

- Reorganizes Panel Settings into focused General, Updates, WordPress Package, Panel Backups, and Operation Logs sections so the page no longer grows into one long workspace.
- Keeps large system-update package lists collapsed by default, moves the GitHub proxy into advanced download settings, and clarifies current-version and last-automatic-update states.
- Separates BasicAuth and Web-login saves; username or password changes now require the current password and commit atomically before active sessions are revoked.
- Adds searchable, status-filtered, paginated operation logs with localized operation names and visible result messages.
- Clarifies that the local WordPress package is only for future site creation and that panel database backups exclude website files, site databases, certificates, and system configuration.
- Adds regression coverage for account mutation safety, log filtering, query validation, and Linux handler compilation.

## v1.8.0 — 2026-09-30

- Adds two bounded DNS presets to VPS Management: Cloudflare for international routing and Alibaba Public DNS for mainland China, each with paired IPv4 and IPv6 resolvers.
- Detects the active resolver and IPv6 default route, tests presets before applying them, verifies resolution afterward, and automatically restores the previous panel-managed configuration if validation fails.
- Keeps DNS read-only when another network manager or an administrator-owned drop-in is detected, and provides an explicit return to system- or cloud-managed DNS.
- Makes `vm.swappiness` recommendations workload-aware: a healthy single WordPress site may use 10, multiple sites or memory pressure keep the kernel default of 60, and zram uses 100.
- Changes fresh-install and upgrade-created Swap defaults to swappiness 60; the panel only applies a different recommendation after an administrator confirms it.
- Detects active-but-disabled nftables persistence and offers a guarded boot-enable action that validates `/etc/nftables.conf` without reloading current firewall rules.
- Improves VPS Management layout, localized status explanations, action feedback, and regression coverage for the new DNS, Swap, and firewall behavior.

## v1.7.1 — 2026-09-30

- Fixes panel login failures caused by a missing or stale CSRF cookie after browser page restoration, cache reuse, or a panel upgrade.
- Refreshes the login CSRF token immediately before authentication and retries one rejected pre-handler request once without weakening CSRF validation.
- Prevents the login page and token endpoint from being cached while keeping both routes behind the panel's random path and BasicAuth layer.

## v1.7.0 — 2026-09-30

- Adds explicit additional-domain policies: new sites default to a canonical 301 redirect, while 302 and same-site serving remain available and existing sites retain their prior behavior.
- Generates host-specific OpenLiteSpeed redirects without reflecting an untrusted Host header, preserves request paths and query strings, and folds HTTP-to-HTTPS canonicalization into a single hop.
- Adds redirect preview and DNS checks to domain management, automatically reissues panel-managed certificates for the primary domain and all aliases, and clearly identifies manual-certificate follow-up work.
- Adds adaptive Swap recommendations to VPS Management: systems with up to 1GB RAM receive a 2GB recommendation, while larger VPSes default to a conservative 1GB emergency buffer.
- Detects active zram, swap partitions, and swap files separately; existing system-managed sources count toward the recommendation and are never modified or deleted by the panel.
- Adds safe controls for applying the recommendation, selecting a 512MB–8GB panel-managed `/swapfile`, and changing `vm.swappiness` without accepting arbitrary shell input.
- Checks free memory before shrinking or removal, preserves at least 8GB of disk headroom, caps projected disk usage at 85%, serializes changes, and requires the exact `REMOVE SWAP` confirmation phrase for deletion.
- Updates fresh installs and the existing best-effort migration to choose the recommended Swap size instead of always creating 2GB or skipping hosts with more than 8GB RAM.
- Prevents destructive uninstall from deleting a user-owned `/swapfile`; cleanup now requires the exact OLS WPanel marker and fstab entry.

## v1.6.0 — 2026-09-30

- Adds a focused VPS Management page with host identity, operating system, kernel, CPU, resource, DNS, NTP, BBR/qdisc, reboot-required, and core systemd service visibility.
- Groups system updates, managed ports, software health, backups, and log analysis into safe operational entry points without exposing arbitrary root shell execution in the browser.
- Adds `o update` for signed in-place update/repair and `o uninstall` for an ordinary panel uninstall that requires the exact `UNINSTALL` confirmation phrase.
- Keeps website files, logs, certificates, OpenLiteSpeed site configuration, MariaDB databases, and shared software during ordinary uninstall; destructive purge remains intentionally outside the web UI.
- Adds deep links from VPS Management to the managed firewall Ports tab and improves the responsive system-page layout.
- Allows a protected manual release run to create a missing SemVer tag only at the exact current `main` commit, while keeping signing and publication in the existing restricted jobs.

## v1.5.0 — 2026-09-30

- Reworks the website performance card around the real cache architecture: the official LiteSpeed Cache plugin manages WordPress integration, OpenLiteSpeed provides page cache, and Redis provides a separate object-cache layer.
- Adds one-click recommended cache configuration for existing WordPress sites, including verified plugin installation, activation, page cache, and isolated per-site Redis settings without requiring another Redis cache plugin.
- Shows the effective plugin, page-cache, and Redis configuration states and links directly to the LiteSpeed Cache settings in WordPress admin.
- Separates page-cache and Redis object-cache clearing so operators can invalidate the intended layer without flushing unrelated data.
- Preserves existing plugin installations, rejects non-regular plugin entry files, and rolls back WordPress configuration when the server-side cache update fails.

## v1.4.1 — 2026-09-29

- Fixes the Settings system-update list so large package sets stay inside a bounded scrolling region in the released UI instead of stretching the page.
- Adds All, Security, and Regular package filters with live counts, plus an explicit show/hide control for the package list.
- Keeps refresh/update actions and task results outside the scrolling region and lets the account and server-settings cards size independently.
- Adds a regression test that rejects the previously uncompiled `max-h-80` dependency and verifies the compact layout contract.

## v1.4.0 — 2026-09-29

- Adds a Ports & Firewall workspace with listener inventory, SSH/panel port discovery, host-policy visibility, and persistent or time-limited nftables allow rules.
- Restricts OpenLiteSpeed WebAdmin port 7080 to an explicit management IP/CIDR and only creates or removes rules owned by OLS WPanel; active UFW and firewalld installations remain read-only to avoid conflicting managers.
- Validates nftables changes before applying them, reconciles managed rules after restart, records changes in the operation log, and retains expired rules when kernel removal fails so access is never silently left unmanaged.
- Adds alert-channel and rule summaries, searchable alert history, more useful empty states for AI Diagnostics and Log Analysis, and a compact troubleshooting/help area with privacy reminders.
- Prepares a compact system-update package list; v1.4.1 completes the released scrolling and filtering behavior.

## v1.3.1 — 2026-09-29

- Reorganizes Software Management into focused Runtime, Performance, and Developer Tools sections to reduce page length and visual noise.
- Replaces repeated repository-status sentences with update notices shown only when a signed APT candidate is actually available.
- Distinguishes the panel's primary LSPHP runtime from installed compatibility runtimes and keeps per-site usage visible.
- Removes empty nftables and Fail2ban configuration cards, prevents undefined values from rendering, and lets configuration cards size independently.
- Improves service-status badges and adds confirmation before stopping or restarting managed services.

## v1.3.0 — 2026-09-29

- Adds fresh-install support for Ubuntu 26.04 LTS (Resolute) on amd64 and arm64 alongside Debian 13 and Ubuntu 24.04 LTS.
- Verifies the Resolute repositories for OpenLiteSpeed/LSPHP 8.3–8.5, MariaDB 11.8, and Redis before release instead of reusing packages from an older Ubuntu release.
- Links system-update package details to the Ubuntu 26.04 catalog and extends the signed bootstrap platform gate.
- Adds native-architecture CI and release checks for Ubuntu 26.04 platform detection and required runtime packages.

## v1.2.5 — 2026-09-29

- Fixes fresh installs stopping at OpenLiteSpeed configuration validation because the no-site fallback root was owned by a privileged UID.
- Assigns the fallback virtual host to the standard unprivileged `www-data` identity and verifies that its UID/GID satisfy OpenLiteSpeed's minimums before validation.
- Repairs the fallback-root identity during upgrades and whenever the managed OpenLiteSpeed registry is regenerated.
- Adds installer, runtime, migration, and Linux build regression coverage for the ownership guard.

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
