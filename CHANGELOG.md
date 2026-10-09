# Changelog

## v1.20.0 — 2026-10-09

- Adds a dedicated Website security workspace with 14 independently reported checks. Saved settings remain distinct from verified enforcement; unavailable files, services or evidence never imply that protection is active. Harmless loopback HEAD checks verify sensitive-file, upload-PHP and disabled XML-RPC rules without generating login failures or SQL attack requests.
- Connects XML-RPC settings and narrow URL/query SQL-injection protection to native OpenLiteSpeed rules before redirects and WordPress rewrites. Preserves ACME challenges and normal core searches, retains minimal security logging when ordinary access logging is disabled, and uses server-generated denial markers for SQLi Fail2ban matching.
- Records real WordPress authentication failures through a bounded native hook and dedicated log, without recording usernames or passwords. Installs the hook for new, reinstalled and upgraded sites; preserves it through domain migration and rollback, and verifies that the running login jail monitors the exact site log before reporting confirmed protection.
- Separates access, login and legacy security-log ingestion cursors, committing events and positions atomically. Handles rotation, truncation, partial records and retries; rejects unsafe log files and parent directories, preserves the original connection peer, and excludes only trusted local verification requests from security events.
- Reads LiteSpeed Cache page-cache and Redis object-cache settings from the active WordPress configuration instead of stale panel flags. Distinguishes unsupported, unconfigured and failed checks, and preserves legitimate WP_CACHE changes while migrating old panel overrides.
- Simplifies website tables into grouped status columns and Details/Files/More actions. Adds keyboard-accessible overflow menus and mobile positioning, clearer security controls, consistent bilingual labels, and deferred page scripts without an artificial navigation delay.
- Repairs panel HTTP-01 challenge routing through a public OpenLiteSpeed document root without exposing private configuration directories. Improves DNS/reachability error messages, certificate controls and settings layout, and shares the actual panel listening port with access-policy and terminal inspection.

Upgrade notes: back up the panel database, configuration and separate MFA encryption key before updating. Startup installs the WordPress login-audit baseline and rebuilds managed virtual hosts. Confirm results in Website security after the update; configured rules without reliable live evidence remain unverified. SQLi protection covers narrow URL/query patterns, not POST/JSON request bodies or a complete WAF. The matching signed GitHub Release must be verified before deploying the short installation entry.

## v1.19.0 — 2026-10-08

- Adds a locally generated QR code to TOTP enrollment while retaining manual secret entry. Restores a centered login form with a dark background and translucent card, and removes quotation text from login success messages.
- Makes the web Server information page read-only, separates IPv4 and IPv6 addresses, and removes its host-maintenance forms and write APIs. DNS, Swap and system maintenance are available through the SSH `o` / `O` menu.
- Adds verified custom DNS and ordinary resolv.conf management with explicit takeover, a private original snapshot, preserved permissions and immutable state, and restoration. Externally managed resolvers remain read-only; failed probes or transaction verification prevent unsafe writes.
- Strengthens Swap creation, resize and removal with full temporary-space checks, independent command deadlines, activation readback and rollback of the original file and settings. Preserves partitions, zram, unmarked files and system swappiness on removal, and shows unknown workload or available-memory readings explicitly.
- Adds terminal port/firewall inspection, service logs, BBR status, disk/inode and APT health checks, dependency checks, hostname settings and independent maintenance history. SSH port changes reuse new-session confirmation and the existing automatic rollback watchdog.
- Corrects maintenance failure exit codes, diagnostic results, update-started messages and login URLs. Update checks distinguish the installed version, latest GitHub release and signed short-entry target; downloaded lifecycle scripts show their actual version and refuse downgrades.
- Preserves active time-sync providers, detects conflicting providers, supports installed IANA timezones and explicit locale-tool installation, and verifies applied settings. Improves first-install credential layout and verifies BBR settings before reporting success.

Upgrade notes: host-maintenance writes are now terminal-only. Use `o dns` and `o swap` over SSH; unsupported externally managed configurations report their owner and remain protected. Existing account-security and MFA backup requirements still apply. The short installation entry is deployed only after the matching signed GitHub Release is available.

## v1.18.0 — 2026-10-08

- Adds an account security workspace with opt-in TOTP two-factor authentication, encrypted enrollment secrets, single-use recovery codes, password rechecks for sensitive account changes, replay protection and bounded verification attempts. Existing accounts retain password login until enrollment is completed.
- Adds active-session metadata and revocation, independent display identifiers, copied session state and renewed authorization checks for queued sensitive requests. MFA changes revoke other sessions; panel credential changes revoke all sessions. Invalid-session HTML redirects now abort protected handlers.
- Persists account security events for up to 90 days and 10,000 records. New sign-in environments, recovery-code use, MFA disablement and credential changes can notify configured SMTP / Webhook channels, with deduplication, rate limits, a bounded queue and network deadlines. Initial sign-in also counts as a new environment; IP/browser metadata is not a verified device identity.
- Rebuilds the interface around a light workspace and dark blue navigation, a grouped dashboard metric strip, theme-aware charts, responsive site tables, clearer login and account-security flows, and accessible confirmation dialogs. Preserves existing operations and both interface languages.
- Prevents stale requests and incomplete configuration reads from replacing newer page state or enabling unsafe saves. Remote backup, notification and database backup policy forms stay read-only after a failed load; backend configuration reads reject database errors instead of returning partial defaults. Rule changes save serially using the latest snapshot, and cron submission guards prevent duplicate requests. Keeps valid sessions active after failed MFA step-up checks, preserves unsaved input and distinguishes a submitted maintenance task from a completed one.
- Creates and verifies a private database snapshot before importing a site backup. Failed imports attempt rollback, retain the safety copy if rollback fails, release transferred site locks and clean up owned upload files. Site deletion now retains its deleting record and reports incomplete external cleanup for a later retry.
- Preserves existing destination files when a cross-site copy fails. Panel SQLite recovery stops subsequent restore actions if stopping the service or cleaning up inactive WAL/SHM sidecars fails, preventing recovery from continuing with unsafe database state.
- Blocks fresh installation or reinstallation over retained websites, applies the version guard to every repair/update entry, preserves repositories and signing keys for retained runtime packages, and reuses protected MariaDB client credentials during complete-uninstall checks and cleanup.
- Documents WAL-safe manual database recovery and the separate MFA encryption-key backup. Private installer repair snapshots preserve `account-mfa.key`; ordinary downloadable panel database backups continue to exclude it. SMTP now reports rejection of the final message data as a delivery failure, and Webhook connections retain checked dual-stack fallback.

Upgrade notes: back up the panel database and configuration before upgrading. After enabling MFA, preserve the matching `account-mfa.key` separately and do not roll back to a pre-v1.18.0 binary, which does not enforce MFA. See [upgrade compatibility](docs/upgrade-compatibility.md) and [account security](docs/account-security.md). Publishing the GitHub Release does not by itself deploy the short installation endpoint.

## v1.17.2 — 2026-10-05

- Uses Y/y confirmation after displaying the ordinary or complete uninstall scope; Enter cancels. Keeps inventory ownership checks and the separate backup-deletion confirmation.
- Exits the active terminal menu when its own o/O command file has been removed, preserves uninstall failure exit codes, and explains the expected absence of commands after reconnecting.
- Reports uninstall failure stages and preserves APT/dpkg diagnostics. A failed reload of unrelated sysctl settings no longer interrupts subsequent cleanup; package removal failures still stop the operation.
- Refuses ordinary-uninstall file deletion while the panel service is still active, and documents read-only checks for remaining services, files and packages.
- Ignores generated release assets so both architecture builds retain clean source revision metadata.

## v1.17.1 — 2026-10-03

- Shares APT update inventory parsing between the update page, alerts and completion checks, with a fixed command locale. Reuses tool version detection, rejects malformed address-priority ownership blocks, and avoids duplicate PHP runtime refreshes.

- Organizes the command entry under cmd/ols-wpanel/, backend packages under internal/, templates and embedded assets under web/, and development utilities under deploy/tools/. Updates import paths, resource embedding, repository checks and release builds while preserving installation entry points, published asset names and server paths.
- Runs frontend behavior regression checks in both CI architectures and before release signing, without downloading frontend dependencies or regenerating reviewed browser assets.

- Makes terminal homepage labels consistent, distinguishes service-read errors from stopped services, wraps long login addresses, and reports remaining system packages instead of an unqualified success in terminal update records.
- Adapts sidebar spacing to viewport height, keeps language controls on one line, and preserves independent navigation scrolling on shorter screens without requiring browser zoom changes.
- Clarifies the firewall draft, preview, temporary application and verified-save steps; validates custom port additions and protects unsaved drafts from accidental refresh. Keeps WordPress task controls in site settings and removes duplicate panel tasks from the read-only system list.
- Shows IPv4/IPv6 configuration ownership and existing address-selection rules before applying changes; external rules remain protected and unavailable actions are disabled.
- Removes persistent suggested-value labels and loads configuration suggestions only on request without replacing edited values. Moves optional development tools into the runtime page and distinguishes missing tools from failed or incomplete detection.
- Allows system package upgrades to install required new dependencies, including new kernel packages, while refusing package removals. Rechecks pending updates after completion and keeps an explicit warning with package names instead of reporting an unqualified success when updates remain.

## v1.17.0 — 2026-10-03

- Adds staged SSH port migration for standard systemd SSH services, with inherited firewall sources, Fail2ban updates, verification from the new SSH session, and a five-minute rollback timer. Unsupported socket activation and custom configurations remain read-only.
- Consolidates frontend sources and templates under static/, source-contract tests under tests/repository/, and license notices under third_party/. Keeps README evergreen and links release details through Releases.

- Adds a previewable port access policy with IPv4/IPv6 source scopes, an independent nftables restriction, manual confirmation, timed rollback, and boot persistence. Default drafts expose HTTP, HTTPS, SSH and the panel; HTTP/3 and WebAdmin stay closed and database/cache access stays local. Existing policies are preserved.

- Simplifies the dashboard, groups WordPress fleet maintenance under Websites, and moves ports and firewall settings into Security settings while preserving existing links.
- Displays resource-based configuration suggestions separately from editable current values; refreshing suggestions never replaces unsaved input. Replaces isolated help icons with inline descriptions and aligns firewall controls.
- Adds per-site WordPress scheduled-task controls and restores the panel-managed WP-Cron override when all tasks are disabled; existing jobs and records are retained.
- Adds independent certificate renewal preferences and attempt records for auto-issued certificates, preserves existing defaults, and leaves uploaded certificates under manual management.

- Creates ACME challenge directories before configuring the default OpenLiteSpeed host and repairs missing directories on existing installations, including when the context already exists; rejects unsafe paths without relaxing configuration-directory permissions.
- Removes workload optimization claims from queue presets, preserves live values by default, and previews each current-to-target change before confirmation.
- Separates update preflight failures from package installation, displays complete errors across the page width, and improves section spacing and home-screen balance.

## v1.16.1 — 2026-10-03

- Groups terminal status output with aligned, width-aware fields; separates current DNS from candidate presets and historical update errors from live service status.
- Preserves DNS resolver order and reports the actual read source, including non-resolved environments.
- Separates advanced queue settings from resource status and disables restore without a valid baseline.
- Adds concise queue profiles identified from live values, with parameter details and a separate pre-change confirmation; keeps existing values unless explicitly changed.
- Accepts case-insensitive y/yes for ordinary confirmations while retaining exact destructive confirmations.

## v1.16.0 — 2026-10-02

- Replaces repeated-install prompts with version-aware maintenance navigation, nests destructive actions, requires confirmation before reinstall and prevents Enter from triggering residual-install repair.

- Makes performance status read-only by default, including sampled CPU usage; moves explicitly confirmed queue changes into advanced settings and removes misleading optimization profile labels.

- Rebuilds SSH navigation with eight compact home entries, dedicated status pages, consistent back actions, terminal redraws and pauses after results; retains existing shortcuts.
- Shows dual-stack DNS presets, resolver ownership and probe results; disables unsupported DNS mutations and permits verified IPv6-only resolvers.
- Adds network connectivity checks, time synchronization and timezone pages; displays package update tasks and measured cleanup results.
- Unifies queue ownership: fresh installs retain system defaults; explicit presets migrate legacy installer queue entries, verify live values and persist restored values across reboot.
- Removes duplicate diagnostics/detail menu entries, clarifies cached package-index refresh, and separates current SSH locale from the system default.

## v1.15.1 — 2026-10-02

- Simplifies installation completion and the o/O home screen into a compact Chinese summary and vertically grouped VPS/panel menus; moves details and complete uninstall into explicit help/advanced entries.
- Labels interface addresses accurately and brackets IPv6 addresses in panel URLs.

## v1.15.0 — 2026-10-02

- Adds a compact VPS maintenance menu to o/O while retaining panel information and existing shortcuts; keeps domain login as the main entry and IP as fallback.
- Adds VPS information, system-update status, bounded cache/journal cleanup, managed DNS, reversible IP preference and connection queue presets, and server locale selection.
- Refreshes the VPS layout with overview/maintenance tabs, resource meters, compact help and advanced lifecycle commands; adds a dashboard introduction and explicit update checks.
- Adds explicit complete-uninstall dispatch, website/database inventory checks, website database deletion, and separate backup retention choice. Redis, Fail2ban and unrelated dependencies are preserved.

- Keeps manual update-check failures visible instead of reporting that the panel is current.
- Saves PHP performance changes in one validated batch, with one reload and restoration on failure.
- Stops generating forced LiteSpeed object-cache constants; adds an explicit migration preserving existing effective values in LiteSpeed Cache settings.
- Adds configurable panel domains, staged trusted-certificate installation, hot certificate replacement and automatic renewal. HTTP-01 requires a reachable dedicated domain on port 80.
- Adds compact help disclosures, visible stale-data warnings and timer cleanup; moves WordPress memory editing to software performance configuration.

- Restores missing native OpenLiteSpeed service registration on panel startup and after system package updates, migrates generated Debian SysV service ownership, preserves custom/stopped native services, and rolls back failed recovery.
- Validates OpenLiteSpeed configuration before PHP baseline restarts and reports restart errors instead of silently ignoring them.

## v1.14.0 — 2026-10-02

- Retires the standalone OLS WPanel Optimizer: stops automatic upgrades and installation, moves anomaly sampling into the isolated panel CLI runner, and adds an explicit migration/deactivation/archive action that preserves LiteSpeed Cache and other plugins.
- Manages application-password and update-check policies through a small wp-config.php hook block with no panel API calls or plugin background jobs. Existing password-reset MU rules remain panel-managed; locked sites must unlock before migration and re-lock afterwards.

- Keeps the panel in dark mode and removes the appearance switch and light styles.
- Enables persistent nftables rules on fresh installations without mistaking managed Fail2ban ban chains for an existing firewall policy; boot activation saves the current rules without reloading them.
- Installs a missing time-sync service, preserves existing providers, and distinguishes enabled NTP from confirmed synchronization.
- Reads the actual WordPress table prefix from wp-config.php for domain operations, prefers the MariaDB client, and reports database errors inline.
- Adds a WordPress admin link with support for installation subdirectories and explains the panel-managed replacement for the companion plugin.

## v1.13.1 — 2026-10-01

- Fixes fresh Debian installs where OpenLiteSpeed's package registers only a SysV `lsws` service: installs the package-provided native `lshttpd` unit and a compatible `lsws` alias before applying process supervision. Preserves existing native units and repair mode, and rejects conflicting custom services.

## v1.13.0 — 2026-10-01

- Turns Website Details navigation into real Overview, Cache, Security, and Logs workspaces so only the selected section is rendered and long logs no longer stretch unrelated settings.
- Adds stable hash deep links, including direct navigation to Security & Maintenance from other panel pages, while preserving legacy Website Details anchors.
- Replaces the misleading alias policy shown on sites without aliases with an explicit “not configured” state and adds a one-click shortcut for adding `www` with a path-preserving 301 redirect.
- Corrects file-protection status semantics: protected WordPress sites are green, unprotected sites are warnings, and generic PHP sites are marked not applicable.
- Adds File Manager protection guidance and “Manage Protection” actions both in the directory list and inside a selected WordPress root, opening the exact protection workspace without silently changing permissions.
- Refines protection action hierarchy, keeps scope preview mandatory before enabling, and expands bilingual regression coverage for the new navigation and safety states.

## v1.12.0 — 2026-10-01

- Adds an explicit one-click `www` canonical-domain workflow when creating a site and when editing an existing site, defaulting to a path- and query-preserving 301 redirect to the primary domain.
- Keeps additional-domain handling visible even before aliases are entered, distinguishes examples from saved values, previews redirect behavior, and automatically selects certificate reissue when a panel-managed certificate must cover the new alias.
- Reorganizes Website Details into overview, runtime, cache, protection, and log sections with compact status badges, balanced cards, collapsible technical information, and on-demand log loading.
- Clarifies that the official WordPress LiteSpeed Cache plugin owns WordPress cache policy, while OLS WPanel provides installation, status, recommended setup, purge actions, advanced OpenLiteSpeed synchronization, and the separate Redis object-cache layer.
- Expands bilingual UI and regression coverage for canonical-domain controls, page navigation, cache ownership guidance, and the compact log workspace.

## v1.11.0 — 2026-10-01

- Reworks Ports & Firewall around explicit access scope, permanent or temporary rules, common service presets, compact empty states, creation and expiry times, and nftables packet-hit counters.
- Separates local-only and network-bound listeners, explains host-firewall versus cloud-security-group reachability, and flags network-bound MariaDB or Redis listeners without claiming every listening socket is publicly reachable.
- Adds a guarded protected mode that preflights SSH and panel listeners, restricts both management ports to the current direct administrator IP, switches the input policy from `accept` to `drop`, and automatically rolls back unless the browser confirms connectivity within 90 seconds.
- Makes fresh installs create and validate a persistent nftables `drop` baseline only on an otherwise unmanaged host, preserving repair mode, active UFW, and existing nftables policy ownership.
- Keeps SSH, HTTP, HTTPS, HTTP/3, and OLS WPanel reachable in the fresh baseline while leaving OpenLiteSpeed WebAdmin, MariaDB, and Redis closed by default.
- Sends dashboard and VPS update badges directly to Panel Settings → Panel & System Updates and localizes the new firewall protection operation records.
- Expands installer, router, translation, validation, and secure-default regression coverage for the new behavior.

## v1.10.0 — 2026-09-30

- Reorganizes Security Settings into runtime status, protection, trust-boundary, and privacy workspaces so effective service state is visible without one long page.
- Splits website and SSH allowlists. Official crawler ranges, CDN origins, and website exceptions no longer bypass the SSH Fail2ban jail; existing custom entries remain web-only after upgrade.
- Adds live Fail2ban, nftables, whitelist-timer, active-ban, and CDN trust-boundary status through a read-only diagnostics endpoint.
- Removes the unsafe CDN “compatible mode” guidance. Custom CDN real-IP groups now require trusted vendor origin IP/CIDR ranges before they can be enabled, while Cloudflare continues using system-maintained official ranges.
- Propagates whitelist timer deployment failures instead of silently reporting a saved configuration, adds database migration safeguards, and expands security regression coverage.
- Rebuilds the bundled stylesheet so the Security and VPS workspaces use their intended responsive multi-column layouts instead of falling back to a single column.

## v1.9.1 — 2026-09-30

- Stops a completed system-update result from reappearing as a large success banner every time Panel Settings opens.
- Shows persisted successful updates as a compact timestamped history line, while a newly completed update remains visible for 10 seconds before collapsing automatically.
- Adds an explicit dismiss control for terminal update results and keeps failed updates prominent until the administrator dismisses them.
- Adds JavaScript behavior coverage for restored success, fresh completion, automatic collapse, and persistent failure states.

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
