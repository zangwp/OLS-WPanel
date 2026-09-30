# OLS WPanel

<p><img src="static/logo.png" alt="OLS WPanel" width="120"></p>

OLS WPanel is a WordPress-focused server panel built around OpenLiteSpeed, isolated per-site LSPHP 8.3/8.4/8.5 applications, LiteSpeed Cache, Redis, and MariaDB.

It supports clean Debian 13, Ubuntu 24.04 LTS, and Ubuntu 26.04 LTS servers on amd64 and arm64. The project is licensed under `GPL-3.0-only` and maintained at [zangwp/OLS-WPanel](https://github.com/zangwp/OLS-WPanel).

## Quick installation

Run as `root`:

```bash
curl -fsSL https://ols.zangyubin.top/install | bash
```

The short entry is pinned to a published release and verifies signed SHA-256 manifests before delegating to the installer. It installs missing bootstrap prerequisites automatically. For minimal images or verification before execution, see [the verified installation guide](docs/verified-install.md).

The current stable release is `v1.10.0`.

### Minimal images / download failures

If the short command cannot start because the image lacks basic download and TLS tools, install them once and retry:

```bash
apt-get update && apt-get install -y --no-install-recommends curl wget ca-certificates openssl && curl -fsSL https://ols.zangyubin.top/install | bash
```

## What it installs

- OpenLiteSpeed with generated HTTP/HTTPS listeners and one isolated virtual host per site
- LSPHP 8.5 by default, with optional 8.4 and 8.3 compatibility runtimes assignable per site
- MariaDB 11.8 on fresh installs; existing databases receive same-series patch and security updates only; Redis follows its official signed APT repository
- The official LiteSpeed Cache WordPress plugin, automatically activated for new WordPress sites
- Redis object-cache integration through LiteSpeed Cache with an independent key prefix per site; no second Redis cache plugin is required
- Fail2ban and nftables for host-level enforcement, listener inventory, and panel-owned allow rules
- The OLS WPanel Go service on its own HTTPS management port

Generic PHP sites use OpenLiteSpeed and LSPHP but do not receive WordPress plugins or the LiteSpeed WordPress cache module configuration.

## Supported systems

| Item | Supported |
|---|---|
| Operating systems | Debian 13 (Trixie), Ubuntu 24.04 LTS (Noble), Ubuntu 26.04 LTS (Resolute) |
| Architectures | amd64/x86_64, arm64/aarch64 |
| CPU | 1 core or more |
| Memory | 1 GiB or more |
| ARM64 page size | 4 KiB or 8 KiB; 16 KiB fails closed because the official OLS binary is incompatible |

## Site provisioning

Creating a WordPress site automatically prepares the system user, document root, logs, database, OpenLiteSpeed virtual host and listener mappings, LSPHP application, WordPress files, LiteSpeed Cache, Redis configuration, and optional TLS certificate. Additional domains default to a canonical 301 redirect to the primary domain, with 302 or same-site serving available when needed. Domain management previews the redirect, checks DNS, and can reissue panel-managed certificates for every configured name. Configuration is validated before `lshttpd` is restarted; failed updates restore the previous files and listener registry.

## Management commands

Both entry points are equivalent:

```text
o / O             show panel information
o restart         restart the panel
o password        reset the administrator password
o info            show version and access information
o status          show runtime status
o unban           clear managed IP bans
o update          update or repair through the signed release chain
o uninstall       ordinary uninstall that preserves sites, databases, and shared software
```

`o uninstall` requires the exact `UNINSTALL` confirmation phrase in the terminal. OS reinstall, disk partitioning, and destructive purge are intentionally not exposed as one-click web actions.

## Security and release model

- Release assets are architecture-qualified and accompanied by SHA-256 manifests and Ed25519 signatures.
- The installer pins and verifies the LiteSpeed APT signing keys before adding its HTTPS repository.
- Each generated OpenLiteSpeed configuration is validated before activation and updated atomically with rollback.
- The management service uses its own TLS listener and does not expose OpenLiteSpeed WebAdmin.
- Website and SSH allowlists are isolated; crawler and CDN trust never bypasses SSH protection, and custom CDN real-IP handling requires declared vendor origin ranges.
- Optional telemetry is disabled by default.

## Runtime updates and OpenLiteSpeed administration

System Update installs the latest verified stable and security candidates from configured signed APT repositories. OpenLiteSpeed and LSPHP follow the official LiteSpeed repository, MariaDB stays on its installed series, Redis follows Redis' official repository, and nftables and Fail2ban follow the target operating-system repository. LSPHP 8.3, 8.4, and 8.5 can coexist and are assigned per site. Database cross-series changes remain controlled migrations rather than routine unattended updates.

OLS WPanel owns the generated server and per-site OpenLiteSpeed configuration, so WebAdmin on port 7080 is disabled by default to avoid conflicting edits and an extra public administration endpoint. The installer enables Gzip, Brotli, and HTTP/3/QUIC, and WordPress sites receive LiteSpeed Cache and Redis configuration automatically. The Software page reports their effective status.

See the [verified installation guide](docs/verified-install.md), [operations and recovery guide](docs/operations-and-recovery.md), [repository layout](docs/repository-layout.md), [NOTICE.md](NOTICE.md), and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
