# OLS WPanel

<img src="static/logo.png" alt="OLS WPanel" width="88">

A lightweight VPS and WordPress management panel for websites, databases, TLS certificates, caching, backups and server maintenance. Built around OpenLiteSpeed, LSPHP, MariaDB and Redis.

[中文](README.md) · [Operations guide](docs/operations-and-recovery.md) · [Changelog](CHANGELOG.md) · [Issues](https://github.com/zangwp/OLS-WPanel/issues)

## Installation

Supports fresh **Debian 13 and Ubuntu 24.04 LTS / Ubuntu 26.04 LTS** servers on **amd64 / arm64**. Minimum: one CPU core and 1 GiB RAM. Run as root:

```bash
curl -fsSL https://ols.zangyubin.top/install | bash
```

The current stable release is `v1.16.0`. The short entry pins a published release and verifies Ed25519 signatures and SHA-256 hashes.

On minimal images without curl, install the prerequisites first:

```bash
apt-get update && apt-get install -y --no-install-recommends curl wget ca-certificates openssl
```

See the [installation guide](docs/verified-install.md) for manual verification, restricted networks and offline installation. Other OS versions, existing production environments and ARM64 16 KiB pages are outside the automatic installation support scope.

## Features

| Area | Capabilities |
|---|---|
| Websites and WordPress | WordPress / PHP provisioning, domains, PHP versions, files, databases and WordPress updates |
| Certificates and caching | Website certificate issuance and renewal; official LiteSpeed Cache for page and Redis object caching |
| Backups and recovery | Website, database and panel backups, with SFTP / S3 remote storage |
| VPS maintenance | Resource and service status, system updates, DNS, Swap, time synchronization and open ports |
| Security and alerts | Login protection, file protection, Fail2ban, nftables, email notifications and log analysis |

Fresh installations default to **LSPHP 8.5 and MariaDB 11.8**. LSPHP 8.4 / 8.3 can be added per site. Existing databases retain their installed series; routine updates do not automatically upgrade across database series.

## SSH commands

Lowercase `o` and uppercase `O` are equivalent. Panel information shows the version, port and access path.

```text
o                 show panel information
o status          diagnose panel status
o log [N]         show the latest N panel log entries
o restart         restart the panel
o password        reset administrator credentials
o unban           clear panel-managed IP bans
o update          update / repair the panel
o uninstall       remove the panel, preserving websites, databases and shared software
```

Ordinary uninstall requires the exact `UNINSTALL` confirmation. Updates use the signed published installation entry.

## v1.16.0 changes

- Rebuilds SSH menus around current status, consistent navigation and explicit confirmations.
- Shows dual-stack DNS ownership and probe results; adds connectivity and time synchronization tools.
- Makes performance status read-only by default; advanced queue changes are verified and reversible.
- Adds version-aware installation maintenance with nested reinstall and uninstall actions.

## v1.15.1 changes

- Compact grouped SSH menus retain existing commands.
- Shorter installation summaries, explicit help/details and advanced uninstall access.
- Accurate interface-address labels and valid IPv6 login URLs.

## v1.15.0 changes

New in this release:

- A simple VPS menu and Overview / Maintenance page layout.
- Custom panel domains, certificate issuance and renewal, with an IP fallback entry.
- Batched PHP configuration saves and removal of forced LiteSpeed Cache overrides.
- Dashboard update checks and a complete-uninstall entry with backup retention choices.

See the [development and verification notes](docs/local-next-version.md) for new commands and verification limits. Complete uninstall deletes websites, their databases and the panel, and requires separate confirmation. These commands require v1.15.0 or newer.

## Documentation

- [Installation and signature verification](docs/verified-install.md)
- [Operations and recovery](docs/operations-and-recovery.md)
- [Upgrade compatibility](docs/upgrade-compatibility.md)
- [Optimizer migration](docs/optimizer-migration.md): v1.14.0 stopped automatic deployment; existing sites can explicitly migrate and remove it.
- [Installer security](docs/security/ols-wpanel-install-security.md) · [Runtime security](docs/security/ols-wpanel-runtime-security.md)
- [Repository layout](docs/repository-layout.md)

## Development layout

Application code uses separate Go packages. Templates and runtime assets are under templates/ and static/; build sources are under assets/. Documentation lives in docs/ and independent Workers in deploy/. Legacy plugin sources remain for compatibility and migration validation.

```text
config/ collector/ database/ models/       configuration and data
handlers/ middleware/ router/ executor/   request handling and system operations
i18n/ templates/ static/ assets/           UI, translations and assets
docs/ deploy/                             documentation and deployment components
scripts/ tests/ third_party/               verification, tests and license material
```

## License

[GPL-3.0-only](LICENSE), maintained by [zangwp](https://github.com/zangwp). Third-party terms are listed in [NOTICE.md](NOTICE.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
