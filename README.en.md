# OLS WPanel

<img src="web/logo.png" alt="OLS WPanel" width="88">

A lightweight VPS and WordPress management panel for websites, databases, TLS certificates, caching, backups and server maintenance. Built around OpenLiteSpeed, LSPHP, MariaDB and Redis.

[中文](README.md) · [Operations guide](docs/operations-and-recovery.md) · [Releases](https://github.com/zangwp/OLS-WPanel/releases) · [Issues](https://github.com/zangwp/OLS-WPanel/issues)

## Installation

Supports fresh **Debian 13 and Ubuntu 24.04 LTS / Ubuntu 26.04 LTS** servers on **amd64 / arm64**. Minimum: one CPU core and 1 GiB RAM. Run as root:

```bash
curl -fsSL https://ols.zangyubin.top/install | bash
```

The short entry pins a published release and verifies Ed25519 signatures and SHA-256 hashes.

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
| VPS maintenance | Web resource, host and service status; DNS, Swap and system settings through the SSH `o` menu; open ports managed in the Security center |
| Account security | Optional TOTP two-factor authentication, single-use recovery codes, active sessions, persistent sign-in audit and new-environment notifications |
| Protection and alerts | File protection, Fail2ban, nftables, email / Webhook notifications and log analysis |

Fresh installations default to **LSPHP 8.5 and MariaDB 11.8**. LSPHP 8.4 / 8.3 can be added per site. Existing databases retain their installed series; routine updates do not automatically upgrade across database series.

The interface combines a light workspace with dark blue navigation, English / Chinese layouts and mobile controls. The dashboard groups resource metrics, and wide website tables scroll horizontally. Account protection is under **Security settings → Account sign-in**. Two-factor authentication requires explicit enrollment; before enabling it, separately back up `account-mfa.key` as described in the [account security guide](docs/account-security.md). Ordinary panel database downloads do not contain that key.

## SSH commands

Lowercase `o` and uppercase `O` are equivalent. Panel information shows the version, port and access path.

```text
o                 open the management menu
o dns             view, test and configure preset or custom DNS addresses
o swap            manage Swap capacity and swappiness
o ports           diagnose local listeners, processes and inbound rules
o services        inspect core services and recent logs
o bbr             inspect active algorithms and persistent configuration
o disk            inspect disk space and inode usage
o apt-check       read-only APT / dpkg health checks
o history         show the latest 200 terminal maintenance records
o ssh             change SSH ports with dual-port transition and timed rollback
o status          diagnose panel status
o log [N]         show the latest N panel log entries
o restart         restart the panel
o password        reset administrator credentials
o unban           clear panel-managed IP bans
o update          update / repair the panel
o uninstall       remove the panel, preserving websites, databases and shared software
```

Swap is under `o → 5. System settings → 3. Swap management`. Only the OLS WPanel marked `/swapfile` is managed; existing partitions, zram and external files are preserved. Resizing checks the full temporary-file disk requirement and verifies runtime state, restoring prior files and settings on failure. Removing the managed file retains system swappiness.

DNS is under `o → 4. Network settings → 1. DNS settings and tests`. Active `systemd-resolved` configurations and ordinary `/etc/resolv.conf` files are supported. Taking over an ordinary file requires confirmation and saves its contents, permissions and immutable state; search/options are preserved and the original configuration can be restored. Every custom IP address must pass checks; ordinary files support up to 3 and resolved up to 4. DHCP, cloud-init, NetworkManager, resolvconf and unrecognized symlinks remain read-only with a specific reason.

The time menu accepts installed IANA time zones; missing locale tools can be installed after confirmation. SSH port changes retain the old port until `o ssh-confirm` is executed from a new SSH connection on the new port. An independent watchdog rolls back unconfirmed changes. `o check-update` distinguishes the latest GitHub release from the short entry's actual target, and `o update` rejects downgrades. The terminal menu currently uses Chinese labels.

Uninstall displays its scope and requires `Y` or `y`; Enter cancels. It exits the active menu and removes the `o` / `O` commands. Updates use the signed published installation entry. Fresh installation and reinstallation are blocked when retained site data or configuration is detected; use update / repair for an existing OLS WPanel installation.

## Documentation

- [Installation and signature verification](docs/verified-install.md)
- [Operations and recovery](docs/operations-and-recovery.md)
- [Upgrade compatibility](docs/upgrade-compatibility.md)
- [Account security, recovery codes and key backups](docs/account-security.md)
- [Optimizer migration](docs/optimizer-migration.md): existing sites can explicitly migrate and remove the legacy plugin.
- [Installer security](docs/security/ols-wpanel-install-security.md) · [Runtime security](docs/security/ols-wpanel-runtime-security.md)
- [Repository layout](docs/repository-layout.md)

---

[GPL-3.0-only](LICENSE) · [Project notice](third_party/NOTICE.md) · [Third-party licenses](third_party/THIRD_PARTY_NOTICES.md) · [zangwp](https://github.com/zangwp)
