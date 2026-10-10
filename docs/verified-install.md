# OLS WPanel verified installation

## Quick installation

On a clean Debian 13, Ubuntu 24.04 LTS, or Ubuntu 26.04 LTS server (amd64 or arm64), run as `root`:

```bash
curl -fsSL https://ols.zangyubin.top/install | bash
```

The Cloudflare entry serves a fixed, deployed stable Release. It verifies the signed bootstrap manifest before returning the script. The bootstrap installs missing download, CA, and OpenSSL prerequisites, downloads the fixed-version installer, verifies its Ed25519 signature and SHA-256 digest, and only then starts it.

GitHub publication and deployment of this short entry are separate steps. If the entry has not yet been updated to the desired release, use the explicit signed-version procedure below. The example targets `v1.21.5`; its assets must exist on GitHub before it can be used.

## First login and server maintenance

Fresh installation prints the login URL separately, followed by two clearly labeled credential groups. Complete **browser authentication** with the first username/password, then **panel sign-in** with the second. Each value occupies its own line for copying from narrow SSH terminals. Save these credentials securely; update/repair keeps the existing identity and does not print passwords again. Plain output and `NO_COLOR` omit ANSI formatting.

The web panel's **Server information** page is read-only: it separates IPv4 and IPv6 interface addresses and displays host configuration, DNS, Swap, and service status. Use the **Dashboard** for resource usage and trends. For DNS, Swap, cleanup, or system settings, connect over SSH and run `o` to open the terminal maintenance menu. Interface addresses do not establish public reachability.

Use `o swap`, or `o → 5. 系统设置 → 3. Swap 管理`, to apply the recommendation, set a custom managed file size, change only swappiness, or remove the marked managed file. Changes require root and confirmation. The existing 512–8192 MiB size limits, 256 MiB increments, disk-space checks and memory checks apply; partitions, zram and unmarked files are preserved. Removing the managed file requires typing `REMOVE SWAP`.

Use `o dns`, or `o → 4. 网络设置 → 1. DNS 设置与检测`, for DNS. Active `systemd-resolved` with its managed resolver symlink and ordinary regular `/etc/resolv.conf` files are supported. The first change to an ordinary file requires explicit terminal confirmation and saves a private original snapshot under `/var/lib/ols-wpanel/dns/original.json`, including permissions, ownership and the immutable flag. Changes replace nameserver lines, preserve other settings, and restore the original immutable flag. The restore action restores the pre-takeover file rather than inventing an automatic configuration. Externally generated DHCP/cloud-init files, NetworkManager, resolvconf and unknown symlinks remain read-only and show their actual manager/reason.

Preset DNS writes only addresses that pass individual DNS queries. Ordinary resolv.conf presets retain at most the first 3 successful addresses because the [glibc resolver supports 3 nameservers](https://man7.org/linux/man-pages/man5/resolv.conf.5.html). Custom DNS accepts comma-separated IP addresses, up to 3 for ordinary files or 4 for systemd-resolved, and refuses the entire change if any specified address fails. Transactions use a protected cross-process lock and verify the resulting resolver state; rollback errors are reported separately.

Swap resizing reserves enough space for the full temporary replacement while retaining the old file. Failed activation, swappiness or verification restores the old file, fstab and settings where possible; a rollback failure retains recovery files and reports their paths. Commands have independent time limits, including recovery commands. Swap activity is read back after activation/deactivation errors; a file is not deleted unless it is confirmed inactive. Missing or zero available-memory readings cannot authorize disabling active Swap. Removing the managed file preserves the current system swappiness because other Swap sources may remain. If the existing panel database is unavailable, host state remains readable and the WordPress workload count is explicitly unknown.

Swap maintenance should run without simultaneous edits from other administrator scripts; the lock coordinates OLS WPanel operations only.

Additional terminal commands are `o ports`, `o services`, `o bbr`, `o disk`, `o apt-check`, `o dependencies`, `o hostname` and `o history`. Port inspection reports local listeners and host firewall policy, not cloud-security-group or public reachability. Disk/inode and APT health checks are read-only; they do not kill package processes or remove lock files. Terminal changes are recorded independently of SQLite in a protected history under `/var/lib/ols-wpanel/vps-cli`, bounded to 200 entries. SSH confirmation tokens and credentials are excluded from that history.

`o ssh` reuses the protected dual-port SSH transaction: first allow the new port in any cloud firewall, retain the current window, connect through the new port in another SSH window, then execute the returned `o ssh-confirm <token>` command there. The old port is removed only after connection and configuration checks. An independent systemd watchdog restores unconfirmed changes after the deadline. Unsupported SSH/socket/firewall configurations remain blocked.

`o check-update` shows three distinct versions: installed, latest GitHub release, and the signed short entry's target from its `X-OLS-WPanel-Release` header. The short entry can lag GitHub. `o update` prints its downloaded signed target and refuses an older version; it retains the existing signature verification chain.

## Verify before executing any remote script

Use this longer procedure if your policy requires downloading first and executing only after local verification:

```bash
set -euo pipefail
umask 077
workdir="$(mktemp -d /tmp/ols-wpanel-install.XXXXXXXXXX)"
trap 'rm -rf -- "$workdir"' EXIT
cd "$workdir"

version='v1.21.5'
base="https://github.com/zangwp/OLS-WPanel/releases/download/${version}"
wget --no-config --https-only --no-hsts \
  "$base/install.sh" \
  "$base/install.sh.sha256" \
  "$base/install.sh.sha256.sig"

cat > release-public-key.pem <<'KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5rZthMZ8gkeCHSqxa22OlYSpYtTIRY0fBrUtnLvWW9Y=
-----END PUBLIC KEY-----
KEY

openssl pkeyutl -verify -pubin -inkey release-public-key.pem -rawin \
  -in install.sh.sha256 -sigfile install.sh.sha256.sig
sha256sum --check --strict install.sh.sha256
bash install.sh
```

The key above is the OLS WPanel release-verification key pinned in the repository and release workflow. Compare it with the key shown in the repository and Release notes before use.

For an existing OLS WPanel installation, choose update / repair when prompted and read the [upgrade compatibility notes](upgrade-compatibility.md), including the separate MFA-key backup and rollback boundary. A fresh installation or reinstallation is not a recovery method for retained websites.

## Minimal images

If `curl`, trusted CA certificates, or OpenSSL are absent:

```bash
apt-get update && apt-get install -y --no-install-recommends curl wget ca-certificates openssl && (set -o pipefail; curl -fsSL --proto '=https' --proto-redir '=https' https://ols.zangyubin.top/install | bash)
```

## Supported targets

- Debian 13 (Trixie), amd64 or arm64
- Ubuntu 24.04 LTS (Noble), amd64 or arm64
- Ubuntu 26.04 LTS (Resolute), amd64 or arm64
- `root` access and a clean server are required
- ARM64 currently requires a 4 KiB or 8 KiB kernel page size because the official OpenLiteSpeed ARM64 build is not compatible with 16 KiB page-size kernels

Do not replace the fixed release URL with a mutable branch URL or `latest` when reproducing a verified installation.
