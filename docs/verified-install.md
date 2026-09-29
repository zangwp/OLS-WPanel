# OLS WPanel verified installation

## Quick installation

On a clean Debian 13, Ubuntu 24.04 LTS, or Ubuntu 26.04 LTS server (amd64 or arm64), run as `root`:

```bash
curl -fsSL https://ols.zangyubin.top/install | bash
```

The Cloudflare entry is pinned to `v1.4.1`. It verifies the signed bootstrap manifest before returning the script. The bootstrap installs missing download, CA, and OpenSSL prerequisites, downloads the fixed-version installer, verifies its Ed25519 signature and SHA-256 digest, and only then starts it.

## Verify before executing any remote script

Use this longer procedure if your policy requires downloading first and executing only after local verification:

```bash
set -euo pipefail
umask 077
workdir="$(mktemp -d /tmp/ols-wpanel-install.XXXXXXXXXX)"
trap 'rm -rf -- "$workdir"' EXIT
cd "$workdir"

version='v1.4.1'
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

The key above is the OLS WPanel release-verification key used by `v1.4.1`. Compare it with the key shown in the repository and Release notes before use.

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
