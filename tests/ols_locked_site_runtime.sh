#!/usr/bin/env bash
set -euo pipefail

# Run only in an ephemeral container with the source and native test binary
# mounted read-only. Package installation uses the installer's pinned keys.
[[ -f /.dockerenv && "$(id -u)" == 0 ]]
[[ $# == 1 && -x "$1" ]]
cd /src
bash /src/install.sh --check-ols-packages
# The same authenticated repository must provide a coherent PHP 8.3 executable
# and its bundled extensions, including the real OPcache shared library.
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove --no-install-recommends \
    lsphp83 lsphp83-common lsphp83-mysql lsphp83-curl lsphp83-intl \
    lsphp83-opcache lsphp83-igbinary lsphp83-redis lsphp83-imagick
export OLS_WPANEL_PACKAGE_COHESION_TEST=1
"$1" -test.run '^TestLSPHPPackageCohesionRuntimeLinux$' -test.count=1 -test.v -test.timeout=1m | tee /tmp/lsphp-package-cohesion.log
grep -Fq -- '--- PASS: TestLSPHPPackageCohesionRuntimeLinux ' /tmp/lsphp-package-cohesion.log
grep -Fq LSPHP83_PACKAGE_COHESION_RUNTIME_OK /tmp/lsphp-package-cohesion.log
export OLS_WPANEL_LOCKED_SITE_RUNTIME_TEST=1
"$1" -test.run '^TestOLSLockedSiteRuntimeLinux$' -test.count=1 -test.v -test.timeout=5m | tee /tmp/ols-locked-site-runtime.log
grep -Fq -- '--- PASS: TestOLSLockedSiteRuntimeLinux ' /tmp/ols-locked-site-runtime.log
grep -Fq OLS_LOCKED_SITE_LEGACY_REPRODUCED /tmp/ols-locked-site-runtime.log
grep -Fq OLS_LEGACY_MAINTENANCE_RUNTIME_OK /tmp/ols-locked-site-runtime.log
grep -Fq OLS_MAINTENANCE_HEADERS_RUNTIME_OK /tmp/ols-locked-site-runtime.log
grep -Fq OLS_LOCKED_SITE_RUNTIME_OK /tmp/ols-locked-site-runtime.log
