#!/usr/bin/env bash
set -euo pipefail

# Run only in an ephemeral container with the source and native test binary
# mounted read-only. Package installation uses the installer's pinned keys.
[[ -f /.dockerenv && "$(id -u)" == 0 ]]
[[ $# == 1 && -x "$1" ]]
cd /src
bash /src/install.sh --check-ols-packages
export OLS_WPANEL_LOCKED_SITE_RUNTIME_TEST=1
"$1" -test.run '^TestOLSLockedSiteRuntimeLinux$' -test.count=1 -test.v -test.timeout=5m | tee /tmp/ols-locked-site-runtime.log
grep -Fq -- '--- PASS: TestOLSLockedSiteRuntimeLinux ' /tmp/ols-locked-site-runtime.log
grep -Fq OLS_LOCKED_SITE_LEGACY_REPRODUCED /tmp/ols-locked-site-runtime.log
grep -Fq OLS_LEGACY_MAINTENANCE_RUNTIME_OK /tmp/ols-locked-site-runtime.log
grep -Fq OLS_LOCKED_SITE_RUNTIME_OK /tmp/ols-locked-site-runtime.log
