#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_DIR"

export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/ols-wpanel-go-build-cache}"
mkdir -p "$GOCACHE"

go test ./...
go vet ./...
go build -o "${TMPDIR:-/tmp}/ols-wpanel-verify" ./cmd/ols-wpanel
git diff --check

if command -v php >/dev/null 2>&1; then
  php -l web/plugins/ols-wpanel-optimizer/ols-wpanel-optimizer.php
else
  echo "php not found; skipped php -l web/plugins/ols-wpanel-optimizer/ols-wpanel-optimizer.php"
fi
