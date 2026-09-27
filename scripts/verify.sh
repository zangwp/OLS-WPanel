#!/usr/bin/env bash
set -euo pipefail

export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/ols-wpanel-go-build-cache}"
mkdir -p "$GOCACHE"

go test ./...
go vet ./...
go build -o "${TMPDIR:-/tmp}/ols-wpanel-verify" .
git diff --check

if command -v php >/dev/null 2>&1; then
  php -l ols-wpanel-optimizer/ols-wpanel-optimizer.php
else
  echo "php not found; skipped php -l ols-wpanel-optimizer/ols-wpanel-optimizer.php"
fi
