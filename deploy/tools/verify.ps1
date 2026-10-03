$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
Set-Location -LiteralPath $projectRoot
$env:GOCACHE = Join-Path $projectRoot '.gocache'
$packages = go list ./... | Where-Object { $_ -notlike '*/scratch' }
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (-not $packages) { throw 'No Go packages found.' }

go test $packages
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

go vet $packages
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

go build -o (Join-Path $env:GOCACHE 'ols-wpanel-verify.exe') ./cmd/ols-wpanel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

git diff --check
exit $LASTEXITCODE
