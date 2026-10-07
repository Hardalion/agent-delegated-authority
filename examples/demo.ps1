# Smoke test for the reference implementation (run from the repository after pnpm install && pnpm build)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "==> 1/3 Policy eval: apply over the cap should BLOCK"
node packages/policy-engine/dist/cli.js --tool apply --args '{"amount":800}' --json
if ($LASTEXITCODE -ne 1) { throw "Expected exit code 1 for BLOCK" }

Write-Host ""
Write-Host "==> 2/3 Policy eval: read should ALLOW"
node packages/policy-engine/dist/cli.js --tool read --json
if ($LASTEXITCODE -ne 0) { throw "Expected exit code 0 for ALLOW" }

Write-Host ""
Write-Host "==> 3/3 Authorization Receipt verify (offline)"
node packages/audit-verify/dist/cli.js examples/receipt.json --public-key examples/issuer-public-key.txt --verbose
if ($LASTEXITCODE -ne 0) { throw "Receipt verify failed" }

Write-Host ""
Write-Host "OK - reference implementation smoke test passed."
