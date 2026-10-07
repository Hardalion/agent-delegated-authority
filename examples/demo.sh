#!/usr/bin/env bash
# Smoke test for the reference implementation (run from the repository after pnpm install && pnpm build)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> 1/3 Policy eval: apply over the cap should BLOCK"
node packages/policy-engine/dist/cli.js --tool apply --args '{"amount":800}' --json || test $? -eq 1

echo ""
echo "==> 2/3 Policy eval: read should ALLOW"
node packages/policy-engine/dist/cli.js --tool read --json

echo ""
echo "==> 3/3 Authorization Receipt verify (offline)"
node packages/audit-verify/dist/cli.js examples/receipt.json --public-key examples/issuer-public-key.txt --verbose

echo ""
echo "OK - reference implementation smoke test passed."
