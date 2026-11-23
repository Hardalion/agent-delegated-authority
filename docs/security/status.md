# Security status

**Tree:** follow-up hardening on top of `3b41e02` (2026-11-23). This is the public reference tree after PR #36 and PR #45, plus the worker-cache, reconciliation, directory-kind, pending-nonce, redaction, and spend-pool fixes in this branch.
**This is not a certification.** No SOC 2, ISO 27001, or independent retest is claimed.

## What the tests in this repository cover

Findings ADAP-001 through ADAP-011 have regression tests named in [regression-matrix.md](regression-matrix.md). The suite to run is `pnpm test:security`. Those tests check the behavior described in this repository. The original assessment PDF is not in this repository, so the matrix is not a line-by-line check of that PDF.

Later review fixes that the suite also covers: production checks fail closed unless the dev opt-out is set; an executor throw after dispatch records `ALLOW` / `SYSTEM_ERROR` / `outcome: unknown`; authority-enforcing MCP calls require a tool-definition pin; a hydrated worker drops a revoked policy URI while keeping the content hash for a pending approval; a negative lookup does not freeze a `started` write as `reconciled`; the gateway directory keeps key `kind` and a non-human key cannot approve; a nonce waiting on `REQUIRE_HUMAN` cannot be executed as `ALLOW`; receipt arguments are redacted unless the caller opts in; cumulative amount pools are separated by ceiling and currency. The reference gateway itself fails closed: `executeAuthorized` does not default `unsafeDevAllowUnconfiguredChecks` to true, and the server requires `audience`, `approvalPolicy.isHuman`, and a revocation check. That finding was reported by Ahmed Shacker (@AS2812) and fixed in #47.

Mohammad Ali Oweidat's independent retest is **not** recorded as complete. A handoff note from an earlier revision existed at `docs/security/historical/EXTERNAL-RETEST-PACKAGE.md` and was moved out of the public tree with the other historical records. It was not a reviewer report and its removal is not a retest result.

## What a receipt proves

A signed receipt proves the issuer attested that body. `executed: true` means the reference runtime's executor callback returned. It does not prove an external system committed the action. Confirming that requires evidence from the external system, such as the reference gateway's reconcile read against its own downstream ledger.

## Local staging is not production

`node staging/scripts/run-validation.mjs` is a Docker Compose drill on one machine. The 2026-11-02 run recorded 37 checks and exit 0. That drill used Vault in dev mode and one Postgres primary. Connection exhaustion in that drill still returned `executed: true` from a gateway that already held a database connection. The readiness snapshot that recorded this was moved out of the public tree with the other historical operational records. The observation stands and is not marked resolved.

## Reporting

Report vulnerabilities as described in [SECURITY.md](../../SECURITY.md).

Earlier audit logs, including notes that still say the remediation was uncommitted, were part of the historical records moved out of the public tree. Previous versions remain in this repository's public Git history. The current security status is this file and [regression-matrix.md](regression-matrix.md).
