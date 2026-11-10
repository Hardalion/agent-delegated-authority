# Security status

**Tree:** `main` at `2ce1e2f35cbc5d4d472e992de545c8bef2857ab3` (2026-11-02).
**This is not a certification.** No SOC 2, ISO 27001, or independent retest is claimed.

## What the tests in this repository cover

Findings ADAP-001 through ADAP-011 have regression tests named in [regression-matrix.md](regression-matrix.md). The suite to run is `pnpm test:security`. Those tests check the behavior described in this repository. The original assessment PDF is not in this repository, so the matrix is not a line-by-line check of that PDF.

Mohammad Ali Oweidat's independent retest is **not** recorded as complete. A handoff note from an earlier revision existed at `docs/security/historical/EXTERNAL-RETEST-PACKAGE.md` and was moved out of the public tree with the other historical records. It was not a reviewer report and its removal is not a retest result.

## What a receipt proves

A signed receipt proves the issuer attested that body. `executed: true` means the reference runtime's executor callback returned. It does not prove an external system committed the action. Confirming that requires evidence from the external system, such as the reference gateway's reconcile read against its own downstream ledger.

## Local staging is not production

`node staging/scripts/run-validation.mjs` is a Docker Compose drill on one machine. The 2026-11-02 run recorded 37 checks and exit 0. That drill used Vault in dev mode and one Postgres primary. Connection exhaustion in that drill still returned `executed: true` from a gateway that already held a database connection. The readiness snapshot that recorded this was moved out of the public tree with the other historical operational records. The observation stands and is not marked resolved.

## Reporting

Report vulnerabilities as described in [SECURITY.md](../../SECURITY.md).

Earlier audit logs, including notes that still say the remediation was uncommitted, were part of the historical records moved out of the public tree. Previous versions remain in this repository's public Git history. The current security status is this file and [regression-matrix.md](regression-matrix.md).
