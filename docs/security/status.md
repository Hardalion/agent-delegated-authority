# Security status

**Tree:** `security/execution-semantics`, including the documentation layout from `main` at `bc5ae766e509aa32ff7b9c29ed4198e651b88177`.
**This is not a certification.** No SOC 2, ISO 27001, or independent retest is claimed.

## What the tests in this repository cover

Findings ADAP-001 through ADAP-011 have regression tests named in [regression-matrix.md](regression-matrix.md). The suite to run is `pnpm test:security`. Those tests check the behavior described in this repository. The original assessment PDF is not in this repository, so the matrix is not a line-by-line check of that PDF.

Mohammad Ali Oweidat's independent retest is **not** recorded as complete. [historical/EXTERNAL-RETEST-PACKAGE.md](historical/EXTERNAL-RETEST-PACKAGE.md) is a handoff note from an earlier revision. It is not a reviewer report.

## What a receipt proves

A signed receipt proves the issuer attested that body. `executed: true` means the reference runtime's executor callback returned. It does not prove an external system committed the action. Confirming that requires evidence from the external system, such as the reference gateway's reconcile read against its own downstream ledger.

## Local staging is not production

`node staging/scripts/run-validation.mjs` is a Docker Compose drill on one machine. The 2026-11-02 run on `main` at `2ce1e2f` recorded 37 checks and exit 0. That drill used Vault in dev mode and one Postgres primary. Connection exhaustion in that drill still returned `executed: true` from a gateway that already held a database connection. The record is [the 2026-11-02 readiness snapshot](../operations/historical/PRODUCTION-READINESS-MATRIX.md). On this branch the gateway checks capacity first and, when no ordinary connection slot remains, returns HTTP 503 with `executed: false` and `executionState: not_dispatched` without calling the executor. A downstream `unknown` is `executed: false` and `outcome: unknown`.

## Reporting

Report vulnerabilities as described in [SECURITY.md](../../SECURITY.md).

Earlier audit logs, including notes that still say the remediation was uncommitted, are in [historical/](historical/).
