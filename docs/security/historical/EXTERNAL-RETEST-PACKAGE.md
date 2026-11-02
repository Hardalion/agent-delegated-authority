> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../status.md).

# EXTERNAL-RETEST-PACKAGE

Prepared for Mohammad Ali Oweidat or another independent reviewer. This file does not record a completed retest.

## Snapshot

| Item | Value |
| --- | --- |
| Repository | `npl-spec` (Hardalion ADAP) |
| HEAD | `1fa576a8ef4a889685d5623d67c9ae71366c8f2d` |
| Branches pointing at that commit | `security/adap-complete-remediation`, `main`, `hackathon/genai-summit` |
| Working tree | Uncommitted remediation, production adapters, and this staging pass. Not committed, not pushed |
| Staging evidence | `npl-spec/staging/.evidence/summary.json` at `2026-11-01T21:23:50.752Z` |
| Earlier working-tree backup | `C:\Users\User\Desktop\adap-staging-validation-backup-20261101-2245` (taken before the staging code). It is not the final tree |

Reproduce the diff with:

```bash
git rev-parse HEAD
git status --short
git diff --stat
```

Untracked packages include `packages/adap-gateway`, `packages/adap-store-postgres`, and `staging/`. Do not copy `staging/.env` or `staging/.secrets`. Those are generated credentials for the local drill.

## What to re-run

```bash
node staging/scripts/run-validation.mjs
pnpm test
pnpm test:security
pnpm --filter adap-store-postgres test
```

Postgres integration tests need `ADAP_PG_URL` or `ADAP_PG_FORCE=1`. The staging script starts its own Postgres and does not use customer data.

## Documents

- `THREAT_MODEL.md`
- `SECURITY-FINAL-VERIFICATION.md`, `SECURITY-REMEDIATION.md`, `SECURITY-REMEDIATION-RT01-RT04.md`
- `PRODUCTION-ARCHITECTURE.md`, `PRODUCTION-READINESS-MATRIX.md`, `PRODUCTION-RESIDUAL-RISKS.md`
- `STAGING-ARCHITECTURE.md`, `STAGING-VALIDATION-REPORT.md`, `STAGING-SECURITY-TESTS.md`

## Not done

No independent reviewer has signed a retest report. Gate 10 stays open.
