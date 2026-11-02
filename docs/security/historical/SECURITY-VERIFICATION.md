> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../status.md).

# SECURITY-VERIFICATION

## Release verification 2026-11-02

The original assessment PDF is not in this repository. These results match the documented attack descriptions and the named tests. They are not a line-by-line check of that PDF, and they are not Mohammad Ali Oweidat's external retest.

Commands run on this tree, all exit 0:

| Command | Result |
| --- | --- |
| `pnpm install --frozen-lockfile` | Lockfile matched. 6 workspace projects |
| `pnpm test` | adap-policy 59, adap-receipt 19, adap 83, adap-gateway 7 |
| `pnpm test:security` | fail-closed 12, adap security files 66, receipt semantics 3, gateway 7 |
| `pnpm typecheck` | exit 0 |
| `pnpm build` | exit 0 |
| `pnpm audit --audit-level high` | No known vulnerabilities found |
| `pnpm attacks` | Six attacks, each BLOCK, executor not called |
| `node scripts/reproduce-findings.mjs` | ADAP-001, 002, 003, 004, 005, 006, 011 reported FIXED. The script does not cover ADAP-007 or ADAP-008 |
| `node scripts/redteam-probe.mjs` | RT-01, RT-03, RT-04, RT-06, RT-08, RT-10 remediated or fixed. RT-02 NOT_REPRO |
| `pnpm test:integration:postgres` with `ADAP_PG_FORCE=1` | 13 passed, 1 skipped. The skip is the `NOT EXECUTED` marker, which runs only when Postgres is absent |
| `node staging/scripts/run-validation.mjs` | Exit 0. Script recorded 37 passed and 0 failed. Local Compose only. Connection exhaustion still returned `executed: true` |

ADAP-003 policy comparison, ADAP-007 `runAuthorityPath` malformed intent, and ADAP-008 caller `now` were included in `pnpm test:security`.

## Earlier log

**Branch:** `security/adap-complete-remediation`  
**Base commit (audited):** `1fa576a8ef4a889685d5623d67c9ae71366c8f2d`  
**Date:** 2026-11-01

## Commands executed

```bash
# Baseline at audited revision (before remediation)
pnpm test
# → adap-policy 46, adap-receipt 16, adap 17  (79 total) PASS

# After remediation
pnpm test
pnpm test:security
pnpm typecheck
pnpm build
pnpm attacks
pnpm demo
node scripts/reproduce-findings.mjs
```

## Test counts (post-remediation)

| Suite | Result |
| --- | --- |
| `adap-policy` | 47 passed |
| `adap-receipt` | 19 passed |
| `adap` | 30 passed |
| **Total unit/integration** | **96 passed** |
| `pnpm test:security` (adversarial) | 13 + 3 = **16 passed** |
| `pnpm typecheck` | PASS |
| `pnpm build` | PASS |
| `pnpm attacks` | 6/6 BLOCK, receipts verified |
| `pnpm demo` | PASS (REQUIRE_HUMAN → approved ALLOW) |

## Independent reproduction script

`node scripts/reproduce-findings.mjs` after rebuild:

| Finding | Status |
| --- | --- |
| ADAP-001 | FIXED |
| ADAP-002 | FIXED |
| ADAP-003 | FIXED |
| ADAP-004 | FIXED (dangerous key rejected) |
| ADAP-005 | FIXED |
| ADAP-006 | FIXED |
| ADAP-011 | FIXED |

ADAP-007/008/009/010 covered by adversarial suite and specs (not all asserted in the one-shot script).

## Independent attacker pass (manual)

Re-checked each original finding with alternate inputs:

- Policy substitution without approval on a pending nonce → BLOCK
- Substituted policy without resolver + approval → BLOCK (hash mismatch)
- Pre-registered resolver URI with substituted caller object → pinned document used
- Object/array/number nonces → rejected
- Independent JSON parse of the same string nonce after consume → rejected
- NaN / ±Infinity amounts → rejected
- `__proto__` in canonicalization → rejected
- Prototype-bearing constraints → rejected
- Empty `agentRole` → `agent_not_in_scope`
- Contradictory receipts → structureOk false
- Concurrent exclusive claim → only one executor call (existing test)

No new fail-open path identified in the remediation. Distributed atomicity remains a deployment requirement.

## Assessment PDFs

`ADAP-Security-Assessment.pdf` and `ADAP-Responsible-Disclosure.pdf` were not found in the workspace. Remediation used the mission brief’s mandatory finding list.
