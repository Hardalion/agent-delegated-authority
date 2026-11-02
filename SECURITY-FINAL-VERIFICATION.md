# SECURITY-FINAL-VERIFICATION

Independent verification after the final hardening pass. Previous pass counts are not copied as evidence.

## Environment

- OS: Windows
- Node: v22.19.0
- pnpm: 10.15.1
- Directory: `npl-spec`
- Branch: `security/adap-complete-remediation`
- `git rev-parse HEAD`: `1fa576a8ef4a889685d5623d67c9ae71366c8f2d`
- All remediation remains uncommitted.

## Diff check

`git diff --check`: exit 0 after the threat-model rewrite (no trailing whitespace).

## Commands and results

### `pnpm test`

Exit 0 (final run after order fix).

| Package | Files | Tests |
| --- | --- | --- |
| adap-policy | 8 passed | 58 passed |
| adap-receipt | 3 passed | 19 passed |
| adap | 12 passed | 75 passed |
| **Total** | **23** | **152 passed, 0 failed** |

### `pnpm test:security`

Exit 0.

| Suite | Tests |
| --- | --- |
| `adap-policy` `fail-closed.test.ts` | 11 passed |
| `adap` security-adversarial + rt-remediation + final-hardening + adversarial-final | 58 passed |
| `adap-receipt` security-semantics | 3 passed |
| **Total** | **72 passed** (subset of the 152, plus policy fail-closed which is also in the 58 policy tests) |

### `pnpm typecheck`

Exit 0.

### `pnpm build`

Exit 0. Policy bundle OK.

### `pnpm attacks`

Exit 0. Six `BLOCK`, executor not called (except attack 04's prior execution). Attack 06 reason: `approval is not bound to this intent`.

### `pnpm demo`

Exit 0. `REQUIRE_HUMAN` then `ALLOW`, receipt verified.

### `node scripts/reproduce-findings.mjs`

Exit 0. ADAP-001, 002, 003, 004, 005, 006, 011 → `FIXED`.

### `node scripts/redteam-probe.mjs`

Exit 0.

| ID | Status |
| --- | --- |
| RT-01 | REMEDIATED |
| RT-02 | NOT_REPRO |
| RT-03 | REMEDIATED |
| RT-04 | REMEDIATED (NaN, ±Infinity, cycle) |
| RT-05 | FIXED |
| RT-06 | REMEDIATED |
| RT-07 | FIXED |
| RT-08 | REMEDIATED |
| RT-09 | FIXED |
| RT-10 | FIXED |
| RT-11 | FIXED |
| RT-12 | FIXED (`approval is not bound to this intent`) |

### `pnpm audit --audit-level high`

Exit 0. `No known vulnerabilities found`. No exception register exists.

## Intermediate failures recorded

1. Approval receipt verification in `final-hardening` used a string key → fixed.
2. Attack 06 golden / reason mismatch against stale dist and late binding check → fixed; early binding check added.
3. Missing-`defaultAction` authority registration threw ZodError → test reshaped.
4. `authorizePresented` before `assertUsable` broke authenticated-amount consume/replay → order restored.
5. An earlier full-suite run in this session failed those cases; the final run above is after the fixes.

## Not run

- Multi-region database-backed nonce store. Only the async adapter double was tested.
- Network or credential-isolation tests outside this repository.
- External third-party retest.

## Independence note

Assertions were inspected in `rt-remediation.test.ts`, `final-hardening.test.ts`, `adversarial-final.test.ts`, `fail-closed.test.ts`, and the red-team probe. Passing labels alone were not treated as proof.
