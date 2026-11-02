# SECURITY-VERIFICATION-LOG

Independent run. Previous remediation counts were not copied into this log.

## Environment

- OS: Windows
- Node: v22.19.0
- pnpm: 10.15.1
- Directory: `npl-spec`
- Branch: `security/adap-complete-remediation`
- `git rev-parse HEAD`: `1fa576a8ef4a889685d5623d67c9ae71366c8f2d`
- Remediation and this audit are uncommitted. HEAD does not contain them.

## Diff check

`git diff --stat 1fa576a8ef4a889685d5623d67c9ae71366c8f2d` at the start of the audit: 27 tracked files, 866 insertions, 197 deletions. Untracked remediation files were also present (validation modules, adversarial tests, security reports).

`git diff --check`: trailing whitespace in `THREAT_MODEL.md` line 3. No other whitespace errors reported.

## Commands and results

### `pnpm test`

Exit 0. Vitest 4.1.12.

| Package | Files | Tests |
| --- | --- | --- |
| adap-policy | 7 passed | 47 passed |
| adap-receipt | 3 passed | 19 passed |
| adap | 9 passed | 30 passed |
| Total | 19 | 96 passed, 0 failed |

### `pnpm test:security`

Exit 0.

- `packages/aap/src/security-adversarial.test.ts`: 1 file, 13 passed
- `packages/audit-verify/src/security-semantics.test.ts`: 1 file, 3 passed

These 16 tests are included in the 96 above. The command re-ran them. It did not add coverage for RT-01, RT-03, or RT-04.

### `pnpm typecheck`

Exit 0. `adap-policy`, `adap-receipt`, and `adap` completed `tsc --noEmit`.

### `pnpm build`

Exit 0. Policy bundle check printed `Built policy bundle OK (read → ALLOW)`. `adap` `tsc` completed.

### `pnpm attacks`

Exit 0. Six cases printed `BLOCK` and `NOT CALLED` except attack 04, which is the replay case and reports one prior execution. Attack 06 reason printed as `nonce already used`.

### `pnpm demo`

Exit 0. Pending decision `REQUIRE_HUMAN`, executed no. After approval, decision `ALLOW`, executed yes, receipt verified.

### `node scripts/reproduce-findings.mjs`

Exit 0.

| ID | Status |
| --- | --- |
| ADAP-001 | FIXED |
| ADAP-002 | FIXED |
| ADAP-003 | FIXED (comparison bypass) |
| ADAP-004 | FIXED |
| ADAP-005 | FIXED |
| ADAP-006 | FIXED |
| ADAP-011 | FIXED |

### `node scripts/redteam-probe.mjs`

Exit 0. This script is not part of CI.

| ID | Status | Detail |
| --- | --- | --- |
| RT-01 | CONFIRMED | Executor observed `dest=evil` after authorization of `legit`. Decision `ALLOW`. |
| RT-02 | NOT_REPRO | Getter flip blocked. |
| RT-03 | CONFIRMED | Forged amount `-1` then legitimate intent: second result `nonce already used`. |
| RT-04 | CONFIRMED | `NaN` threw out of `runAuthorityPath`. |
| RT-05 | FIXED | Policy substitution without approval did not execute. |
| RT-06 | CONDITIONAL | Expired `now` blocks. Caller `now` inside the window executes. |
| RT-07 | FIXED | Object nonce rejected. |
| RT-08 | CONDITIONAL | Omitted `agentRole` → `ALLOW`. |
| RT-09 | FIXED | Contradictory receipt `structureOk=false`. |
| RT-10 | Not a bypass | `resource/./vault` → `capability not granted`. |
| RT-11 | FIXED | One executor call. Retry blocked. |
| RT-12 | FIXED | Approval for another intent did not execute. |

## Not executed

- A second OS process sharing a nonce store. No such store is in the tree.
- Network calls, credential use, or any system outside this repository.
- `pnpm audit` as a gating check. The workflow allows it to fail.

## Failures hidden

None. The vitest suites passed. The red-team script reported the confirmed defects above. Those defects are not vitest failures because no test asserts them.

## Post-patch run appended 2026-11-01

Same branch, same HEAD (`1fa576a8ef4a889685d5623d67c9ae71366c8f2d`), same machine. The RT-01 / RT-03 / RT-04 patch was in the working tree. An intermediate `pnpm typecheck` failed on `packages/aap/src/snapshot.ts` (`seen.has` did not narrow `unknown`). That type error was fixed before the commands below. Those commands are the final run.

### `pnpm test`

Exit 0. Vitest 4.1.12.

| Package | Files | Tests |
| --- | --- | --- |
| adap-policy | 7 passed | 47 passed |
| adap-receipt | 3 passed | 19 passed |
| adap | 10 passed | 44 passed |
| Total | 20 | 110 passed, 0 failed |

The adap count includes `src/rt-remediation.test.ts`: 14 passed. The previous log's 30 adap tests are the pre-patch count.

### `pnpm test:security`

Exit 0.

- `packages/aap/src/security-adversarial.test.ts`: 1 file, 13 passed
- `packages/audit-verify/src/security-semantics.test.ts`: 1 file, 3 passed

These 16 tests remain a subset of the 110. RT-01, RT-03, and RT-04 are covered by `rt-remediation.test.ts`, which this command does not run.

### `pnpm typecheck`

Exit 0 after the `snapshot.ts` narrowing fix.

### `pnpm build`

Exit 0. Policy bundle check printed `Built policy bundle OK (read → ALLOW)`. `adap` `tsc` completed.

### `pnpm attacks`

Exit 0. Six cases printed `BLOCK` and `NOT CALLED`, except attack 04, which reports the prior execution and then `nonce already used`. Attack 06 reason printed as `nonce already used`.

### `pnpm demo`

Exit 0. `purchase €420` printed `REQUIRE_HUMAN`, executed no, then `ALLOW`, executed yes, receipt verified.

### `node scripts/reproduce-findings.mjs`

Exit 0.

| ID | Status |
| --- | --- |
| ADAP-001 | FIXED |
| ADAP-002 | FIXED |
| ADAP-003 | FIXED (`NaN bypass=false`, `-Infinity bypass=false`) |
| ADAP-004 | FIXED |
| ADAP-005 | FIXED |
| ADAP-006 | FIXED |
| ADAP-011 | FIXED |

### `node scripts/redteam-probe.mjs`

Exit 0. Built `dist` after the patch.

| ID | Status | Detail |
| --- | --- | --- |
| RT-01 | REMEDIATED | `observed=legit receiptDest=legit decision=ALLOW executed=true authenticated=true` |
| RT-02 | NOT_REPRO | `reads=2 observed=10 decision=ALLOW executed=true` |
| RT-03 | REMEDIATED | Forged `authenticated=false` receipt absent, `BLOCK` / `signature_invalid`. Follow-up `REQUIRE_HUMAN` / `apply_needs_human`. |
| RT-04 NaN | REMEDIATED | `threw=false decision=BLOCK authenticated=false receipt=absent executed=false calls=0 reason=intent could not be canonicalized` |
| RT-04 +Infinity | REMEDIATED | Same shape as NaN. |
| RT-04 -Infinity | REMEDIATED | Same shape as NaN. |
| RT-04 cycle | REMEDIATED | `reason=intent.parameters.self contains a cycle`. No throw, no receipt, 0 calls. |
| RT-05 | FIXED | `pending=REQUIRE_HUMAN` substitution `BLOCK`, exec 0 |
| RT-06 | CONDITIONAL | Caller `now` inside the window still executes. |
| RT-07 | FIXED | Object nonce rejected. |
| RT-08 | CONDITIONAL | Omitted `agentRole` → `ALLOW`. |
| RT-09 | FIXED | Contradictory receipt `structureOk=false`. |
| RT-10 | FIXED | `resource/./vault` → `capability not granted`. |
| RT-11 | FIXED | One executor call. Retry `nonce already used`. |
| RT-12 | FIXED | Approval on another nonce did not execute. |

## Failures in the final run

None. The intermediate typecheck failure is recorded above and was fixed before this run.
